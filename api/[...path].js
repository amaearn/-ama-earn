
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

function verifyTelegram(initData) {
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  const authDate = Number(params.get("auth_date"));

  if (!hash || !authDate) return null;
  if (Math.abs(Date.now() / 1000 - authDate) > 86400) return null;

  const entries = [...params.entries()]
    .filter(([key]) => key !== "hash")
    .sort(([a], [b]) => a.localeCompare(b));

  const checkString = entries
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secret = crypto
    .createHmac("sha256", "WebAppData")
    .update(process.env.TELEGRAM_BOT_TOKEN)
    .digest();

  const calculated = crypto
    .createHmac("sha256", secret)
    .update(checkString)
    .digest("hex");

  const a = Buffer.from(hash, "hex");
  const b = Buffer.from(calculated, "hex");

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return null;
  }

  try {
    return {
      user: JSON.parse(params.get("user")),
      startParam: params.get("start_param")
    };
  } catch {
    return null;
  }
}

async function checkTelegramMembership(chatUsername, userId) {
  const response = await fetch(
    `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/getChatMember`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatUsername,
        user_id: userId
      })
    }
  );

  const result = await response.json();

  if (!result.ok) {
    console.error("Telegram verification error:", result);
    throw new Error("Telegram membership check failed");
  }

  const member = result.result;

  return (
    ["creator", "administrator", "member"].includes(member.status) ||
    (member.status === "restricted" && member.is_member === true)
  );
}

function isAdmin(userId) {
  return (
    process.env.ADMIN_TELEGRAM_ID &&
    String(userId) === String(process.env.ADMIN_TELEGRAM_ID)
  );
}

module.exports = async (req, res) => {
  try {
    if (
      !process.env.SUPABASE_URL ||
      !process.env.SUPABASE_SECRET_KEY ||
      !process.env.TELEGRAM_BOT_TOKEN
    ) {
      return res.status(500).json({
        error: "Server environment variables missing"
      });
    }

    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SECRET_KEY,
      {
        auth: { persistSession: false }
      }
    );

    const authorization = req.headers.authorization || "";

    if (!authorization.startsWith("tma ")) {
      return res.status(401).json({
        error: "Telegram authentication required"
      });
    }

    const verified = verifyTelegram(authorization.slice(4));

    if (!verified || !verified.user?.id) {
      return res.status(401).json({
        error: "Invalid Telegram session"
      });
    }

    const user = verified.user;

    const { error: profileError } = await supabase
      .from("profiles")
      .upsert(
        {
          telegram_id: user.id,
          username: user.username || null,
          first_name: user.first_name || null
        },
        { onConflict: "telegram_id" }
      );

    if (profileError) throw profileError;

    const startParam = verified.startParam || "";

    if (startParam.startsWith("ref_")) {
      const referrerId = startParam.slice(4);

      if (/^\d+$/.test(referrerId)) {
        const { error } = await supabase.rpc(
          "ama_register_referral",
          {
            p_user_id: user.id,
            p_referrer_id: referrerId
          }
        );

        if (error) throw error;
      }
    }

    const path = new URL(req.url, "https://example.com").pathname;

    // PROFILE
    if (path === "/api/me" && req.method === "GET") {
      const { data, error } = await supabase
        .from("profiles")
        .select("points")
        .eq("telegram_id", user.id)
        .single();

      if (error) throw error;

      return res.status(200).json({
        points: data.points,
        referral_link:
          `https://t.me/AMA_Earn_Bot?startapp=ref_${user.id}`
      });
    }

    // TAP TO EARN
    if (path === "/api/tap" && req.method === "POST") {
      const { data, error } = await supabase.rpc(
        "ama_tap",
        { p_telegram_id: user.id }
      );

      if (error) throw error;

      return res.status(200).json({ points: data });
    }

    // DAILY REWARD
    if (path === "/api/daily" && req.method === "POST") {
      const { data, error } = await supabase.rpc(
        "ama_daily_claim",
        { p_telegram_id: user.id }
      );

      if (error) {
        if (error.code === "23505") {
          return res.status(409).json({
            error: "Daily reward already claimed"
          });
        }
        throw error;
      }

      return res.status(200).json({ points: data });
    }

    // LOAD TASKS
    if (path === "/api/tasks" && req.method === "GET") {
      const { data, error } = await supabase
        .from("tasks")
        .select("id, title, description, reward, task_url")
        .eq("is_active", true)
        .order("created_at", { ascending: true });

      if (error) throw error;

      return res.status(200).json({ tasks: data });
    }

    // VERIFY TELEGRAM TASK
    if (path === "/api/verify-task" && req.method === "POST") {
      const body = typeof req.body === "string"
        ? JSON.parse(req.body)
        : req.body || {};

      const taskId = body.task_id;

      if (
        typeof taskId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(taskId)
      ) {
        return res.status(400).json({ error: "Invalid task ID" });
      }

      const { data: task, error: taskError } = await supabase
        .from("tasks")
        .select("id, title, reward, task_url")
        .eq("id", taskId)
        .eq("is_active", true)
        .single();

      if (taskError || !task) {
        return res.status(404).json({ error: "Task not found" });
      }

      let chatUsername = null;

      try {
        const taskUrl = new URL(task.task_url);
        const taskPath = taskUrl.pathname.replace(/^\/+|\/+$/g, "").toLowerCase();

        if (taskUrl.hostname === "t.me" && taskPath === "amaearnofficial") {
          chatUsername = "@AMAEarnOfficial";
        } else if (taskUrl.hostname === "t.me" && taskPath === "amaearncommunity") {
          chatUsername = "@AMAEarnCommunity";
        }
      } catch {
        chatUsername = null;
      }

      if (!chatUsername) {
        return res.status(400).json({
          error: "This task is not a Telegram task"
        });
      }

      const isMember = await checkTelegramMembership(
        chatUsername,
        user.id
      );

      if (!isMember) {
        return res.status(403).json({
          error: "Please join the Telegram channel or group first"
        });
      }

      const { data: reward, error: rewardError } = await supabase.rpc(
        "ama_complete_task",
        {
          p_telegram_id: user.id,
          p_task_id: task.id
        }
      );

      if (rewardError) throw rewardError;

      return res.status(200).json({
        success: true,
        points_awarded: reward,
        already_completed: Number(reward) === 0
      });
    }

    // SUBMIT INSTAGRAM / YOUTUBE SCREENSHOT
    if (path === "/api/submit-proof" && req.method === "POST") {
      const body = typeof req.body === "string"
        ? JSON.parse(req.body)
        : req.body || {};

      const taskId = body.task_id;
      const imageData = body.image;

      if (
        typeof taskId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(taskId)
      ) {
        return res.status(400).json({ error: "Invalid task ID" });
      }

      if (typeof imageData !== "string") {
        return res.status(400).json({ error: "Please select a screenshot" });
      }

      const match = imageData.match(
        /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/
      );

      if (!match) {
        return res.status(400).json({
          error: "Only JPG, PNG and WEBP screenshots are allowed"
        });
      }

      const mimeType = match[1];
      const buffer = Buffer.from(match[2], "base64");

      if (buffer.length > 3 * 1024 * 1024) {
        return res.status(413).json({
          error: "Screenshot must be smaller than 3 MB"
        });
      }

      if (!buffer.length) {
        return res.status(400).json({ error: "Empty screenshot" });
      }

      const { data: task, error: taskError } = await supabase
        .from("tasks")
        .select("id, title, task_url")
        .eq("id", taskId)
        .eq("is_active", true)
        .single();

      if (taskError || !task) {
        return res.status(404).json({ error: "Task not found" });
      }

      let host = "";

      try {
        host = new URL(task.task_url).hostname.toLowerCase();
      } catch {
        host = "";
      }

      const isInstagram = host === "instagram.com" || host === "www.instagram.com";
      const isYouTube = host === "youtube.com" || host === "www.youtube.com";

      if (!isInstagram && !isYouTube) {
        return res.status(400).json({
          error: "Proof upload is only for Instagram and YouTube tasks"
        });
      }

      const { data: existing, error: existingError } = await supabase
        .from("task_submissions")
        .select("id, status")
        .eq("telegram_id", user.id)
        .eq("task_id", taskId)
        .in("status", ["pending", "approved"]);

      if (existingError) throw existingError;

      if (existing && existing.length > 0) {
        return res.status(409).json({
          error: existing[0].status === "approved"
            ? "This task has already been approved"
            : "Your proof is already waiting for review"
        });
      }

      const extension = mimeType === "image/png"
        ? "png"
        : mimeType === "image/webp"
          ? "webp"
          : "jpg";

      const proofPath =
        `${user.id}/${taskId}-${crypto.randomUUID()}.${extension}`;

      const { error: uploadError } = await supabase.storage
        .from("task-proofs")
        .upload(proofPath, buffer, {
          contentType: mimeType,
          upsert: false
        });

      if (uploadError) throw uploadError;

      const { data: submission, error: insertError } = await supabase
        .from("task_submissions")
        .insert({
          telegram_id: user.id,
          task_id: taskId,
          proof_path: proofPath,
          status: "pending"
        })
        .select("id")
        .single();

      if (insertError) {
        await supabase.storage.from("task-proofs").remove([proofPath]);
        throw insertError;
      }

      return res.status(201).json({
        success: true,
        submission_id: submission.id,
        message: "Screenshot submitted for admin review"
      });
    }

    // ADMIN: LIST PENDING SUBMISSIONS
    if (path === "/api/admin/submissions" && req.method === "GET") {
      if (!isAdmin(user.id)) {
        return res.status(403).json({ error: "Admin access denied" });
      }

      const { data: submissions, error } = await supabase
        .from("task_submissions")
        .select("id, telegram_id, task_id, proof_path, status, created_at")
        .eq("status", "pending")
        .order("created_at", { ascending: true });

      if (error) throw error;

      const ids = [...new Set(submissions.map(item => item.telegram_id))];

      let profiles = [];

      if (ids.length) {
        const { data, error: profileError } = await supabase
          .from("profiles")
          .select("telegram_id, username, first_name")
          .in("telegram_id", ids);

        if (profileError) throw profileError;
        profiles = data || [];
      }

      const results = await Promise.all(
        submissions.map(async item => {
          const { data: signed, error: signedError } = await supabase.storage
            .from("task-proofs")
            .createSignedUrl(item.proof_path, 300);

          if (signedError) throw signedError;

          const { data: task } = await supabase
            .from("tasks")
            .select("title, reward")
            .eq("id", item.task_id)
            .single();

          const profile = profiles.find(
            p => String(p.telegram_id) === String(item.telegram_id)
          );

          return {
            id: item.id,
            telegram_id: item.telegram_id,
            username: profile?.username || null,
            first_name: profile?.first_name || null,
            task_title: task?.title || "Social task",
            reward: task?.reward || 0,
            proof_url: signed.signedUrl,
            created_at: item.created_at
          };
        })
      );

      return res.status(200).json({ submissions: results });
    }

    // ADMIN: APPROVE OR REJECT SUBMISSION
    if (path === "/api/admin/review" && req.method === "POST") {
      if (!isAdmin(user.id)) {
        return res.status(403).json({ error: "Admin access denied" });
      }

      const body = typeof req.body === "string"
        ? JSON.parse(req.body)
        : req.body || {};

      if (
        typeof body.submission_id !== "string" ||
        typeof body.approved !== "boolean"
      ) {
        return res.status(400).json({
          error: "Submission ID and approval decision are required"
        });
      }

      const { data, error } = await supabase.rpc(
        "ama_review_task_submission",
        {
          p_submission_id: body.submission_id,
          p_approved: body.approved,
          p_admin_note: String(body.note || "").slice(0, 500),
          p_admin_id: user.id
        }
      );

      if (error) throw error;

      return res.status(200).json(data);
    }

    return res.status(404).json({
      error: "API route not found"
    });

  } catch (error) {
    console.error("AMA Earn API error:", error);

    return res.status(500).json({
      error: "Server error. Please try again."
    });
  }
};
