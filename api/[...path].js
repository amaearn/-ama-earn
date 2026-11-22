
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

function verifyTelegram(initData) {
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  const authDate = Number(params.get("auth_date"));

  if (!hash || !authDate) return null;

  if (Math.abs(Date.now() / 1000 - authDate) > 86400) {
    return null;
  }

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

  if (
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) {
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

// Telegram membership verification
async function checkTelegramMembership(chatUsername, userId) {
  const token = process.env.TELEGRAM_BOT_TOKEN;

  const response = await fetch(
    `https://api.telegram.org/bot${token}/getChatMember`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
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
        auth: {
          persistSession: false
        }
      }
    );

    const authorization = req.headers.authorization || "";

    if (!authorization.startsWith("tma ")) {
      return res.status(401).json({
        error: "Telegram authentication required"
      });
    }

    const verified = verifyTelegram(
      authorization.slice(4)
    );

    if (!verified || !verified.user?.id) {
      return res.status(401).json({
        error: "Invalid Telegram session"
      });
    }

    const user = verified.user;

    // Register or update user profile
    const { error: profileError } = await supabase
      .from("profiles")
      .upsert(
        {
          telegram_id: user.id,
          username: user.username || null,
          first_name: user.first_name || null
        },
        {
          onConflict: "telegram_id"
        }
      );

    if (profileError) throw profileError;

    // Referral registration
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

    const path = new URL(
      req.url,
      "https://example.com"
    ).pathname;

    // Get user profile and referral link
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

    // Tap to earn
    if (path === "/api/tap" && req.method === "POST") {
      const { data, error } = await supabase.rpc(
        "ama_tap",
        {
          p_telegram_id: user.id
        }
      );

      if (error) throw error;

      return res.status(200).json({
        points: data
      });
    }

    // Daily reward
    if (path === "/api/daily" && req.method === "POST") {
      const { data, error } = await supabase.rpc(
        "ama_daily_claim",
        {
          p_telegram_id: user.id
        }
      );

      if (error) {
        if (error.code === "23505") {
          return res.status(409).json({
            error: "Daily reward already claimed"
          });
        }

        throw error;
      }

      return res.status(200).json({
        points: data
      });
    }

    // Load active social media tasks
    if (path === "/api/tasks" && req.method === "GET") {
      const { data, error } = await supabase
        .from("tasks")
        .select("id, title, description, reward, task_url")
        .eq("is_active", true)
        .order("created_at", {
          ascending: true
        });

      if (error) throw error;

      return res.status(200).json({
        tasks: data
      });
    }

    // Verify Telegram channel or group task
    if (path === "/api/verify-task" && req.method === "POST") {
      const body = typeof req.body === "string"
        ? JSON.parse(req.body)
        : req.body || {};

      const taskId = body.task_id;

      if (
        typeof taskId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(taskId)
      ) {
        return res.status(400).json({
          error: "Invalid task ID"
        });
      }

      const { data: task, error: taskError } = await supabase
        .from("tasks")
        .select("id, title, reward, task_url")
        .eq("id", taskId)
        .eq("is_active", true)
        .single();

      if (taskError || !task) {
        return res.status(404).json({
          error: "Task not found"
        });
      }

      let chatUsername = null;

      try {
        const taskUrl = new URL(task.task_url);
        const taskPath = taskUrl.pathname
          .replace(/^\/+|\/+$/g, "")
          .toLowerCase();

        if (
          taskUrl.hostname === "t.me" &&
          taskPath === "amaearnofficial"
        ) {
          chatUsername = "@AMAEarnOfficial";
        } else if (
          taskUrl.hostname === "t.me" &&
          taskPath === "amaearncommunity"
        ) {
          chatUsername = "@AMAEarnCommunity";
        }
      } catch {
        chatUsername = null;
      }

      if (!chatUsername) {
        return res.status(400).json({
          error: "Automatic verification is not available for this task yet"
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
        already_completed: Number(reward) === 0,
        message: Number(reward) === 0
          ? "Task already completed"
          : "Task verified. Points added!"
      });
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
