
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY,
  { auth: { persistSession: false } }
);

function verifyTelegram(initData) {
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  const authDate = Number(params.get("auth_date"));

  if (!hash || !authDate) return null;
  if (Math.abs(Date.now() / 1000 - authDate) > 86400) return null;

  const entries = [...params.entries()]
    .filter(([key]) => key !== "hash")
    .sort(([a], [b]) => a.localeCompare(b));

  const checkString = entries.map(([k, v]) => `${k}=${v}`).join("\n");

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

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  try {
    return {
      user: JSON.parse(params.get("user")),
      startParam: params.get("start_param")
    };
  } catch {
    return null;
  }
}

module.exports = async (req, res) => {
  try {
    if (
      !process.env.SUPABASE_URL ||
      !process.env.SUPABASE_SECRET_KEY ||
      !process.env.TELEGRAM_BOT_TOKEN
    ) {
      return res.status(500).json({ error: "Server environment variables missing" });
    }

    const authorization = req.headers.authorization || "";

    if (!authorization.startsWith("tma ")) {
      return res.status(401).json({ error: "Telegram authentication required" });
    }

    const verified = verifyTelegram(authorization.slice(4));
    if (!verified || !verified.user?.id) {
      return res.status(401).json({ error: "Invalid Telegram session" });
    }

    const user = verified.user;

    const { error: profileError } = await supabase
      .from("profiles")
      .upsert({
        telegram_id: user.id,
        username: user.username || null,
        first_name: user.first_name || null
      }, { onConflict: "telegram_id" });

    if (profileError) throw profileError;

    // Register referral from Telegram's signed start parameter.
    const startParam = verified.startParam || "";

    if (startParam.startsWith("ref_")) {
      const referrerId = startParam.slice(4);

      if (/^\d+$/.test(referrerId)) {
        const { error } = await supabase.rpc("ama_register_referral", {
          p_user_id: user.id,
          p_referrer_id: referrerId
        });

        if (error) throw error;
      }
    }

    const path = new URL(req.url, "https://example.com").pathname;

    if (path === "/api/me" && req.method === "GET") {
      const { data, error } = await supabase
        .from("profiles")
        .select("points")
        .eq("telegram_id", user.id)
        .single();

      if (error) throw error;

      return res.status(200).json({
        points: data.points,
        referral_link: `https://t.me/AMA_Earn_Bot?startapp=ref_${user.id}`
      });
    }

    if (path === "/api/tap" && req.method === "POST") {
      const { data, error } = await supabase.rpc("ama_tap", {
        p_telegram_id: user.id
      });

      if (error) throw error;
      return res.status(200).json({ points: data });
    }

    if (path === "/api/daily" && req.method === "POST") {
      const { data, error } = await supabase.rpc("ama_daily_claim", {
        p_telegram_id: user.id
      });

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

    return res.status(404).json({ error: "API route not found" });

  } catch (error) {
    console.error("AMA Earn API error:", error);
    return res.status(500).json({ error: "Server error. Please try again." });
  }
};
