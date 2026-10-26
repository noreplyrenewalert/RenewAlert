const crypto = require("crypto");
const attempts = new Map(); // best-effort limiter (resets when the function restarts)

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 405, body: "Method not allowed" };
  const ip = event.headers["x-nf-client-connection-ip"] || "unknown";
  const now = Date.now();
  const rec = (attempts.get(ip) || []).filter((t) => now - t < 15 * 60 * 1000);
  if (rec.length >= 5) return json(429, { error: "Too many attempts. Try again in 15 minutes." });

  let password = "";
  try { password = String(JSON.parse(event.body).password || ""); } catch {}
  const [salt, hash] = (process.env.PASSWORD_HASH || ":").split(":");
  const given = crypto.scryptSync(password, salt, 64);
  const stored = Buffer.from(hash, "hex");
  const ok = stored.length === given.length && crypto.timingSafeEqual(given, stored);

  if (!ok) {
    rec.push(now); attempts.set(ip, rec);
    return json(401, { error: "Wrong password." });
  }
  const exp = now + 12 * 60 * 60 * 1000;
  const sig = crypto.createHmac("sha256", process.env.SESSION_SECRET).update(String(exp)).digest("hex");
  return json(200, { token: exp + "." + sig });
};

function json(statusCode, body) {
  return { statusCode, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}
