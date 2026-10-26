const crypto = require("crypto");
const nodemailer = require("nodemailer");

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const fmtDate = (d) => new Date(d + "T00:00:00Z").toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });

function validToken(token) {
  const [exp, sig] = String(token || "").split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const good = crypto.createHmac("sha256", process.env.SESSION_SECRET).update(exp).digest("hex");
  return sig.length === good.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good));
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 405, body: "Method not allowed" };
  let b;
  try { b = JSON.parse(event.body); } catch { return res(400, "Invalid request."); }
  if (!validToken(b.token)) return res(401, "Session expired. Log in again.");

  const { to, amount, reason, dueDate, nextDate } = b;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to || "")) return res(400, "Enter a valid recipient email.");
  if (!(Number(amount) > 0) || !reason || !/^\d{4}-\d{2}-\d{2}$/.test(dueDate || "") || !/^\d{4}-\d{2}-\d{2}$/.test(nextDate || ""))
    return res(400, "Fill in every field.");

  const amt = "AED " + Number(amount).toFixed(2);
  const due = fmtDate(dueDate), next = fmtDate(nextDate);
  const subject = `Payment Reminder: ${amt} Due on ${due}`;
  const text = `Dear Customer,\n\nThis is a formal reminder regarding your payment.\n\nAmount due: ${amt}\nReason: ${reason}\nDue date: ${due}\nNext payment date: ${next}\n\nPlease ensure that payment is made on or before the due date. The following payment will be due on ${next}.\n\nKind regards,\nRenewAlert`;
  const html = `<p>Dear Customer,</p><p>This is a formal reminder regarding your payment.</p><p><b>Amount due:</b> ${esc(amt)}<br><b>Reason:</b> ${esc(reason)}<br><b>Due date:</b> ${esc(due)}<br><b>Next payment date:</b> ${esc(next)}</p><p>Please ensure that payment is made on or before the due date. The following payment will be due on ${esc(next)}.</p><p>Kind regards,<br>RenewAlert</p>`;

  try {
    const t = nodemailer.createTransport({
      host: "smtp.gmail.com", port: 465, secure: true,
      auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD },
    });
    await t.sendMail({ from: `"RenewAlert" <${process.env.GMAIL_USER}>`, to, subject, text, html });
    return res(200, "Sent.");
  } catch (e) {
    return res(500, "Could not send the email. Check the Gmail settings.");
  }
};

const res = (statusCode, message) => ({ statusCode, headers: { "Content-Type": "application/json" }, body: JSON.stringify({ message }) });
