const crypto = require("crypto");
const nodemailer = require("nodemailer");

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const today = () => new Date().toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "Asia/Dubai" });
const clean = (v) => String(v || "").trim();
const tooLong = (...vals) => vals.some((v) => v.length > 200);

function money(v) {
  const s = clean(v);
  const n = s.replace(/^AED\s*/i, "").replace(/,/g, "");
  if (/^\d+(\.\d{1,2})?$/.test(n)) return { label: "AED " + Number(n).toFixed(2), value: Number(n) };
  return { label: s, value: 0 };
}

function validToken(token) {
  const [exp, sig] = String(token || "").split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const good = crypto.createHmac("sha256", process.env.SESSION_SECRET).update(exp).digest("hex");
  return sig.length === good.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good));
}

function buildReminder(b) {
  const amt = money(b.amount).label;
  const reason = clean(b.reason), due = clean(b.dueDate), next = clean(b.nextDate);
  if (!amt || !reason || !due || !next || tooLong(amt, reason, due, next)) return null;
  return {
    fromName: "RenewAlert",
    subject: `Payment Reminder: ${amt} Due on ${due}`,
    text: `Dear Customer,\n\nThis is a formal reminder regarding your payment.\n\nAmount due: ${amt}\nReason: ${reason}\nDue date: ${due}\nNext payment date: ${next}\n\nPlease ensure that payment is made on or before the due date. The following payment will be due on ${next}.\n\nKind regards,\nRenewAlert`,
    html: `<p>Dear Customer,</p><p>This is a formal reminder regarding your payment.</p><p><b>Amount due:</b> ${esc(amt)}<br><b>Reason:</b> ${esc(reason)}<br><b>Due date:</b> ${esc(due)}<br><b>Next payment date:</b> ${esc(next)}</p><p>Please ensure that payment is made on or before the due date. The following payment will be due on ${esc(next)}.</p><p>Kind regards,<br>RenewAlert</p>`,
  };
}

function buildOrder(b) {
  const name = clean(b.name), item = clean(b.item), qty = clean(b.qty), rawNo = clean(b.orderNo);
  const p = money(b.price), d = money(b.priority), r = money(b.prep);
  if (!item || !qty || !rawNo || !p.label) return null;
  if (tooLong(name, item, qty, rawNo, p.label, d.label, r.label)) return null;

  const orderNo = /^\d+$/.test(rawNo) ? "#" + parseInt(rawNo, 10) : rawNo;
  const total = "AED " + (p.value + d.value + r.value).toFixed(2);
  const date = today();
  const hello = name ? `Hi ${name},` : "Hello,";

  const rows = [
    ["Order number", orderNo],
    ["Date", date],
    ["Item", item],
    ["Quantity", qty],
    ["Price", p.label],
  ];
  if (d.label) rows.push(["Priority delivery", d.label]);
  if (r.label) rows.push(["Preparation", r.label]);

  const lines = rows.map(([k, v]) => `${k}: ${v}`).join("\n");
  const tableRows = rows.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("");

  return {
    fromName: "3D Hub",
    subject: "Order Confirmation",
    text: `${hello}\n\nThank you for your purchase at 3D Hub. We will ship your order as soon as possible.\n\nReceipt\n${lines}\nTotal: ${total}\n\nKind regards,\n3D Hub`,
    html: `<p>${esc(hello)}</p><p>Thank you for your purchase at 3D Hub. We will ship your order as soon as possible.</p><p><b>Receipt</b></p><table cellpadding="6" style="border-collapse:collapse;border:1px solid #000">${tableRows}<tr><td><b>Total</b></td><td><b>${esc(total)}</b></td></tr></table><p>Kind regards,<br>3D Hub</p>`,
  };
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 405, body: "Method not allowed" };
  let b;
  try { b = JSON.parse(event.body); } catch { return res(400, "Invalid request."); }
  if (!validToken(b.token)) return res(401, "Session expired. Log in again.");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(b.to || "")) return res(400, "Enter a valid recipient email.");

  const mail = b.type === "order" ? buildOrder(b) : buildReminder(b);
  if (!mail) return res(400, "Fill in every required field.");

  try {
    const t = nodemailer.createTransport({
      host: "smtp.gmail.com", port: 465, secure: true,
      auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD },
    });
    await t.sendMail({
      from: `"${mail.fromName}" <${process.env.GMAIL_USER}>`,
      to: b.to, subject: mail.subject, text: mail.text, html: mail.html,
    });
    return res(200, "Sent.");
  } catch (e) {
    return res(500, "Could not send the email. Check the Gmail settings.");
  }
};

const res = (statusCode, message) => ({ statusCode, headers: { "Content-Type": "application/json" }, body: JSON.stringify({ message }) });
