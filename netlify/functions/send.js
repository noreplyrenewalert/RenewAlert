const crypto = require("crypto");
const nodemailer = require("nodemailer");

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const fmtDate = (d) => new Date(d + "T00:00:00Z").toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
const today = () => new Date().toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "Asia/Dubai" });
const isDate = (d) => /^\d{4}-\d{2}-\d{2}$/.test(d || "");

function validToken(token) {
  const [exp, sig] = String(token || "").split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const good = crypto.createHmac("sha256", process.env.SESSION_SECRET).update(exp).digest("hex");
  return sig.length === good.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good));
}

function buildReminder(b) {
  const { amount, reason, dueDate, nextDate } = b;
  if (!(Number(amount) > 0) || !reason || String(reason).length > 200 || !isDate(dueDate) || !isDate(nextDate)) return null;
  const amt = "AED " + Number(amount).toFixed(2);
  const due = fmtDate(dueDate), next = fmtDate(nextDate);
  return {
    fromName: "RenewAlert",
    subject: `Payment Reminder: ${amt} Due on ${due}`,
    text: `Dear Customer,\n\nThis is a formal reminder regarding your payment.\n\nAmount due: ${amt}\nReason: ${reason}\nDue date: ${due}\nNext payment date: ${next}\n\nPlease ensure that payment is made on or before the due date. The following payment will be due on ${next}.\n\nKind regards,\nRenewAlert`,
    html: `<p>Dear Customer,</p><p>This is a formal reminder regarding your payment.</p><p><b>Amount due:</b> ${esc(amt)}<br><b>Reason:</b> ${esc(reason)}<br><b>Due date:</b> ${esc(due)}<br><b>Next payment date:</b> ${esc(next)}</p><p>Please ensure that payment is made on or before the due date. The following payment will be due on ${esc(next)}.</p><p>Kind regards,<br>RenewAlert</p>`,
  };
}

function buildOrder(b) {
  const name = String(b.name || "").trim();
  const item = String(b.item || "").trim();
  const qty = parseInt(b.qty, 10);
  const price = Number(b.price);
  const num = parseInt(b.orderNo, 10);
  if (!item || item.length > 200 || name.length > 100) return null;
  if (!(qty >= 1 && qty <= 1000) || !(price > 0) || !(num >= 1 && num <= 6000)) return null;
  const orderNo = "#" + num;
  const each = "AED " + price.toFixed(2);
  const total = "AED " + (qty * price).toFixed(2);
  const date = today();
  const hello = name ? `Hi ${name},` : "Hello,";
  return {
    fromName: "3D Hub",
    subject: "Order Confirmation",
    text: `${hello}\n\nThank you for your purchase at 3D Hub. We will ship your order as soon as possible.\n\nReceipt\nOrder number: ${orderNo}\nDate: ${date}\nItem: ${item}\nQuantity: ${qty}\nPrice each: ${each}\nTotal: ${total}\n\nKind regards,\n3D Hub`,
    html: `<p>${esc(hello)}</p><p>Thank you for your purchase at 3D Hub. We will ship your order as soon as possible.</p><p><b>Receipt</b></p><table cellpadding="6" style="border-collapse:collapse;border:1px solid #000"><tr><td>Order number</td><td>${esc(orderNo)}</td></tr><tr><td>Date</td><td>${esc(date)}</td></tr><tr><td>Item</td><td>${esc(item)}</td></tr><tr><td>Quantity</td><td>${qty}</td></tr><tr><td>Price each</td><td>${esc(each)}</td></tr><tr><td><b>Total</b></td><td><b>${esc(total)}</b></td></tr></table><p>Kind regards,<br>3D Hub</p>`,
  };
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 405, body: "Method not allowed" };
  let b;
  try { b = JSON.parse(event.body); } catch { return res(400, "Invalid request."); }
  if (!validToken(b.token)) return res(401, "Session expired. Log in again.");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(b.to || "")) return res(400, "Enter a valid recipient email.");

  const mail = b.type === "order" ? buildOrder(b) : buildReminder(b);
  if (!mail) return res(400, "Fill in every field correctly.");

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
