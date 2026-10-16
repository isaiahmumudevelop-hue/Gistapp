require('dotenv').config();
const express    = require('express');
/* ---------- web-push ---------- GISTAPP_WEBPUSH_V1 */
const webpush = require('web-push');
const VAPID_PUBLIC  = process.env.VAPID_PUBLIC_KEY || '';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:isaiahmumudevelop@gmail.com';
const WEBPUSH_OK = !!(VAPID_PUBLIC && VAPID_PRIVATE);
if (WEBPUSH_OK){
  try {
    webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC, VAPID_PRIVATE);
    console.log('✅ Web push ready');
  } catch(e){ console.error('❌ web-push init failed:', e.message); }
} else {
  console.log('ℹ️  Web push disabled (missing VAPID keys)');
}

const rateLimit  = require('express-rate-limit');  // GISTAPP_RATE_LIMIT_V1
const { ipKeyGenerator } = require('express-rate-limit');  // GISTAPP_IPV6_FIX — normalize IPv6 to /56 subnet
const http       = require('http');
const { Server } = require('socket.io');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const path       = require('path');
const fs         = require('fs');
const multer     = require('multer');
const Filestack = require('@upstash/blob'); // GISTAPP_FILESTACK_RENAME
const pool       = require('./db');

// Crash-proofing: log errors instead of dying
process.on('uncaughtException', (err) => {
  console.error('💥 UNCAUGHT:', err.message);
  if (err.stack) console.error(err.stack.split('\n')[1]);
});
process.on('unhandledRejection', (reason) => {
  console.error('💥 UNHANDLED:', reason && reason.message || reason);
});

const speakeasy    = require('speakeasy');
const { OAuth2Client } = require('google-auth-library');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const qrcode       = require('qrcode');

/* ---------- mailer via Gmail HTTP API (works on Render) ---------- GISTAPP_GMAIL_API_V1 */
const USE_GMAIL_API = !!(process.env.GMAIL_CLIENT_ID && process.env.GMAIL_CLIENT_SECRET && process.env.GMAIL_REFRESH_TOKEN);
const GMAIL_SENDER = process.env.GMAIL_SENDER || process.env.SMTP_USER || 'onboarding@gistapp.app';

let _gmailTokenCache = { token: null, exp: 0 };
async function getGmailAccessToken(){
  if (_gmailTokenCache.token && Date.now() < _gmailTokenCache.exp - 30000){
    return _gmailTokenCache.token;
  }
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.GMAIL_CLIENT_ID,
      client_secret: process.env.GMAIL_CLIENT_SECRET,
      refresh_token: process.env.GMAIL_REFRESH_TOKEN,
      grant_type: 'refresh_token'
    }).toString()
  });
  const data = await r.json();
  if (!data.access_token){
    throw new Error('Gmail token refresh failed: ' + JSON.stringify(data));
  }
  _gmailTokenCache.token = data.access_token;
  _gmailTokenCache.exp = Date.now() + (data.expires_in || 3600) * 1000;
  return data.access_token;
}

async function sendViaGmailAPI({ to, subject, html, text, from, headers, replyTo, attachments}){
  const accessToken = await getGmailAccessToken();
  const senderName = 'GistApp';
  const fromHeader = '"' + senderName + '" <' + (from || GMAIL_SENDER) + '>';
  const boundary = 'gist_' + Date.now() + '_' + Math.random().toString(36).slice(2,8);
  const altBoundary = 'gistalt_' + Date.now() + '_' + Math.random().toString(36).slice(2,8);
  // GISTAPP_MIME_SUBJECT_FIX — RFC 2047 encode non-ASCII subjects (emoji, accents)
  const _encSubject = (function(s){
    s = String(s == null ? '' : s);
    // eslint-disable-next-line no-control-regex
    if (/^[\x00-\x7F]*$/.test(s)) return s;
    return '=?UTF-8?B?' + Buffer.from(s, 'utf-8').toString('base64') + '?=';
  })(subject);
  const _msgId = '<' + Date.now() + '.' + Math.random().toString(36).slice(2,10) + '@gistapp.local>';
  const _date = new Date().toUTCString();
  const _hasAttach = Array.isArray(attachments) && attachments.length > 0;

  const headerLines = [
    'From: ' + fromHeader,
    'To: ' + to,
    'Subject: ' + _encSubject,
    'Date: ' + _date,
    'Message-ID: ' + _msgId,
    ...(replyTo ? ['Reply-To: ' + replyTo] : []),
    ...(headers ? Object.keys(headers).map(function(k){ return k + ': ' + headers[k]; }) : []),
    'MIME-Version: 1.0'
  ];

  let mime;
  if (_hasAttach){
    // multipart/mixed wrapper
    const parts = [];
    parts.push(...headerLines);
    parts.push('Content-Type: multipart/mixed; boundary="' + boundary + '"');
    parts.push('');
    parts.push('--' + boundary);
    parts.push('Content-Type: multipart/alternative; boundary="' + altBoundary + '"');
    parts.push('');
    parts.push('--' + altBoundary);
    parts.push('Content-Type: text/plain; charset="UTF-8"');
    parts.push('');
    parts.push(text || 'Please view this email in an HTML-compatible viewer.');
    parts.push('');
    parts.push('--' + altBoundary);
    parts.push('Content-Type: text/html; charset="UTF-8"');
    parts.push('');
    parts.push(html || text || '');
    parts.push('');
    parts.push('--' + altBoundary + '--');
    parts.push('');
    // Attachment parts
    attachments.forEach(function(a){
      parts.push('--' + boundary);
      parts.push('Content-Type: ' + (a.contentType || 'application/octet-stream') + '; name="' + (a.filename || 'attachment') + '"');
      parts.push('Content-Disposition: attachment; filename="' + (a.filename || 'attachment') + '"');
      parts.push('Content-Transfer-Encoding: base64');
      parts.push('');
      var b64 = Buffer.isBuffer(a.content) ? a.content.toString('base64') : Buffer.from(String(a.content)).toString('base64');
      // Wrap at 76 chars per RFC 2045
      parts.push(b64.replace(/(.{76})/g, '$1\r\n'));
      parts.push('');
    });
    parts.push('--' + boundary + '--');
    parts.push('');
    mime = parts.join('\r\n');
  } else {
    mime = [
      ...headerLines,
      'Content-Type: multipart/alternative; boundary="' + boundary + '"',
      '',
      '--' + boundary,
      'Content-Type: text/plain; charset="UTF-8"',
      '',
      text || 'Please view this email in an HTML-compatible viewer.',
      '',
      '--' + boundary,
      'Content-Type: text/html; charset="UTF-8"',
      '',
      html || text || '',
      '',
      '--' + boundary + '--',
      ''
    ].join('\r\n');
  }

  const raw = Buffer.from(mime).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const r = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + accessToken,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ raw })
  });
  if (!r.ok){
    const err = await r.text();
    throw new Error('Gmail API ' + r.status + ': ' + err.slice(0, 200));
  }
  return r.json();
}

// Shim so existing mailer.sendMail({...}) calls keep working
const mailer = {
  sendMail: async function(opts){
    // GISTAPP_MIME_SUBJECT_FIX — pass extra headers through
    // GISTAPP_INVOICE_PDF — pass attachments through
    return sendViaGmailAPI({
      to: opts.to,
      subject: opts.subject,
      html: opts.html,
      text: opts.text,
      from: GMAIL_SENDER,
      headers: opts.headers || null,
      replyTo: opts.replyTo || null,
      attachments: opts.attachments || null
    });
  },
  verify: async function(cb){
    try {
      if (!USE_GMAIL_API){
        console.warn('⚠️  Gmail env vars missing — emails will fail');
        return cb && cb(new Error('Gmail not configured'));
      }
      await getGmailAccessToken();
      console.log('✅ Mail ready via Gmail HTTP API');
      cb && cb(null);
    } catch(e){
      console.error('❌ Mail verify failed:', e.message);
      cb && cb(e);
    }
  }
};

// verify at boot
mailer.verify((err) => {
  if (err) console.error('❌ Mail not ready:', err.message);
});

/* ---------- reCAPTCHA verify (GISTAPP_RECAPTCHA_V1) ---------- */
const RECAPTCHA_SECRET = process.env.TURNSTILE_SECRET || process.env.RECAPTCHA_SECRET || '0x4AAAAAAAFU67j6KgW8q0TuJwb7RwZLHdoE';
const RECAPTCHA_ENABLED = !!RECAPTCHA_SECRET;
async function verifyRecaptcha(token, remoteIp){
  // GISTAPP_NO_CAPTCHA — captcha disabled; other defenses are active:
  // rate limiting, honeypot, disposable email block, email verification.
  return { ok: true, skipped: true, reason: 'disabled' };
}


function makeToken(){
  return require('crypto').randomBytes(24).toString('hex');
}

async function sendVerificationEmail(toEmail, token, displayName){
  const baseUrl = process.env.APP_URL || 'http://localhost:3000';
  const link = baseUrl + '/verify?token=' + token;
  const info = await mailer.sendMail({
    from: '"GistApp" <' + GMAIL_SENDER + '>',
    to: toEmail,
    replyTo: process.env.SMTP_USER,
    subject: 'Verify your GistApp account',
    headers: {
      'X-Priority': '3',
      'Importance': 'normal',
      'List-Unsubscribe': '<mailto:' + process.env.SMTP_USER + '>'
    },
    html: `
      <div style="font-family:Inter,sans-serif;max-width:520px;margin:0 auto;padding:32px;background:#f7f5ff;border-radius:20px">
        <h2 style="color:#33344c;margin:0 0 16px">Hi ${displayName || 'there'} 👋</h2>
        <p style="color:#4a4568;font-size:15px;line-height:1.6">
          Welcome to GistApp! Tap the button below to verify your email address and activate your account.
        </p>
        <div style="text-align:center;margin:28px 0">
          <a href="${link}" style="background:#33344c;color:#fff;text-decoration:none;padding:14px 32px;border-radius:14px;font-weight:700;display:inline-block">
            Verify my email
          </a>
        </div>
        <p style="color:#8e8e93;font-size:13px;line-height:1.6">
          Or copy this link into your browser:<br>
          <span style="color:#6a62b8;word-break:break-all">${link}</span>
        </p>
        <p style="color:#8e8e93;font-size:12px;margin-top:24px">
          If you didn't sign up for GistApp, just ignore this email.
        </p>
      </div>
    `
  });
  return info;
}


/* GISTAPP_WELCOME_PRO — professional welcome email with community guidelines */
async function sendWelcomeEmail(toEmail, displayName){
  const baseUrl = process.env.APP_URL || 'http://localhost:3000';
  const iconUrl = baseUrl + '/icon-192.png';
  const name = displayName || 'there';
  const year = new Date().getFullYear();
  const termsUrl = baseUrl + '/?legal=terms';
  const privacyUrl = baseUrl + '/?legal=privacy';

  const featureRow = (emoji, title, desc) =>
    '<tr><td style="padding:13px 0;vertical-align:top;width:44px;font-size:22px;line-height:1">' + emoji + '</td>' +
    '<td style="padding:13px 0;color:#1c1c22;font-size:14px;line-height:1.55"><b style="color:#2b2c44">' + title + '</b><br>' +
    '<span style="color:#6a6a73">' + desc + '</span></td></tr>';

  const canItem = (text) =>
    '<tr><td style="padding:5px 0;color:#1f7a3d;font-size:15px;width:24px;vertical-align:top;font-weight:800">&#10003;</td>' +
    '<td style="padding:5px 0;color:#2b2c44;font-size:13.5px;line-height:1.55">' + text + '</td></tr>';

  const cannotItem = (text) =>
    '<tr><td style="padding:5px 0;color:#c03434;font-size:15px;width:24px;vertical-align:top;font-weight:800">&#10007;</td>' +
    '<td style="padding:5px 0;color:#2b2c44;font-size:13.5px;line-height:1.55">' + text + '</td></tr>';

  const html = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Welcome to GistApp</title></head>
<body style="margin:0;padding:0;background:#f2f0fa;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f2f0fa;padding:24px 12px">
<tr><td align="center">
<table role="presentation" width="560" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:24px;overflow:hidden;box-shadow:0 12px 40px rgba(51,52,76,.10)">

<tr><td style="background:linear-gradient(135deg,#2b2c44 0%,#5a6cd6 55%,#7b8cff 100%);padding:38px 32px 30px;text-align:center">
<img src="${iconUrl}" alt="GistApp" width="72" height="72" style="border-radius:20px;display:block;margin:0 auto 16px;box-shadow:0 10px 30px rgba(0,0,0,.35);border:3px solid rgba(255,255,255,.14)">
<div style="color:#ffffff;font-size:25px;font-weight:800;letter-spacing:-.5px;line-height:1.2">Welcome to GistApp</div>
<div style="color:rgba(255,255,255,.85);font-size:13px;font-weight:500;margin-top:6px;letter-spacing:.2px">Chat &middot; Stream &middot; Earn</div>
</td></tr>

<tr><td style="padding:32px 32px 4px">
<p style="margin:0 0 14px;color:#1c1c22;font-size:19px;font-weight:700;letter-spacing:-.3px">Hey ${name} &#128075;</p>
<p style="margin:0;color:#4a4a55;font-size:14.5px;line-height:1.65">Your account is verified and your email is confirmed. You are officially part of the GistApp community &mdash; a place to chat, go live, and earn from what you create. Here is everything you need to get started.</p>
</td></tr>

<tr><td style="padding:24px 32px 0">
<div style="color:#8e8e93;font-size:11px;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;margin-bottom:6px">What you can do</div>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse">
${featureRow('&#128172;','Start a chat','Message anyone by email &mdash; no phone number needed.')}
${featureRow('&#128308;','Go live','Stream to your followers in real time and earn coins from gifts.')}
${featureRow('&#127912;','Make it yours','Pick a wallpaper, accent color, and profile style that fits you.')}
${featureRow('&#128274;','Stay secure','Enable 2FA and biometric lock to protect your account.')}
</table>
</td></tr>

<tr><td style="padding:26px 32px 0">
<div style="color:#8e8e93;font-size:11px;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;margin-bottom:6px">Community guidelines</div>
<p style="margin:0 0 14px;color:#4a4a55;font-size:13.5px;line-height:1.65">GistApp works because our members treat each other with respect. By joining, you agree to these ground rules.</p>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f0fbf4;border:1px solid #c9efd6;border-radius:14px;border-collapse:separate">
<tr><td colspan="2" style="padding:12px 18px 4px;color:#1f7a3d;font-size:13px;font-weight:800;letter-spacing:.2px">You are free to</td></tr>
${canItem('Chat, post, and go live with anyone on the platform.')}
${canItem('Share content you own or have the right to share.')}
${canItem('Earn coins from gifts and withdraw your balance.')}
${canItem('Block, mute, or report anyone who crosses a line.')}
${canItem('Delete your account and data at any time.')}
<tr><td colspan="2" style="padding:0 18px 14px"></td></tr>
</table>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#fdf1f1;border:1px solid #f4c9c9;border-radius:14px;margin-top:12px;border-collapse:separate">
<tr><td colspan="2" style="padding:12px 18px 4px;color:#c03434;font-size:13px;font-weight:800;letter-spacing:.2px">You are not allowed to</td></tr>
${cannotItem('Harass, threaten, or abuse other members.')}
${cannotItem('Post illegal, adult, or sexually explicit content.')}
${cannotItem('Impersonate anyone or misrepresent who you are.')}
${cannotItem('Spam, scam, or run unauthorised promotions.')}
${cannotItem('Share someone else\'s private information without consent.')}
${cannotItem('Use the app if you are under 18 years old.')}
<tr><td colspan="2" style="padding:0 18px 14px"></td></tr>
</table>
</td></tr>

<tr><td style="padding:24px 32px 0">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f7f5ff;border-left:3px solid #7b8cff;border-radius:8px;border-collapse:separate">
<tr><td style="padding:14px 18px;color:#4a4568;font-size:13px;line-height:1.65">
<b style="color:#2b2c44">By using GistApp</b>, you agree to our <a href="${termsUrl}" style="color:#5a6cd6;text-decoration:none;font-weight:700">Terms of Service</a> and <a href="${privacyUrl}" style="color:#5a6cd6;text-decoration:none;font-weight:700">Privacy Policy</a>. You can also read the full versions any time inside the app under <b>Settings &rarr; Legal</b>.
</td></tr>
</table>
</td></tr>

<tr><td style="padding:28px 32px 6px;text-align:center">
<a href="${baseUrl}" style="background:#2b2c44;color:#ffffff;text-decoration:none;padding:15px 44px;border-radius:14px;font-weight:800;display:inline-block;font-size:15px;letter-spacing:.2px;box-shadow:0 8px 24px rgba(43,44,68,.28)">Open GistApp</a>
</td></tr>

<tr><td style="padding:12px 32px 30px">
<p style="margin:0;color:#8e8e93;font-size:13px;line-height:1.65;text-align:center">Questions, feedback, or concerns? Just reply to this email &mdash; a real person reads every one.<br>We are glad to have you in the community.</p>
</td></tr>

<tr><td style="background:#f7f6fc;padding:22px 32px;text-align:center;border-top:1px solid #eae7f5">
<p style="margin:0 0 6px;color:#8e8e93;font-size:11.5px;line-height:1.6">You are receiving this because you created a GistApp account.</p>
<p style="margin:0;color:#a8a5b3;font-size:11px;line-height:1.6">&copy; ${year} GistApp Community &middot; All rights reserved.</p>
</td></tr>

</table>
<table role="presentation" width="560" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;width:100%;margin-top:12px">
<tr><td style="text-align:center;color:#a8a5b3;font-size:11px;line-height:1.6;padding:0 12px">This email was sent to ${toEmail}.</td></tr>
</table>
</td></tr>
</table>
</body></html>`;

  const info = await mailer.sendMail({
    from: '"GistApp Community" <' + GMAIL_SENDER + '>',
    to: toEmail,
    replyTo: process.env.SMTP_USER,
    subject: 'Welcome to the GistApp community, ' + name + ' \uD83C\uDF89',
    headers: {
      'X-Priority': '3',
      'Importance': 'normal',
      'List-Unsubscribe': '<mailto:' + process.env.SMTP_USER + '>',
      'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click'
    },
    html: html
  });
  return info;
}

/* GISTAPP_RENEWAL_REMINDER — emails Pro/Biz users before subscription expires */
async function sendRenewalReminderEmail(toEmail, displayName, info){
  if (!toEmail) return false;
  info = info || {};
  const baseUrl = process.env.APP_URL || 'https://gistapp.onrender.com';
  const iconUrl = baseUrl + '/icon-192.png';
  const name = displayName || 'there';
  const planKey = info.plan || 'pro';
  const planName = planKey === 'business' ? 'Business' : 'Pro';
  const daysLeft = Number(info.days_left || 0);
  const autoRenew = !!info.auto_renew;
  const endsAt = info.ends_at ? new Date(info.ends_at) : null;
  const endsStr = endsAt ? endsAt.toLocaleDateString('en-GB', { timeZone: 'Africa/Lagos', weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' }) : 'soon';
  const subject = daysLeft <= 1
    ? 'Your ' + planName + ' subscription ends tomorrow ⏳'
    : 'Your ' + planName + ' subscription ends in ' + daysLeft + ' days';

  const emoji = planKey === 'business' ? '💎' : '👑';

  const featureRow = (f) =>
    '<tr><td style="padding:6px 0;color:#c03434;font-size:14px;width:22px;vertical-align:top">&#10007;</td>' +
    '<td style="padding:6px 0;color:#2b2c44;font-size:13.5px;line-height:1.5">' + f + '</td></tr>';

  const features = [
    'Verified ' + emoji + ' badge on your profile',
    planKey === 'business' ? 'All Business features (unlimited uploads, priority support)' : 'All Pro features',
    'Ability to earn from gifts and withdraw earnings',
    'Priority in search and discover'
  ];

  const statusBlock = autoRenew
    ? '<div style="background:#f0fbf4;border:1px solid #c9efd6;border-radius:12px;padding:14px 16px;margin-bottom:18px">' +
      '<div style="color:#1f7a3d;font-size:13px;font-weight:800;letter-spacing:.2px;margin-bottom:4px">✅ Auto-renew is ON</div>' +
      '<div style="color:#2b2c44;font-size:13px;line-height:1.55">We will charge your saved payment method automatically on <b>' + endsStr + '</b>. No action needed.</div>' +
      '</div>'
    : '<div style="background:#fff3cd;border:1px solid #ffe58f;border-radius:12px;padding:14px 16px;margin-bottom:18px">' +
      '<div style="color:#7a5a00;font-size:13px;font-weight:800;letter-spacing:.2px;margin-bottom:4px">⚠️ Auto-renew is OFF</div>' +
      '<div style="color:#2b2c44;font-size:13px;line-height:1.55">Your subscription will end on <b>' + endsStr + '</b>. Tap below to renew and keep your benefits.</div>' +
      '</div>';

  const html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + subject + '</title></head>' +
  '<body style="margin:0;padding:0;background:#f2f0fa;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Inter,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased">' +
  '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f2f0fa;padding:24px 12px">' +
  '<tr><td align="center">' +
  '<table role="presentation" width="560" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:24px;overflow:hidden;box-shadow:0 12px 40px rgba(51,52,76,.10)">' +

  '<tr><td style="background:linear-gradient(135deg,#d97706 0%,#f59e0b 55%,#fbbf24 100%);padding:30px 32px 26px;text-align:center">' +
  '<img src="' + iconUrl + '" alt="GistApp" width="56" height="56" style="border-radius:14px;display:block;margin:0 auto 12px;box-shadow:0 8px 22px rgba(0,0,0,.3)">' +
  '<div style="font-size:44px;line-height:1;margin:0 0 6px">' + emoji + '</div>' +
  '<div style="color:#ffffff;font-size:20px;font-weight:800;letter-spacing:-.3px">' + planName + ' subscription ' + (daysLeft <= 1 ? 'ends tomorrow' : 'ends in ' + daysLeft + ' days') + '</div>' +
  '</td></tr>' +

  '<tr><td style="padding:28px 32px 4px">' +
  '<p style="margin:0 0 12px;color:#1c1c22;font-size:17px;font-weight:700;letter-spacing:-.2px">Hi ' + name + ',</p>' +
  '<p style="margin:0 0 20px;color:#4a4a55;font-size:14.5px;line-height:1.65">Your <b>' + planName + '</b> subscription on GistApp ends on <b>' + endsStr + '</b>. Here is what you will lose if it lapses:</p>' +
  '</td></tr>' +

  '<tr><td style="padding:0 32px">' +
  '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse">' +
  features.map(featureRow).join('') +
  '</table>' +
  '</td></tr>' +

  '<tr><td style="padding:24px 32px 0">' + statusBlock + '</td></tr>' +

  '<tr><td style="padding:0 32px 6px;text-align:center">' +
  '<a href="' + baseUrl + '" style="background:' + (autoRenew ? '#2b2c44' : '#d97706') + ';color:#ffffff;text-decoration:none;padding:15px 42px;border-radius:14px;font-weight:800;display:inline-block;font-size:15px;letter-spacing:.2px">' + (autoRenew ? 'Open GistApp' : 'Renew ' + planName) + '</a>' +
  '</td></tr>' +

  '<tr><td style="padding:12px 32px 30px;text-align:center">' +
  '<p style="margin:0;color:#8e8e93;font-size:12.5px;line-height:1.65">Manage your subscription anytime in <b>Settings &rarr; Subscription</b>.<br>Questions? Just reply to this email.</p>' +
  '</td></tr>' +

  '<tr><td style="background:#f7f6fc;padding:18px 32px;text-align:center;border-top:1px solid #eae7f5">' +
  '<p style="margin:0;color:#a8a5b3;font-size:11px;line-height:1.6">&copy; ' + new Date().getFullYear() + ' GistApp Community &middot; All rights reserved.</p>' +
  '</td></tr>' +

  '</table></td></tr></table></body></html>';

  try {
    await mailer.sendMail({
      from: '"GistApp" <' + GMAIL_SENDER + '>',
      to: toEmail,
      replyTo: process.env.SMTP_USER,
      subject: subject,
      headers: {
        'X-Priority': '3',
        'Importance': 'normal'
      },
      html: html
    });
    console.log('✅ Renewal reminder sent to', toEmail, '(' + planName + ', ' + daysLeft + 'd left)');
    return true;
  } catch(e){
    console.warn('renewal email failed:', e && e.message);
    return false;
  }
}

/* GISTAPP_RENEWAL_REMINDER — cron: check subscriptions ending in 5d or 1d */
async function checkSubscriptionRenewals(){
  try {
    // Find Pro/Biz users whose subscription ends in the next 6 days
    const r = await pool.query(`
      SELECT id, email, display_name, subscription_tier, subscription_ends_at,
             COALESCE(auto_renew, false) AS auto_renew, prefs
      FROM users
      WHERE subscription_tier IN ('pro','business')
        AND subscription_status = 'active'
        AND subscription_ends_at IS NOT NULL
        AND subscription_ends_at > NOW()
        AND subscription_ends_at < NOW() + INTERVAL '6 days'
        AND email IS NOT NULL
    `);

    for (const u of r.rows){
      try {
        const daysLeft = Math.ceil((new Date(u.subscription_ends_at) - Date.now()) / (24 * 60 * 60 * 1000));
        // Fire at 5 days and 1 day (or below)
        let milestone = null;
        if (daysLeft <= 1) milestone = '1d';
        else if (daysLeft <= 5) milestone = '5d';
        if (!milestone) continue;

        // Check if we already sent for this milestone
        const prefs = u.prefs || {};
        const sentKey = 'renewal_' + milestone + '_sent_at';
        const lastSent = prefs[sentKey];
        if (lastSent){
          const lastMs = Date.parse(lastSent);
          if (!isNaN(lastMs) && (Date.now() - lastMs) < 3 * 24 * 60 * 60 * 1000){
            continue; // sent within last 3 days — skip
          }
        }

        // Don't spam if user already unsubscribed from renewal emails
        if (prefs.renewal_emails === 'false') continue;

        await sendRenewalReminderEmail(u.email, u.display_name, {
          plan: u.subscription_tier,
          days_left: daysLeft,
          ends_at: u.subscription_ends_at,
          auto_renew: u.auto_renew
        });

        // Mark as sent
        await pool.query(
          "UPDATE users SET prefs = COALESCE(prefs,'{}'::jsonb) || jsonb_build_object($1::text, NOW()::text) WHERE id=$2",
          [sentKey, u.id]
        );
      } catch(innerErr){
        console.warn('renewal reminder error for user', u.id, ':', innerErr.message);
      }
    }
  } catch(e){ console.warn('checkSubscriptionRenewals:', e.message); }
}

/* GISTAPP_INVOICE_PDF — generate a PDF invoice for a payment row */
let _PDFDocument = null;
function _getPDFDocument(){
  if (_PDFDocument) return _PDFDocument;
  try {
    _PDFDocument = require('pdfkit');
    return _PDFDocument;
  } catch(e){
    console.warn('pdfkit not available:', e.message);
    return null;
  }
}

async function generateInvoicePDF(payment){
  const PDFDocument = _getPDFDocument();
  if (!PDFDocument) throw new Error('PDF library not available');

  return new Promise(async (resolve, reject) => {
    try {
      const doc = new PDFDocument({ size: 'A4', margin: 50 });
      const chunks = [];
      doc.on('data', c => chunks.push(c));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);

      const baseUrl = process.env.APP_URL || 'https://gistapp.onrender.com';
      const invoiceNum = 'INV-' + String(payment.id || 0).padStart(5, '0');
      const paidAt = payment.completed_at ? new Date(payment.completed_at) : (payment.created_at ? new Date(payment.created_at) : new Date());
      const dateStr = paidAt.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });

      const planKey = payment.plan || 'pro';
      const planName = planKey === 'business' ? 'GistApp Business' : 'GistApp Pro';
      const amount = Number(payment.amount || 0);
      const currency = payment.currency || 'NGN';
      const sym = currency === 'NGN' ? '\u20A6' : currency;
      const amountStr = sym + amount.toLocaleString('en-NG');

      // Colors
      const accent = '#5a6cd6';
      const dark = '#2b2c44';
      const muted = '#6a6a73';
      const line = '#e6e4ef';

      // Header bar
      doc.rect(0, 0, doc.page.width, 110).fill(accent);
      doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(26).text('GistApp', 50, 42);
      doc.font('Helvetica').fontSize(11).fillColor('rgba(255,255,255,0.85)').text('Chat  \u00B7  Stream  \u00B7  Earn', 50, 74);

      doc.font('Helvetica-Bold').fontSize(22).fillColor('#ffffff').text('INVOICE', 0, 45, { align: 'right', width: doc.page.width - 50 });

      // Reset cursor position below header
      doc.fillColor(dark).moveDown(3);

      // Invoice meta (right side)
      const metaTop = 140;
      doc.font('Helvetica').fontSize(9).fillColor(muted)
        .text('INVOICE NUMBER', 50, metaTop)
        .text('DATE', 50, metaTop + 16)
        .text('STATUS', 50, metaTop + 32);
      doc.font('Helvetica-Bold').fontSize(10).fillColor(dark)
        .text(invoiceNum, 50, metaTop + 42)
        .text(dateStr, 50, metaTop + 58)
        .text('PAID', 50, metaTop + 74);

      // Billed to
      doc.font('Helvetica').fontSize(9).fillColor(muted).text('BILLED TO', 320, metaTop);
      doc.font('Helvetica-Bold').fontSize(11).fillColor(dark).text(payment.display_name || 'Customer', 320, metaTop + 16);
      doc.font('Helvetica').fontSize(10).fillColor(dark).text(payment.email || '', 320, metaTop + 32);
      if (payment.reference_id){
        doc.fontSize(9).fillColor(muted).text('Ref: ' + payment.reference_id, 320, metaTop + 50);
      }

      // Horizontal rule
      const lineY = metaTop + 110;
      doc.moveTo(50, lineY).lineTo(doc.page.width - 50, lineY).strokeColor(line).lineWidth(1).stroke();

      // Line items table
      const tableTop = lineY + 20;
      doc.font('Helvetica-Bold').fontSize(9).fillColor(muted)
        .text('DESCRIPTION', 50, tableTop)
        .text('QTY', 380, tableTop, { width: 40, align: 'right' })
        .text('AMOUNT', 430, tableTop, { width: 110, align: 'right' });

      doc.moveTo(50, tableTop + 20).lineTo(doc.page.width - 50, tableTop + 20).strokeColor(line).stroke();

      doc.font('Helvetica-Bold').fontSize(11).fillColor(dark)
        .text(planName + ' \u2014 30 days', 50, tableTop + 36)
        .text('1', 380, tableTop + 36, { width: 40, align: 'right' })
        .text(amountStr, 430, tableTop + 36, { width: 110, align: 'right' });

      doc.font('Helvetica').fontSize(9).fillColor(muted)
        .text('Full access to all ' + (planKey === 'business' ? 'Business' : 'Pro') + ' features', 50, tableTop + 54, { width: 300 });

      // Totals
      const totalsTop = tableTop + 110;
      doc.moveTo(50, totalsTop).lineTo(doc.page.width - 50, totalsTop).strokeColor(line).stroke();

      const totalX = 330;
      doc.font('Helvetica').fontSize(10).fillColor(muted).text('Subtotal', totalX, totalsTop + 16);
      doc.font('Helvetica-Bold').fontSize(10).fillColor(dark).text(amountStr, totalX, totalsTop + 16, { width: 210, align: 'right' });

      doc.font('Helvetica').fontSize(10).fillColor(muted).text('Tax (0%)', totalX, totalsTop + 34);
      doc.font('Helvetica-Bold').fontSize(10).fillColor(dark).text('\u2014', totalX, totalsTop + 34, { width: 210, align: 'right' });

      // Total row (highlighted)
      const totalRowY = totalsTop + 60;
      doc.rect(totalX, totalRowY - 6, 210, 34).fill('#f4f2fb');
      doc.font('Helvetica-Bold').fontSize(12).fillColor(dark).text('Total', totalX + 12, totalRowY + 4);
      doc.font('Helvetica-Bold').fontSize(14).fillColor(dark).text(amountStr, totalX, totalRowY + 2, { width: 200, align: 'right' });

      // Payment method
      const payTop = totalRowY + 60;
      const method = payment.method === 'manual' ? 'Bank transfer (OPay)' : 'Card (Paystack)';
      doc.font('Helvetica').fontSize(9).fillColor(muted).text('PAYMENT METHOD', 50, payTop);
      doc.font('Helvetica-Bold').fontSize(10).fillColor(dark).text(method, 50, payTop + 14);
      if (payment.payer_name){
        doc.font('Helvetica').fontSize(9).fillColor(muted).text('PAYER', 50, payTop + 36);
        doc.font('Helvetica-Bold').fontSize(10).fillColor(dark).text(payment.payer_name, 50, payTop + 50);
      }

      // Footer
      const footY = doc.page.height - 90;
      doc.moveTo(50, footY).lineTo(doc.page.width - 50, footY).strokeColor(line).stroke();
      doc.font('Helvetica').fontSize(9).fillColor(muted)
        .text('Operated by PERION DEVELOPMENT LTD', 50, footY + 14)
        .text('Questions? Contact support@gistapp.app', 50, footY + 28);

      doc.fontSize(8).fillColor(muted)
        .text('Generated automatically by GistApp on ' + new Date().toISOString().slice(0, 10), 50, footY + 46, { width: doc.page.width - 100, align: 'center' });

      doc.end();
    } catch(e){ reject(e); }
  });
}

/* GISTAPP_EARNINGS_PDF — creator earnings report (stats + breakdown) */
async function generateEarningsPDF(userId, range){
  const PDFDocument = _getPDFDocument();
  if (!PDFDocument) throw new Error('PDF library not available');

  // Fetch data
  const uid = userId;
  let interval = "30 days";
  if (range === '7d') interval = "7 days";
  else if (range === 'all') interval = null;
  const whereTime = interval ? "AND ls.started_at > NOW() - INTERVAL '" + interval + "'" : "";

  const me = await pool.query('SELECT email, display_name FROM users WHERE id=$1', [uid]);
  const user = me.rows[0] || { display_name: 'Creator', email: '' };

  const totals = await pool.query(
    `SELECT
       COUNT(*)::int AS streams,
       COALESCE(SUM(EXTRACT(EPOCH FROM (COALESCE(ls.ended_at, ls.started_at) - ls.started_at)) / 3600), 0)::numeric(10,1) AS hours_streamed,
       COALESCE(SUM(ls.peak_viewers), 0)::int AS peak_viewers,
       COALESCE(SUM(ls.gift_count), 0)::int AS gift_count
     FROM live_streams ls WHERE ls.streamer_id=$1 ${whereTime}`,
    [uid]
  );
  const t = totals.rows[0] || {};

  const earnings = await pool.query(
    `SELECT COALESCE(SUM(lg.coins), 0)::int AS gross_coins
     FROM live_gifts lg JOIN live_streams ls ON ls.id=lg.stream_id
     WHERE ls.streamer_id=$1 ${whereTime}`,
    [uid]
  );
  const grossCoins = earnings.rows[0] ? earnings.rows[0].gross_coins : 0;
  const creatorCoins = Math.floor(grossCoins * 0.7);
  const creatorNgn = Math.floor(creatorCoins / 10);

  const streams = await pool.query(
    `SELECT ls.id, ls.title, ls.peak_viewers, ls.started_at,
            COALESCE((SELECT SUM(lg.coins) FROM live_gifts lg WHERE lg.stream_id=ls.id), 0)::int AS coins
     FROM live_streams ls WHERE ls.streamer_id=$1 ${whereTime}
     ORDER BY ls.started_at DESC LIMIT 15`,
    [uid]
  );

  const gifts = await pool.query(
    `SELECT lg.gift_type, COUNT(*)::int AS n, COALESCE(SUM(lg.coins),0)::int AS coins
     FROM live_gifts lg JOIN live_streams ls ON ls.id=lg.stream_id
     WHERE ls.streamer_id=$1 ${whereTime}
     GROUP BY lg.gift_type ORDER BY coins DESC`,
    [uid]
  );

  const rangeLabel = range === '7d' ? 'Last 7 days' : range === 'all' ? 'All time' : 'Last 30 days';

  return new Promise(async (resolve, reject) => {
    try {
      const doc = new PDFDocument({ size: 'A4', margin: 50 });
      const chunks = [];
      doc.on('data', c => chunks.push(c));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);

      const accent = '#5a6cd6';
      const dark = '#2b2c44';
      const muted = '#6a6a73';
      const line = '#e6e4ef';

      // Header
      doc.rect(0, 0, doc.page.width, 100).fill(accent);
      doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(24).text('GistApp', 50, 34);
      doc.font('Helvetica').fontSize(10).fillColor('rgba(255,255,255,0.85)').text('Creator Earnings Report', 50, 66);
      doc.font('Helvetica-Bold').fontSize(14).fillColor('#ffffff').text(rangeLabel, 0, 42, { align: 'right', width: doc.page.width - 50 });

      // Creator info
      const metaTop = 130;
      doc.font('Helvetica').fontSize(9).fillColor(muted).text('CREATOR', 50, metaTop);
      doc.font('Helvetica-Bold').fontSize(12).fillColor(dark).text(user.display_name || 'Creator', 50, metaTop + 16);
      doc.font('Helvetica').fontSize(10).fillColor(dark).text(user.email || '', 50, metaTop + 34);
      doc.font('Helvetica').fontSize(9).fillColor(muted).text('Generated on', 350, metaTop);
      doc.font('Helvetica-Bold').fontSize(10).fillColor(dark).text(new Date().toLocaleString('en-GB', { timeZone: 'Africa/Lagos' }) + ' WAT', 350, metaTop + 16);

      // Earnings hero card
      const heroY = metaTop + 80;
      doc.rect(50, heroY, doc.page.width - 100, 90).fill('#f4f2fb');
      doc.font('Helvetica').fontSize(10).fillColor(muted).text('TOTAL EARNED', 70, heroY + 16);
      doc.font('Helvetica-Bold').fontSize(32).fillColor(dark).text(creatorCoins.toLocaleString() + ' \u20AE', 70, heroY + 32, { continued: false });
      doc.font('Helvetica').fontSize(11).fillColor(dark).text('\u2248 \u20A6' + creatorNgn.toLocaleString(), 70, heroY + 68);
      doc.font('Helvetica').fontSize(9).fillColor(muted).text('Gross: ' + grossCoins.toLocaleString() + ' \u20AE  \u00B7  70% creator share', 300, heroY + 16);
      doc.font('Helvetica-Bold').fontSize(20).fillColor(dark).text(String(t.streams || 0), 300, heroY + 36);
      doc.font('Helvetica').fontSize(9).fillColor(muted).text('streams', 300, heroY + 62);
      doc.font('Helvetica-Bold').fontSize(20).fillColor(dark).text(String(t.gift_count || 0), 420, heroY + 36);
      doc.font('Helvetica').fontSize(9).fillColor(muted).text('gifts', 420, heroY + 62);

      // Summary stats row
      const statsY = heroY + 110;
      const statBox = (label, value, x) => {
        doc.font('Helvetica').fontSize(9).fillColor(muted).text(label.toUpperCase(), x, statsY);
        doc.font('Helvetica-Bold').fontSize(14).fillColor(dark).text(value, x, statsY + 14);
      };
      statBox('Hours streamed', String(t.hours_streamed || 0), 50);
      statBox('Peak viewers', String(t.peak_viewers || 0), 200);
      statBox('Streams', String(t.streams || 0), 350);
      statBox('Avg coins/stream', t.streams ? Math.round(grossCoins / t.streams) + ' \u20AE' : '\u2014', 460);

      // Streams table
      let tableY = statsY + 60;
      doc.font('Helvetica-Bold').fontSize(11).fillColor(dark).text('Stream breakdown', 50, tableY);
      tableY += 22;
      doc.font('Helvetica-Bold').fontSize(8.5).fillColor(muted);
      doc.text('DATE', 50, tableY);
      doc.text('TITLE', 120, tableY);
      doc.text('VIEWERS', 380, tableY, { width: 60, align: 'right' });
      doc.text('COINS', 440, tableY, { width: 100, align: 'right' });
      tableY += 14;
      doc.moveTo(50, tableY).lineTo(doc.page.width - 50, tableY).strokeColor(line).lineWidth(0.5).stroke();
      tableY += 6;

      const streamRows = streams.rows;
      if (streamRows.length === 0){
        doc.font('Helvetica-Oblique').fontSize(10).fillColor(muted).text('No streams in this period.', 50, tableY + 4);
        tableY += 24;
      } else {
        for (const s of streamRows){
          if (tableY > doc.page.height - 120) break;
          const dt = new Date(s.started_at).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
          doc.font('Helvetica').fontSize(10).fillColor(dark).text(dt, 50, tableY);
          doc.font('Helvetica').fontSize(10).fillColor(dark).text(String(s.title || 'Untitled').slice(0, 40), 120, tableY, { width: 250, ellipsis: true });
          doc.font('Helvetica').fontSize(10).fillColor(dark).text(String(s.peak_viewers || 0), 380, tableY, { width: 60, align: 'right' });
          doc.font('Helvetica-Bold').fontSize(10).fillColor(dark).text(String(s.coins || 0), 440, tableY, { width: 100, align: 'right' });
          tableY += 18;
        }
      }

      // Gift breakdown
      const giftRows = gifts.rows;
      if (giftRows.length && tableY < doc.page.height - 160){
        tableY += 20;
        doc.font('Helvetica-Bold').fontSize(11).fillColor(dark).text('Top gifts', 50, tableY);
        tableY += 22;
        doc.font('Helvetica-Bold').fontSize(8.5).fillColor(muted);
        doc.text('GIFT', 50, tableY);
        doc.text('COUNT', 300, tableY, { width: 80, align: 'right' });
        doc.text('COINS', 400, tableY, { width: 140, align: 'right' });
        tableY += 14;
        doc.moveTo(50, tableY).lineTo(doc.page.width - 50, tableY).strokeColor(line).stroke();
        tableY += 6;

        for (const g of giftRows.slice(0, 8)){
          if (tableY > doc.page.height - 100) break;
          doc.font('Helvetica').fontSize(10).fillColor(dark).text(String(g.gift_type || 'gift').toUpperCase(), 50, tableY);
          doc.font('Helvetica').fontSize(10).fillColor(dark).text(String(g.n), 300, tableY, { width: 80, align: 'right' });
          doc.font('Helvetica-Bold').fontSize(10).fillColor(dark).text(String(g.coins), 400, tableY, { width: 140, align: 'right' });
          tableY += 18;
        }
      }

      // Footer
      const footY = doc.page.height - 80;
      doc.moveTo(50, footY).lineTo(doc.page.width - 50, footY).strokeColor(line).stroke();
      doc.font('Helvetica').fontSize(9).fillColor(muted);
      doc.text('GistApp Creator Report \u00B7 Operated by PERION DEVELOPMENT LTD', 50, footY + 12);
      doc.text('support@gistapp.app', 50, footY + 26);
      doc.fontSize(8).fillColor(muted).text(
        'Generated automatically by GistApp on ' + new Date().toISOString().slice(0, 10),
        50, footY + 42, { width: doc.page.width - 100, align: 'center' }
      );

      doc.end();
    } catch(e){ reject(e); }
  });
}

/* GISTAPP_INVOICE_PDF — send receipt email WITH PDF attachment */
async function sendPaymentReceiptEmailWithInvoice(toEmail, displayName, info){
  // delegate to existing sendPaymentReceiptEmail, but attach the invoice if we can find the payment row
  try {
    if (info && info.payment_id){
      const r = await pool.query(
        'SELECT p.*, u.email, u.display_name FROM payments p JOIN users u ON u.id=p.user_id WHERE p.id=$1',
        [info.payment_id]
      );
      if (r.rowCount){
        const payment = r.rows[0];
        const pdfBuf = await generateInvoicePDF(payment);
        // Attach to the receipt email — modify existing sendPaymentReceiptEmail signature
        return sendPaymentReceiptEmail(toEmail, displayName, Object.assign({}, info, { _pdfBuffer: pdfBuf, _pdfName: 'GistApp-Invoice-' + String(payment.id).padStart(5, '0') + '.pdf' }));
      }
    }
  } catch(e){ console.warn('invoice attach failed:', e.message); }
  // fallback: send without attachment
  return sendPaymentReceiptEmail(toEmail, displayName, info);
}

/* GISTAPP_SECURITY_ALERT — emails on critical account changes */
async function sendSecurityAlertEmail(toEmail, displayName, eventType, meta){
  if (!toEmail) return;
  meta = meta || {};
  const baseUrl = process.env.APP_URL || 'http://localhost:3000';
  const iconUrl = baseUrl + '/icon-192.png';
  const name = displayName || 'there';
  const configs = {
    '2fa_enabled':   { emoji:'\uD83D\uDEE1\uFE0F', title:'Two-factor authentication enabled',
                       body:'2FA is now active on your GistApp account. You will need your authenticator app to sign in.' },
    '2fa_disabled':  { emoji:'\u26A0\uFE0F', title:'Two-factor authentication DISABLED',
                       body:'2FA was turned off. Your account is now protected by password only. If you did not do this, re-enable 2FA immediately.' },
    'email_changed': { emoji:'\u2709\uFE0F', title:'Your account email was changed',
                       body:'The email on your GistApp account was changed to <b>' + (meta.newEmail || 'a new address') + '</b>. If you did not do this, secure your account immediately.' }
  };
  const c = configs[eventType];
  if (!c) return;
  const time = new Date().toLocaleString('en-GB', { timeZone: 'Africa/Lagos' }) + ' WAT';
  const ip = meta.ip ? String(meta.ip) : 'unknown';
  try {
    await mailer.sendMail({
      from: '"GistApp Security" <' + GMAIL_SENDER + '>',
      to: toEmail,
      replyTo: process.env.SMTP_USER,
      subject: c.emoji + ' ' + c.title,
      headers: { 'X-Priority': '3', 'Importance': 'normal', 'List-Unsubscribe': '<mailto:' + process.env.SMTP_USER + '>' },
      html: `
        <div style="font-family:Inter,-apple-system,system-ui,sans-serif;max-width:520px;margin:0 auto;padding:0;background:#f7f5ff;border-radius:20px;overflow:hidden">
          <div style="background:linear-gradient(135deg,#e5484d,#ff6b6b);padding:24px 32px;text-align:center">
            <img src="${iconUrl}" alt="GistApp" width="56" height="56" style="border-radius:14px;display:block;margin:0 auto 10px">
            <div style="color:#fff;font-size:20px;font-weight:800">${c.emoji} ${c.title}</div>
          </div>
          <div style="padding:28px 32px 32px">
            <p style="color:#33344c;font-size:16px;line-height:1.6;margin:0 0 16px">Hi ${name},</p>
            <p style="color:#4a4568;font-size:15px;line-height:1.6;margin:0 0 20px">${c.body}</p>
            <div style="background:#fff;border:1px solid #e6e2ff;border-radius:12px;padding:14px 16px;margin:0 0 22px">
              <table style="width:100%;font-size:13.5px;color:#4a4568;line-height:1.7">
                <tr><td style="color:#8e8e93;padding-right:12px">Account:</td><td>${toEmail}</td></tr>
                <tr><td style="color:#8e8e93;padding-right:12px">Time:</td><td>${time}</td></tr>
                <tr><td style="color:#8e8e93;padding-right:12px">IP:</td><td>${ip}</td></tr>
              </table>
            </div>
            <div style="background:#fff3cd;border:1px solid #ffe58f;border-radius:12px;padding:14px 16px;margin:0 0 22px">
              <p style="color:#7a5a00;font-size:13.5px;line-height:1.6;margin:0"><b>If this wasn't you</b>, secure your account immediately.</p>
            </div>
            <div style="text-align:center;margin:24px 0 12px">
              <a href="${baseUrl}" style="background:#e5484d;color:#fff;text-decoration:none;padding:13px 32px;border-radius:12px;font-weight:700;display:inline-block;font-size:15px">Open GistApp</a>
            </div>
            <p style="color:#8e8e93;font-size:12.5px;line-height:1.6;margin:20px 0 0;text-align:center">You're receiving this because security settings on your GistApp account changed.<br>&copy; GistApp</p>
          </div>
        </div>
      `
    });
    console.log('\u2705 Security alert sent (' + eventType + ') to', toEmail);
    return true;
  } catch(e){
    console.warn('security alert failed:', e && e.message);
    return false;
  }
}

/* GISTAPP_PAYMENT_RECEIPT — sent on successful Paystack or manual payment */
async function sendPaymentReceiptEmail(toEmail, displayName, info){
  if (!toEmail) return;
  info = info || {};
  const baseUrl = process.env.APP_URL || 'https://gistapp.onrender.com';
  const iconUrl = baseUrl + '/icon-192.png';
  const name = displayName || 'there';

  const planKey = info.plan || 'pro';
  const planName = planKey === 'business' ? 'GistApp Business' : 'GistApp Pro';
  const amountNgn = Number(info.amount || 0);
  const amountStr = '₦' + amountNgn.toLocaleString('en-NG');
  const method = info.method === 'manual' ? 'Bank transfer (OPay)' : 'Card (Paystack)';
  const ref = info.reference || '—';
  const paidAt = new Date(info.completed_at || Date.now()).toLocaleString('en-GB', { timeZone: 'Africa/Lagos' }) + ' WAT';
  const nextBill = new Date(Date.now() + (info.days || 30) * 24 * 60 * 60 * 1000).toLocaleDateString('en-GB', { timeZone: 'Africa/Lagos', day: 'numeric', month: 'short', year: 'numeric' });

  const row = (label, value, bold) =>
    '<tr>' +
    '<td style="padding:10px 0;color:#6a6a73;font-size:13px;' + (bold ? 'font-weight:700' : '') + '">' + label + '</td>' +
    '<td style="padding:10px 0;color:#1c1c22;font-size:13px;text-align:right;' + (bold ? 'font-weight:800;font-size:15px' : 'font-weight:600') + '">' + value + '</td>' +
    '</tr>';

  const html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Receipt</title></head>' +
  '<body style="margin:0;padding:0;background:#f2f0fa;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Inter,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased">' +
  '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f2f0fa;padding:24px 12px">' +
  '<tr><td align="center">' +
  '<table role="presentation" width="560" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:24px;overflow:hidden;box-shadow:0 12px 40px rgba(51,52,76,.10)">' +

  // Header
  '<tr><td style="background:linear-gradient(135deg,#0d8a5a 0%,#22a36b 55%,#34c47f 100%);padding:30px 32px 26px;text-align:center">' +
  '<img src="' + iconUrl + '" alt="GistApp" width="56" height="56" style="border-radius:14px;display:block;margin:0 auto 12px;box-shadow:0 8px 22px rgba(0,0,0,.3)">' +
  '<div style="color:#ffffff;font-size:12px;font-weight:700;letter-spacing:1.6px;text-transform:uppercase;opacity:.9">Payment received</div>' +
  '<div style="color:#ffffff;font-size:28px;font-weight:800;letter-spacing:-.5px;margin-top:6px">' + amountStr + '</div>' +
  '</td></tr>' +

  // Greeting
  '<tr><td style="padding:28px 32px 4px">' +
  '<p style="margin:0 0 12px;color:#1c1c22;font-size:17px;font-weight:700;letter-spacing:-.2px">Hi ' + name + ',</p>' +
  '<p style="margin:0;color:#4a4a55;font-size:14.5px;line-height:1.65">Thanks for subscribing to ' + planName + '. Your receipt is below — keep this email for your records.</p>' +
  '</td></tr>' +

  // Receipt card
  '<tr><td style="padding:22px 32px 0">' +
  '<div style="background:#fafaff;border:1px solid #eae7f5;border-radius:14px;padding:6px 20px">' +
  '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse">' +
  row('Plan', planName) +
  row('Method', method) +
  row('Reference', ref) +
  row('Paid at', paidAt) +
  '<tr><td colspan="2" style="padding:0;border-top:1px solid #eae7f5;height:0;line-height:0">&nbsp;</td></tr>' +
  row('Total paid', amountStr, true) +
  '</table>' +
  '</div>' +
  '</td></tr>' +

  // What's active
  '<tr><td style="padding:24px 32px 0">' +
  '<div style="background:#f0fbf4;border:1px solid #c9efd6;border-radius:14px;padding:16px 20px">' +
  '<div style="color:#1f7a3d;font-size:13px;font-weight:800;letter-spacing:.2px;margin-bottom:8px">What is now active</div>' +
  '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">' +
  '<tr><td style="padding:4px 0;color:#1f7a3d;font-size:14px;width:22px">&#10003;</td><td style="padding:4px 0;color:#2b2c44;font-size:13.5px">Verified badge on your profile</td></tr>' +
  '<tr><td style="padding:4px 0;color:#1f7a3d;font-size:14px">&#10003;</td><td style="padding:4px 0;color:#2b2c44;font-size:13.5px">' + (planKey === 'business' ? 'All Business features unlocked' : 'All Pro features unlocked') + '</td></tr>' +
  '<tr><td style="padding:4px 0;color:#1f7a3d;font-size:14px">&#10003;</td><td style="padding:4px 0;color:#2b2c44;font-size:13.5px">Access until <b>' + nextBill + '</b></td></tr>' +
  '</table>' +
  '</div>' +
  '</td></tr>' +

  // CTA
  '<tr><td style="padding:26px 32px 6px;text-align:center">' +
  '<a href="' + baseUrl + '" style="background:#2b2c44;color:#ffffff;text-decoration:none;padding:14px 40px;border-radius:14px;font-weight:800;display:inline-block;font-size:14.5px;letter-spacing:.2px">Open GistApp</a>' +
  '</td></tr>' +

  // Manage link
  '<tr><td style="padding:10px 32px 28px;text-align:center">' +
  '<p style="margin:0;color:#8e8e93;font-size:12.5px;line-height:1.6">Need to update your payment info or cancel?<br>' +
  'Go to <b>Settings &rarr; Subscription</b> or reply to this email.</p>' +
  '</td></tr>' +

  // Footer
  '<tr><td style="background:#f7f6fc;padding:18px 32px;text-align:center;border-top:1px solid #eae7f5">' +
  '<p style="margin:0 0 6px;color:#8e8e93;font-size:11.5px;line-height:1.6">This receipt was sent to ' + toEmail + '.</p>' +
  '<p style="margin:0;color:#a8a5b3;font-size:11px;line-height:1.6">&copy; ' + new Date().getFullYear() + ' GistApp Community &middot; All rights reserved.</p>' +
  '</td></tr>' +

  '</table></td></tr></table></body></html>';

  try {
    var _mailOpts = {
      from: '"GistApp" <' + GMAIL_SENDER + '>',
      to: toEmail,
      replyTo: process.env.SMTP_USER,
      subject: 'Your GistApp receipt — ' + amountStr + ' (' + planName + ')',
      headers: {
        'X-Priority': '3',
        'Importance': 'normal'
      },
      html: html
    };
    // GISTAPP_INVOICE_PDF — attach invoice if provided
    if (info && info._pdfBuffer){
      _mailOpts.attachments = [{
        filename: info._pdfName || 'GistApp-Invoice.pdf',
        content: info._pdfBuffer,
        contentType: 'application/pdf'
      }];
    }
    await mailer.sendMail(_mailOpts);
    console.log('✅ Receipt sent to', toEmail, '(' + ref + ')' + (info && info._pdfBuffer ? ' [PDF attached]' : ''));
    return true;
  } catch(e){
    console.warn('receipt email failed:', e && e.message);
    return false;
  }
}

/* GISTAPP_GIFT_EMAIL — notified streamer when a gift arrives while they're offline */
const GIFT_EMOJI_MAP = {
  heart:'❤️', rose:'🌹', fire:'🔥', star:'⭐', cake:'🎂',
  crown:'👑', diamond:'💎', rocket:'🚀'
};
async function sendGiftEmail(toEmail, displayName, info){
  if (!toEmail) return false;
  info = info || {};
  const baseUrl = process.env.APP_URL || 'https://gistapp.onrender.com';
  const iconUrl = baseUrl + '/icon-192.png';
  const name = displayName || 'there';
  const senderName = info.sender_name || 'Someone';
  const emoji = GIFT_EMOJI_MAP[info.gift_type] || '🎁';
  const coins = Number(info.coins || 0);
  const creatorCoins = Number(info.creator_coins || Math.floor(coins * 0.7));
  const streamTitle = info.stream_title || 'your live stream';
  const when = new Date().toLocaleString('en-GB', { timeZone: 'Africa/Lagos' }) + ' WAT';

  const html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>New gift</title></head>' +
  '<body style="margin:0;padding:0;background:#f2f0fa;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Inter,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased">' +
  '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f2f0fa;padding:24px 12px">' +
  '<tr><td align="center">' +
  '<table role="presentation" width="560" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:24px;overflow:hidden;box-shadow:0 12px 40px rgba(51,52,76,.10)">' +

  // Header
  '<tr><td style="background:linear-gradient(135deg,#d97706 0%,#f59e0b 55%,#fbbf24 100%);padding:30px 32px 26px;text-align:center">' +
  '<img src="' + iconUrl + '" alt="GistApp" width="56" height="56" style="border-radius:14px;display:block;margin:0 auto 12px;box-shadow:0 8px 22px rgba(0,0,0,.3)">' +
  '<div style="font-size:52px;line-height:1;margin:0 0 8px">' + emoji + '</div>' +
  '<div style="color:#ffffff;font-size:20px;font-weight:800;letter-spacing:-.3px">You received a gift!</div>' +
  '</td></tr>' +

  // Body
  '<tr><td style="padding:28px 32px 4px">' +
  '<p style="margin:0 0 12px;color:#1c1c22;font-size:17px;font-weight:700;letter-spacing:-.2px">Hey ' + name + ',</p>' +
  '<p style="margin:0;color:#4a4a55;font-size:14.5px;line-height:1.65"><b>' + senderName + '</b> just sent you a gift during <b>' + streamTitle + '</b>. You earned coins while you were away.</p>' +
  '</td></tr>' +

  // Earnings card
  '<tr><td style="padding:22px 32px 0">' +
  '<div style="background:linear-gradient(135deg,#fff9e6,#fff3c4);border:1px solid #fde68a;border-radius:14px;padding:20px 22px;text-align:center">' +
  '<div style="color:#92400e;font-size:11px;font-weight:800;letter-spacing:1.4px;text-transform:uppercase">You earned</div>' +
  '<div style="color:#1c1c22;font-size:34px;font-weight:800;letter-spacing:-.5px;line-height:1.1;margin-top:6px">' + creatorCoins + ' 🪙</div>' +
  '<div style="color:#92400e;font-size:12.5px;font-weight:600;margin-top:4px">from a ' + coins + ' 🪙 ' + (info.gift_type || 'gift') + '</div>' +
  '</div>' +
  '</td></tr>' +

  // Details
  '<tr><td style="padding:20px 32px 0">' +
  '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#fafaff;border:1px solid #eae7f5;border-radius:12px;padding:0 16px">' +
  '<tr><td style="padding:10px 0;color:#6a6a73;font-size:13px">Gift</td><td style="padding:10px 0;color:#1c1c22;font-size:13px;font-weight:700;text-align:right">' + emoji + ' ' + (info.gift_type || 'gift') + '</td></tr>' +
  '<tr><td style="padding:10px 0;color:#6a6a73;font-size:13px;border-top:1px solid #f0edf5">From</td><td style="padding:10px 0;color:#1c1c22;font-size:13px;font-weight:700;text-align:right">' + senderName + '</td></tr>' +
  '<tr><td style="padding:10px 0;color:#6a6a73;font-size:13px;border-top:1px solid #f0edf5">When</td><td style="padding:10px 0;color:#1c1c22;font-size:13px;font-weight:700;text-align:right">' + when + '</td></tr>' +
  '</table>' +
  '</td></tr>' +

  // CTA
  '<tr><td style="padding:26px 32px 6px;text-align:center">' +
  '<a href="' + baseUrl + '" style="background:#2b2c44;color:#ffffff;text-decoration:none;padding:14px 40px;border-radius:14px;font-weight:800;display:inline-block;font-size:14.5px;letter-spacing:.2px">Open GistApp</a>' +
  '</td></tr>' +

  // Footer with preferences
  '<tr><td style="padding:10px 32px 28px;text-align:center">' +
  '<p style="margin:0;color:#8e8e93;font-size:12px;line-height:1.6">You got this because a viewer sent you a gift.<br>' +
  'Turn off gift emails in <b>Settings &rarr; Notifications</b>.</p>' +
  '</td></tr>' +

  '<tr><td style="background:#f7f6fc;padding:18px 32px;text-align:center;border-top:1px solid #eae7f5">' +
  '<p style="margin:0;color:#a8a5b3;font-size:11px;line-height:1.6">&copy; ' + new Date().getFullYear() + ' GistApp Community &middot; All rights reserved.</p>' +
  '</td></tr>' +

  '</table></td></tr></table></body></html>';

  try {
    await mailer.sendMail({
      from: '"GistApp" <' + GMAIL_SENDER + '>',
      to: toEmail,
      replyTo: process.env.SMTP_USER,
      subject: emoji + ' ' + senderName + ' sent you ' + creatorCoins + ' coins!',
      headers: {
        'X-Priority': '3',
        'Importance': 'normal'
      },
      html: html
    });
    console.log('✅ Gift email sent to', toEmail, '(' + senderName + ' → ' + creatorCoins + ' coins)');
    return true;
  } catch(e){
    console.warn('gift email failed:', e && e.message);
    return false;
  }
}

// Throttle map: userId → timestamp of last gift email (in-memory, resets on restart)
const _giftEmailLastSent = new Map();

/* GISTAPP_MSG_EMAIL — offline DM notification emails (throttled 1/hr per user) */
const _msgEmailLastSent = new Map(); // userId -> ts

async function sendMessageNotificationEmail(toEmail, toName, info){
  if (!toEmail) return false;
  info = info || {};
  const baseUrl = process.env.APP_URL || 'https://gistapp.onrender.com';
  const iconUrl = baseUrl + '/icon-192.png';
  const name = toName || 'there';
  const senderName = info.sender_name || 'Someone';
  const snippet = String(info.snippet || '').slice(0, 200);
  const chatId = info.chat_id;

  const html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>New message</title></head>' +
  '<body style="margin:0;padding:0;background:#f2f0fa;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Inter,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased">' +
  '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f2f0fa;padding:24px 12px">' +
  '<tr><td align="center">' +
  '<table role="presentation" width="560" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:24px;overflow:hidden;box-shadow:0 12px 40px rgba(51,52,76,.10)">' +
  '<tr><td style="background:linear-gradient(135deg,#2b2c44 0%,#5a6cd6 55%,#7b8cff 100%);padding:24px 32px;text-align:center">' +
  '<img src="' + iconUrl + '" alt="GistApp" width="48" height="48" style="border-radius:12px;display:block;margin:0 auto 8px">' +
  '<div style="color:#fff;font-size:18px;font-weight:800">💬 New message on GistApp</div>' +
  '</td></tr>' +
  '<tr><td style="padding:26px 32px 8px">' +
  '<p style="margin:0 0 14px;color:#1c1c22;font-size:15.5px;line-height:1.5"><b>' + senderName + '</b> sent you a message' + (info.chat_name ? ' in <b>' + info.chat_name + '</b>' : '') + ':</p>' +
  '<div style="background:#fafaff;border:1px solid #eae7f5;border-left:3px solid #7b8cff;border-radius:10px;padding:14px 16px;color:#2b2c44;font-size:14px;line-height:1.55;word-wrap:break-word">' + snippet + '</div>' +
  '</td></tr>' +
  '<tr><td style="padding:24px 32px 30px;text-align:center">' +
  '<a href="' + baseUrl + '" style="background:#2b2c44;color:#fff;text-decoration:none;padding:13px 36px;border-radius:12px;font-weight:700;display:inline-block;font-size:14px">Reply on GistApp</a>' +
  '</td></tr>' +
  '<tr><td style="background:#f7f6fc;padding:18px 32px;text-align:center;border-top:1px solid #eae7f5">' +
  '<p style="margin:0 0 6px;color:#8e8e93;font-size:11.5px;line-height:1.6">You got this because a message arrived while you were away.</p>' +
  '<p style="margin:0;color:#a8a5b3;font-size:11px">Turn off message emails in <b>Settings → Notifications</b>.</p>' +
  '</td></tr>' +
  '</table></td></tr></table></body></html>';

  try {
    await mailer.sendMail({
      from: '"GistApp" <' + GMAIL_SENDER + '>',
      to: toEmail,
      replyTo: process.env.SMTP_USER,
      subject: senderName + ' sent you a message on GistApp',
      headers: { 'X-Priority': '3', 'Importance': 'normal' },
      html: html
    });
    console.log('✅ Message notification sent to', toEmail, '(from ' + senderName + ')');
    return true;
  } catch(e){
    console.warn('msg email failed:', e && e.message);
    return false;
  }
}

const app    = express();

/* ========== GISTAPP_RATE_LIMIT_V1 ========== */
// Trust proxy (Render sits behind a reverse proxy)
app.set('trust proxy', 1);

// Global: 200 requests / minute per IP for any /api/* route
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' },
  skip: (req) => req.method === 'OPTIONS',
});

// Signup: 3 accounts / hour per IP
const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many accounts created from this IP. Try again later.' },
  keyGenerator: (req) => ipKeyGenerator(req.ip),  // GISTAPP_IPV6_FIX
});

// Login: 10 attempts / 15 min per IP + email combo (prevents brute-force)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
  keyGenerator: (req) => ipKeyGenerator(req.ip) + '|' + String((req.body && req.body.email) || '').toLowerCase(),  // GISTAPP_IPV6_FIX
});

// Forgot-password: 5 requests / hour per IP
const pwResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many password reset requests. Try again later.' },
});

// Verify-resend: 3 requests / hour per email
const resendLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many resend requests. Try again later.' },
  keyGenerator: (req) => ipKeyGenerator(req.ip) + '|' + String((req.body && req.body.email) || '').toLowerCase(),  // GISTAPP_IPV6_FIX
});

// Upload: 60 files / hour per user
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Upload limit reached. Try again in an hour.' },
});

// Apply global limiter to every /api/* request
app.use('/api', globalLimiter);

console.log('✅ Rate limiting enabled (global 200/min, signup 3/hr, login 10/15min)');

const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const onlineUsers = new Map();

/* ---------- uploads ---------- */
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (_req,_file,cb)=>cb(null, uploadDir),
  filename: (_req,file,cb)=>cb(null, Date.now()+'-'+Math.random().toString(36).slice(2,8)+path.extname(file.originalname||''))
});
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 } });

/* ---------- upstash blob (permanent media storage) ---------- GISTAPP_UPSTASH_SAFE */
const UPSTASH_TOKEN = process.env.UPSTASH_BLOB_TOKEN || '';
const UPSTASH_OK = !!UPSTASH_TOKEN;
let blobBucket = null;
let _upstashInitError = null;

// Lazy + safe: never crash the server if the token is bad
function getBlobBucket(){
  if (blobBucket) return blobBucket;
  if (!UPSTASH_OK){ _upstashInitError = 'UPSTASH_BLOB_TOKEN missing'; return null; }
  try {
    const { Bucket } = require('@upstash/blob');
    blobBucket = new Bucket({ token: UPSTASH_TOKEN });
    return blobBucket;
  } catch(e){
    _upstashInitError = e.message || String(e);
    console.warn('⚠️  Upstash Blob init failed:', _upstashInitError);
    console.warn('⚠️  Uploads will return 503 until UPSTASH_BLOB_TOKEN is valid.');
    return null;
  }
}

// Do NOT call getBlobBucket() at boot — only on first upload
if (UPSTASH_OK){
  console.log('📦 Upstash Blob token present (lazy init on first upload)');
} else {
  console.warn('⚠️  UPSTASH_BLOB_TOKEN missing — uploads will fail');
}

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* GISTAPP_LIVE_SHARE_V1 — /live/:id serves index.html with injected OG tags for rich previews */
const fs_share = require('fs');
const path_share = require('path');
function _escapeHTML(str){
  return String(str == null ? '' : str).replace(/[&<>"']/g, function(c){
    return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c];
  });
}
app.get('/live/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const indexPath = path_share.join(__dirname, 'public', 'index.html');
    let html = fs_share.readFileSync(indexPath, 'utf8');
    const baseUrl = process.env.APP_URL || 'https://gistapp.onrender.com';

    // Try to load stream info
    let ogTitle = 'GistApp — Chat, Stream, Earn';
    let ogDesc  = 'Chat by email, go live, and earn from gifts.';
    let ogImage = baseUrl + '/icon-512.png';
    let ogUrl   = baseUrl + '/live/' + id;

    try {
      const r = await pool.query(
        `SELECT s.title, s.status, u.display_name, u.username, u.avatar_url
         FROM live_streams s
         JOIN users u ON u.id = s.streamer_id
         WHERE s.id=$1`,
        [id]
      );
      if (r.rowCount){
        const st = r.rows[0];
        const name = st.display_name || st.username || 'Someone';
        if (st.status === 'live'){
          ogTitle = '🔴 ' + name + ' is live on GistApp';
          ogDesc  = st.title ? st.title : ('Watch ' + name + ' live right now');
        } else {
          ogTitle = name + ' on GistApp';
          ogDesc  = 'Live stream ended — see more on GistApp';
        }
        if (st.avatar_url){
          // GISTAPP_LIVE_SHARE_IMG_FIX — OG images must be absolute URLs
          var _img = String(st.avatar_url);
          if (/^https?:\/\//i.test(_img)){
            ogImage = _img;
          } else if (_img.charAt(0) === '/'){
            ogImage = baseUrl + _img;
          } else {
            ogImage = baseUrl + '/' + _img;
          }
        }
      }
    } catch(_){}

    // Inject OG meta tags right before </head>
    const ogBlock = '<!-- GISTAPP_LIVE_SHARE_V1 -->\n' +
      '<meta property="og:type" content="video.other">\n' +
      '<meta property="og:site_name" content="GistApp">\n' +
      '<meta property="og:title" content="' + _escapeHTML(ogTitle) + '">\n' +
      '<meta property="og:description" content="' + _escapeHTML(ogDesc) + '">\n' +
      '<meta property="og:image" content="' + _escapeHTML(ogImage) + '">\n' +
      '<meta property="og:url" content="' + _escapeHTML(ogUrl) + '">\n' +
      '<meta name="twitter:card" content="summary_large_image">\n' +
      '<meta name="twitter:title" content="' + _escapeHTML(ogTitle) + '">\n' +
      '<meta name="twitter:description" content="' + _escapeHTML(ogDesc) + '">\n' +
      '<meta name="twitter:image" content="' + _escapeHTML(ogImage) + '">\n';

    // Strip existing og tags from the static head to avoid dupes, then inject
    html = html.replace(/<meta property="og:[^>]+>\s*/g, '');
    html = html.replace(/<meta name="twitter:[^>]+>\s*/g, '');
    html = html.replace('</head>', ogBlock + '</head>');

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch(e){
    console.error('live share route:', e.message);
    res.sendFile(path_share.join(__dirname, 'public', 'index.html'));
  }
});

/* ---------- helpers ---------- */
// GISTAPP_AUTH_HARDENING — block unverified users from writes
async function auth(req,res,next){
  const h = req.headers.authorization||'';
  const token = h.startsWith('Bearer ')?h.slice(7):null;
  if (!token) return res.status(401).json({error:'No token'});
  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); }
  catch { return res.status(401).json({error:'Invalid token'}); }


  // GISTAPP_AUTH_SESSION — reject tokens from old sessions
  try {
    if (payload && payload.id){
      let cached = _sessionCacheGet(payload.id);
      if (cached === null){
        const sr = await pool.query('SELECT session_id FROM users WHERE id=$1', [payload.id]);
        if (!sr.rowCount) return res.status(401).json({ error: 'User not found' });
        cached = sr.rows[0].session_id || null;
        if (cached) _sessionCacheSet(payload.id, cached);
      }
      // If DB has a session_id and it doesn't match → user logged in elsewhere
      if (cached && payload.session_id && String(cached) !== String(payload.session_id)){
        return res.status(401).json({ error: 'Logged in on another device', code: 'SESSION_REPLACED' });
      }
    }
  } catch(sessErr){
    console.warn('session check error:', sessErr.message);
  }

  // Trust the JWT fast path if it says verified or has google_id
  let isVerified = payload.verified === true || !!payload.google_id;

  if (!isVerified){
    // Slow path — check DB (handles legacy tokens issued before hardening)
    try {
      const r = await pool.query('SELECT verified, google_id FROM users WHERE id=$1', [payload.id]);
      if (!r.rowCount) return res.status(401).json({error:'User not found'});
      const u = r.rows[0];
      isVerified = !!u.verified || !!u.google_id;
    } catch(e){
      // On DB failure, fail-open to avoid locking users out during outages
      console.warn('auth verify check failed:', e.message);
      isVerified = true;
    }
  }

  // Block non-GET requests for unverified users
  if (!isVerified && req.method !== 'GET'){
    return res.status(403).json({ error: 'Verify your email first', needsVerification: true });
  }

  req.user = payload;
  req.user.verified = isVerified;
  next();
}
// GISTAPP_SIGNUP_HARDENING — carry verified + google_id in JWT
/* GISTAPP_SINGLE_DEVICE — one active session per user */
const _sessionCache = new Map(); // userId -> { sid, exp }
function _sessionCacheSet(uid, sid){
  _sessionCache.set(Number(uid), { sid: sid, exp: Date.now() + 15000 });
}
function _sessionCacheGet(uid){
  const e = _sessionCache.get(Number(uid));
  if (!e) return null;
  if (Date.now() > e.exp){ _sessionCache.delete(Number(uid)); return null; }
  return e.sid;
}

async function rotateUserSession(userId){
  const crypto = require('crypto');
  const sid = crypto.randomBytes(16).toString('hex');
  await pool.query('UPDATE users SET session_id=$1, session_started_at=NOW() WHERE id=$2', [sid, userId]);
  _sessionCacheSet(userId, sid);
  return sid;
}

const sign = u => jwt.sign({
  id: u.id,
  email: u.email,
  verified: !!u.verified,
  google_id: u.google_id || null,
  subscription_tier: u.subscription_tier || 'free',
  session_id: u.session_id || null
}, JWT_SECRET, {expiresIn:'30d'});

async function isMember(chatId,userId){ const r = await pool.query('SELECT status,is_admin,muted,archived,favorite FROM chat_members WHERE chat_id=$1 AND user_id=$2',[chatId,userId]); return r.rows[0]; }
async function isAdmin(chatId,userId){ const r = await pool.query("SELECT is_admin FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND is_admin=true",[chatId,userId]); return r.rowCount>0; }

/* ---------- google social login ---------- */
app.post('/api/auth/google', async (req,res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'Missing credential' });
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = (payload.email || '').toLowerCase();
    const name  = payload.name || email.split('@')[0];
    const gid   = payload.sub;
    if (!email) return res.status(400).json({ error: 'No email from Google' });
    let user = (await pool.query('SELECT * FROM users WHERE email=$1',[email])).rows[0];
    if (!user){
      const r = await pool.query(
        'INSERT INTO users (email, password_hash, display_name, verified, google_id, onboarded) VALUES ($1,$2,$3,true,$4,false) RETURNING id,email,display_name,avatar_color,dark_mode,font_size,onboarded',
        [email, 'google-oauth', name, gid]
      );
      user = r.rows[0];
    } else {
      await pool.query('UPDATE users SET google_id=$1, verified=true WHERE id=$2', [gid, user.id]);
    }
    await pool.query('UPDATE users SET last_seen_at=NOW() WHERE id=$1',[user.id]);
    // GISTAPP_GOOGLE_SESSION — rotate session on Google login too
    const sid = await rotateUserSession(user.id);
    user.session_id = sid;
    // GISTAPP_LOGIN_SESSION
    // removed duplicate sid
    res.json({
      user: { id: user.id, email: user.email, display_name: user.display_name,
        avatar_color: user.avatar_color, dark_mode: user.dark_mode,
        font_size: user.font_size, onboarded: user.onboarded,
        subscription_tier: user.subscription_tier || 'free' },
      token: sign(user),
      isNew: !user.onboarded
    });
  } catch(e){
    console.error('google auth error:', e.message);
    res.status(401).json({ error: 'Google sign-in failed' });
  }
});

app.post('/api/onboard', auth, async (req,res) => {
  try {
    const { display_name, bio, avatar_url } = req.body;
    const sets=[]; const vals=[]; let i=1;
    if (display_name){ sets.push(`display_name=$${i++}`); vals.push(display_name); }
    if (bio){ sets.push(`bio=$${i++}`); vals.push(bio); }
    if (avatar_url){ sets.push(`avatar_url=$${i++}`); vals.push(avatar_url); }
    sets.push(`onboarded=true`);
    vals.push(req.user.id);
    const r = await pool.query(
      `UPDATE users SET ${sets.join(', ')} WHERE id=$${i} RETURNING id,email,display_name,avatar_color,avatar_url,bio,onboarded`,
      vals
    );
    res.json(r.rows[0]);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- auth ---------- */
app.post('/api/signup', signupLimiter, async (req,res)=>{
  try {
    // GISTAPP_SIGNUP_HARDENING — server-side signup checks
    const { email, password, display_name, terms_accepted, website } = req.body;

    // Honeypot: bots fill hidden fields
    if (website){ return res.status(400).json({ error: 'Signup rejected' }); }

    // Terms must be accepted
    if (!terms_accepted){ return res.status(400).json({ error: 'You must accept the Terms of Service and Privacy Policy' }); }

    if (!email || !password) return res.status(400).json({error:'Email and password required'});

    // Password strength: 8+ chars, letters AND numbers
    const pw = String(password);
    if (pw.length < 8 || !/[a-zA-Z]/.test(pw) || !/[0-9]/.test(pw)){
      return res.status(400).json({ error: 'Password must be 8+ characters with both letters and numbers' });
    }

    // Disposable email block
    const DISPOSABLE = new Set([
      'tempmail.com','tempmail.net','10minutemail.com','10minutemail.net','guerrillamail.com','guerrillamail.net',
      'mailinator.com','trashmail.com','yopmail.com','yopmail.fr','throwawaymail.com','sharklasers.com',
      'temp-mail.org','temp-mail.io','fakeinbox.com','maildrop.cc','dispostable.com','mintemail.com',
      'mohmal.com','mytrashmail.com','spam4.me','spambox.us','getnada.com','guerrillamail.org',
      'mailnesia.com','mailcatch.com','inboxbear.com','throwaway.email','tempinbox.com','harakirimail.com',
      'mailmetrash.com','thankyou2010.com','mt2009.com','trash2009.com','trashymail.com','tyldd.com',
      'uggsrock.com','wegwerfmail.de','wegwerfmail.net','wegwerfmail.org','spam.la','binkmail.com',
      'bobmail.info','chammy.info','devnullmail.com','letthemeatspam.com','mail-temporaire.fr',
      'mail.mezimages.net','mailzilla.com','mbx.cc','mega.zik.dj','meltmail.com','messagebeamer.de'
    ]);
    const emailDomain = String(email).toLowerCase().split('@')[1] || '';
    if (DISPOSABLE.has(emailDomain)){ return res.status(400).json({ error: 'Please use a permanent email address (disposable emails not allowed)' }); }

    // Phone-number-as-email block (some spam patterns)
    if (/^\d{6,}@/.test(email)){ return res.status(400).json({ error: 'Invalid email format' }); }

    const exists = await pool.query('SELECT id FROM users WHERE email=$1',[email.toLowerCase()]);
    if (exists.rowCount) return res.status(409).json({error:'Email already registered'});
    const hash = await bcrypt.hash(password,10);
    const name = display_name || email.split('@')[0];
    const vtoken = makeToken();
    const vexpires = new Date(Date.now() + 24 * 3600 * 1000);
    const r = await pool.query(
      'INSERT INTO users (email,password_hash,display_name,verified,verify_token,verify_expires) VALUES ($1,$2,$3,false,$4,$5) RETURNING id,email,display_name,avatar_color,dark_mode,font_size',
      [email.toLowerCase(), hash, name, vtoken, vexpires]
    );
    // GISTAPP_SIGNUP_SID_FIX — rotate session for new user
    const sid = await rotateUserSession(r.rows[0].id);
    const userWithSid = Object.assign({}, r.rows[0], { session_id: sid });
    res.json({
      user: userWithSid,
      token: sign(userWithSid),
      needsVerification: true,
      emailSent: true,
      emailError: null
    });

    // Send the email in the background (fire-and-forget)
    sendVerificationEmail(email.toLowerCase(), vtoken, name)
      .then(() => console.log('✅ Verification email sent to', email.toLowerCase()))
      .catch(mailErr => console.error('❌ Email send failed:', mailErr.message));
  } catch(e){ console.error(e); res.status(500).json({error:'Server error'}); }
});
app.post('/api/login', loginLimiter, async (req,res)=>{
  try {
    const { email, password } = req.body;
    const r = await pool.query('SELECT * FROM users WHERE email=$1',[email.toLowerCase()]);
    if (!r.rowCount) return res.status(401).json({error:'Invalid credentials'});
    const user = r.rows[0];
    if (!await bcrypt.compare(password,user.password_hash)) return res.status(401).json({error:'Invalid credentials'});
    if (user.verified === false) {
      return res.status(403).json({
        error: 'Please verify your email first — check your inbox for the link.',
        needsVerification: true
      });
    }
    await pool.query('UPDATE users SET last_seen_at=NOW() WHERE id=$1',[user.id]);
    // GISTAPP_SINGLE_DEVICE
      const sid = await rotateUserSession(user.id);
      user.session_id = sid;
      res.json({
      user: {
        id: user.id, email: user.email, display_name: user.display_name,
        avatar_color: user.avatar_color, dark_mode: user.dark_mode, font_size: user.font_size
      },
      token: sign(user)
    });
  } catch(e){ console.error(e); res.status(500).json({error:'Server error'}); }
});
app.get('/api/me', auth, async (req,res)=>{
  const r = await pool.query('SELECT id,email,display_name,username,avatar_color,dark_mode,font_size,blocked_ids,prefs,avatar_url,cover_url,bio,totp_enabled,onboarded,onboard_stage,birthday,interests,follows,joined_communities,permissions,pin_hash,app_lock_enabled,app_lock_timeout_min,chat_lock_enabled,locked_chats, subscription_tier, subscription_status, subscription_ends_at, is_admin FROM users /* GISTAPP_ME_TIER */ /* GISTAPP_ADMIN_FLAG */ WHERE id=$1',[req.user.id]);
  res.json(r.rows[0]);
});
app.patch('/api/me', auth, async (req,res)=>{
  const { display_name, avatar_color, dark_mode, font_size, dnd_until, prefs, avatar_url, cover_url, bio, gender } = req.body;
  const sets=[],vals=[]; let i=1;
  if (display_name!==undefined){sets.push(`display_name=$${i++}`);vals.push(display_name);}
  if (avatar_color!==undefined){sets.push(`avatar_color=$${i++}`);vals.push(avatar_color);}
  if (dark_mode!==undefined){sets.push(`dark_mode=$${i++}`);vals.push(!!dark_mode);}
  if (font_size!==undefined){sets.push(`font_size=$${i++}`);vals.push(font_size);}
  if (dnd_until!==undefined){sets.push(`dnd_until=$${i++}`);vals.push(dnd_until);}
  if (avatar_url!==undefined){sets.push(`avatar_url=$${i++}`);vals.push(avatar_url);}
  if (cover_url!==undefined){sets.push(`cover_url=$${i++}`);vals.push(cover_url);}
  if (bio!==undefined){sets.push(`bio=$${i++}`);vals.push(bio);}
  if (gender!==undefined){sets.push(`gender=$${i++}`);vals.push(gender);}
  if (prefs!==undefined){
    const existing = await pool.query('SELECT prefs FROM users WHERE id=$1',[req.user.id]);
    const merged = Object.assign({}, existing.rows[0].prefs||{}, prefs);
    sets.push(`prefs=$${i++}`); vals.push(merged);
  }
  if (!sets.length) return res.json({ok:true});
  vals.push(req.user.id);
  const r = await pool.query(`UPDATE users SET ${sets.join(', ')} WHERE id=$${i} RETURNING id,email,display_name,avatar_color,dark_mode,font_size,dnd_until,prefs,avatar_url,cover_url,bio`,[...vals]);
  // Notify all connected clients that this user's profile changed
  try { io.emit('user-updated', { userId: req.user.id }); } catch(_) {}
  res.json(r.rows[0]);
});

/* ---------- USERNAME + ONBOARDING ---------- */
app.get('/api/username/suggest', auth, async (req, res) => {
  try {
    const base = (req.query.base || 'user').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 15) || 'user';
    const suggestions = [];
    let attempts = 0;
    while (suggestions.length < 5 && attempts < 40){
      attempts++;
      let candidate;
      const r = Math.random();
      if (r < 0.33) candidate = base + Math.floor(Math.random() * 9000 + 1000);
      else if (r < 0.66) candidate = base + '_' + Math.floor(Math.random() * 900 + 100);
      else candidate = base + Math.floor(Math.random() * 99 + 1);
      const exists = await pool.query('SELECT 1 FROM users WHERE LOWER(username)=$1', [candidate]);
      if (!exists.rowCount && !suggestions.includes(candidate)) suggestions.push(candidate);
    }
    res.json({ base, suggestions });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/username/set', auth, async (req, res) => {
  try {
    const u = String(req.body.username || '').trim().toLowerCase();
    if (!/^[a-z0-9_]{3,20}$/.test(u)) return res.status(400).json({ error: '3-20 chars, a-z, 0-9, _ only' });
    const taken = await pool.query('SELECT 1 FROM users WHERE LOWER(username)=$1 AND id<>$2', [u, req.user.id]);
    if (taken.rowCount) return res.status(409).json({ error: 'Username already taken' });
    await pool.query('UPDATE users SET username=$1 WHERE id=$2', [u, req.user.id]);
    res.json({ ok: true, username: u });
  } catch(e){ console.error('username error:', e.message); res.status(500).json({ error: e.message || 'Server error' }); }
});

// GISTAPP_ONBOARD_FIX_V1
app.post('/api/onboard/profile', auth, async (req, res) => {
  try {
    const { display_name, bio, avatar_url, birthday, gender, password } = req.body;
    const sets = [];
    const vals = [];
    let i = 1;

    const push = (col, val) => { sets.push(col + '=$' + (i++)); vals.push(val); };

    if (display_name && String(display_name).trim()) push('display_name', String(display_name).trim());
    if (bio && String(bio).trim()) push('bio', String(bio).trim());
    if (avatar_url) push('avatar_url', avatar_url);
    if (gender) push('gender', gender);

    if (birthday){
      const dob = new Date(birthday);
      const age = Math.floor((Date.now() - dob.getTime()) / (365.25 * 24 * 3600 * 1000));
      if (isNaN(age)) return res.status(400).json({ error: 'Invalid birthday' });
      if (age < 18) return res.status(403).json({ error: 'You must be at least 18' });
      push('birthday', birthday);
    }

    if (password && String(password).length >= 6){
      const hash = await bcrypt.hash(String(password), 10);
      push('password_hash', hash);
    }

    // Always bump onboard_stage — COALESCE handles NULL properly
    sets.push('onboard_stage=GREATEST(COALESCE(onboard_stage, 0), 1)');

    // Where clause
    vals.push(req.user.id);
    const whereClause = ' WHERE id=$' + i;

    // Safety: ensure we have at least one SET
    if (sets.length === 0){
      return res.status(400).json({ error: 'No fields to update' });
    }

    const sql = 'UPDATE users SET ' + sets.join(', ') + whereClause +
      ' RETURNING id,email,display_name,username,avatar_color,avatar_url,bio,birthday,gender,onboard_stage';

    try {
      const r = await pool.query(sql, vals);
      if (!r.rowCount) return res.status(404).json({ error: 'User not found' });
      res.json(r.rows[0]);
    } catch (dbErr){
      console.error('onboard profile DB error:', {
        msg: dbErr && dbErr.message,
        code: dbErr && dbErr.code,
        detail: dbErr && dbErr.detail,
        hint: dbErr && dbErr.hint,
        sql: sql,
        vals: vals.map(v => typeof v === 'string' ? v.slice(0, 60) : v)
      });
      return res.status(500).json({ error: (dbErr && (dbErr.message || dbErr.detail)) || 'DB error' });
    }
  } catch(e){
    console.error('onboard profile OUTER error:', e && e.message, e && e.stack ? e.stack.split('\n')[1] : '');
    res.status(500).json({ error: (e && e.message) || 'Server error' });
  }
});

app.post('/api/onboard/interests', auth, async (req, res) => {
  try {
    const list = (req.body.interests || []).slice(0, 20).map(String);
    const r = await pool.query('UPDATE users SET interests=$1::jsonb, onboard_stage=GREATEST(onboard_stage, 2) WHERE id=$2 RETURNING interests, onboard_stage', [JSON.stringify(list), req.user.id]);
    res.json(r.rows[0]);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/onboard/picks', auth, async (req, res) => {
  try {
    const follows = (req.body.follows || []).slice(0, 50).map(String);
    const joined = (req.body.joined_communities || []).slice(0, 50).map(String);
    const r = await pool.query('UPDATE users SET follows=$1::jsonb, joined_communities=$2::jsonb, onboard_stage=GREATEST(onboard_stage, 3) WHERE id=$3 RETURNING follows, joined_communities, onboard_stage', [JSON.stringify(follows), JSON.stringify(joined), req.user.id]);
    res.json(r.rows[0]);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/onboard/permissions', auth, async (req, res) => {
  try {
    const perms = {
      notifications: !!(req.body.permissions && req.body.permissions.notifications),
      find_friends: !!(req.body.permissions && req.body.permissions.find_friends)
    };
    const r = await pool.query('UPDATE users SET permissions=$1::jsonb, onboard_stage=4, onboarded=true WHERE id=$2 RETURNING permissions, onboard_stage, onboarded', [JSON.stringify(perms), req.user.id]);
    res.json(r.rows[0]);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- chats list ---------- */

async function isBlockedBetween(aId, bId){
  try {
    const r = await pool.query(
      'SELECT blocked_ids FROM users WHERE id=$1',
      [aId]
    );
    let list = (r.rows[0] && r.rows[0].blocked_ids); if (!Array.isArray(list)) list = [];
    return list.map(Number).includes(Number(bId));
  } catch(_){ return false; }
}

/* ---------- avatar visibility ---------- */
/* Generic visibility check — used for bio, status, last_seen, groups */
async function canViewField(viewerId, ownerId, prefKey){
  if (Number(viewerId) === Number(ownerId)) return true;
  try {
    const r = await pool.query('SELECT prefs FROM users WHERE id=$1', [ownerId]);
    if (!r.rowCount) return false;
    const vis = (r.rows[0].prefs && r.rows[0].prefs[prefKey]) || 'Everyone';
    if (vis === 'Everyone') return true;
    if (vis === 'Nobody') return false;
    if (vis === 'My contacts'){
      const c = await pool.query(`
        SELECT 1 FROM chats ch
        JOIN chat_members a ON a.chat_id=ch.id AND a.user_id=$1
        JOIN chat_members b ON b.chat_id=ch.id AND b.user_id=$2
        WHERE ch.type='dm' LIMIT 1
      `, [ownerId, viewerId]);
      return c.rowCount > 0;
    }
    return false;
  } catch(_){ return false; }
}

async function canViewPhoto(viewerId, ownerId){
  if (Number(viewerId) === Number(ownerId)) return true;
  try {
    const r = await pool.query('SELECT prefs, avatar_url FROM users WHERE id=$1',[ownerId]);
    if (!r.rowCount) return false;
    const owner = r.rows[0];
    if (!owner.avatar_url) return false;
    const vis = (owner.prefs && owner.prefs.profile_photo) || 'Everyone';
    if (vis === 'Everyone') return true;
    if (vis === 'Nobody')   return false;
    if (vis === 'My contacts'){
      const c = await pool.query(`
        SELECT 1 FROM chats ch
        JOIN chat_members a ON a.chat_id=ch.id AND a.user_id=$1
        JOIN chat_members b ON b.chat_id=ch.id AND b.user_id=$2
        WHERE ch.type='dm' LIMIT 1
      `,[ownerId,viewerId]);
      return c.rowCount > 0;
    }
    return false;
  } catch(_){ return false; }
}

app.get('/api/chats', auth, async (req,res)=>{
  const r = await pool.query(`
    SELECT c.id,c.type,c.name,c.description,c.icon_emoji,
      m.status AS my_status, m.muted, m.archived, m.favorite,
      (SELECT body FROM messages WHERE chat_id=c.id AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1) AS last_message,
      (SELECT created_at FROM messages WHERE chat_id=c.id AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1) AS last_at,
      (SELECT COUNT(*) FROM messages WHERE chat_id=c.id AND sender_id<>$1 AND deleted_at IS NULL AND created_at > COALESCE(m.last_read_at,'1970-01-01')) AS unread,
      o.id AS other_id, o.display_name AS other_name, o.email AS other_email, o.avatar_color AS other_color, o.subscription_tier AS other_tier,
      o.avatar_url   AS other_url,
      o.last_seen_at AS other_last_seen,
      om.status AS other_status,
      (SELECT COUNT(*) FROM chat_members WHERE chat_id=c.id) AS member_count
    FROM chats c
    JOIN chat_members m ON m.chat_id=c.id AND m.user_id=$1 AND m.status='accepted'
    LEFT JOIN chat_members om ON om.chat_id=c.id AND om.user_id<>$1 AND c.type='dm'
    LEFT JOIN users o ON o.id=om.user_id
    ORDER BY m.favorite DESC, m.archived ASC, COALESCE(
      (SELECT created_at FROM messages WHERE chat_id=c.id ORDER BY created_at DESC LIMIT 1), c.created_at) DESC
  `,[req.user.id]);

  // Enforce visibility prefs per chat
  const rows = await Promise.all(r.rows.map(async c => {
    if (c.other_id){
      if (c.other_url){
        const ok = await canViewPhoto(req.user.id, c.other_id);
        if (!ok) c.other_url = null;
      }
      if (c.other_last_seen){
        const ok = await canViewField(req.user.id, c.other_id, 'last_seen');
        if (!ok) c.other_last_seen = null;
      }
    }
    return c;
  }));
  // GISTAPP_LIVE_BADGE_BE
      try {
        const liveIds = await getLiveUserIds();
        r.rows.forEach(function(c){ c.other_is_live = liveIds.has(Number(c.other_id)); });
      } catch(_){}
      res.json(rows);
});

/* ---------- requests ---------- */
app.get('/api/requests', auth, async (req,res)=>{
  const r = await pool.query(`
    SELECT c.id AS chat_id, c.type, c.name, u.id AS user_id, u.display_name, u.email, u.avatar_color, u.avatar_url, c.created_at
    FROM chats c
    JOIN chat_members m ON m.chat_id=c.id AND m.user_id=$1 AND m.status='pending'
    LEFT JOIN chat_members om ON om.chat_id=c.id AND om.user_id<>$1
    LEFT JOIN users u ON u.id=om.user_id
    ORDER BY c.created_at DESC
  `,[req.user.id]);
  const rows = await Promise.all(r.rows.map(async x => {
    if (x.avatar_url && x.user_id){
      const ok = await canViewPhoto(req.user.id, x.user_id);
      if (!ok) x.avatar_url = null;
    }
    return x;
  }));
  res.json(rows);
});
app.post('/api/requests/:id/accept', auth, async (req,res)=>{
  const chatId = Number(req.params.id);
  const r = await pool.query("UPDATE chat_members SET status='accepted', last_read_at=NOW() WHERE chat_id=$1 AND user_id=$2 AND status='pending' RETURNING chat_id",[chatId,req.user.id]);
  if (!r.rowCount) return res.status(404).json({error:'No pending request'});
  const others = await pool.query('SELECT user_id FROM chat_members WHERE chat_id=$1 AND user_id<>$2',[chatId,req.user.id]);
  others.rows.forEach(row=>io.to('user:'+row.user_id).emit('chats-changed'));
  res.json({ok:true});
});
app.post('/api/requests/:id/decline', auth, async (req,res)=>{
  const chatId = Number(req.params.id);
  const r = await pool.query("SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='pending'",[chatId,req.user.id]);
  if (!r.rowCount) return res.status(404).json({error:'No pending request'});
  await pool.query('DELETE FROM chats WHERE id=$1',[chatId]);
  res.json({ok:true});
});

/* ---------- start DM / group ---------- */
app.post('/api/chats/dm', auth, async (req,res)=>{
  const { email } = req.body;
  const other = await pool.query('SELECT id FROM users WHERE email=$1',[String(email||'').toLowerCase()]);
  if (!other.rowCount) return res.status(404).json({error:'User not found'});
  const otherId = other.rows[0].id;
  if (otherId === req.user.id) return res.status(400).json({error:'Cannot chat with yourself'});
  const existing = await pool.query(`SELECT c.id, a.status AS my_status FROM chats c JOIN chat_members a ON a.chat_id=c.id AND a.user_id=$1 JOIN chat_members b ON b.chat_id=c.id AND b.user_id=$2 WHERE c.type='dm' LIMIT 1`,[req.user.id,otherId]);
  if (existing.rowCount){
    const row = existing.rows[0];
    if (row.my_status==='pending'){
      await pool.query("UPDATE chat_members SET status='accepted', last_read_at=NOW() WHERE chat_id=$1 AND user_id=$2",[row.id,req.user.id]);
      io.to('user:'+otherId).emit('chats-changed');
    }
    return res.json({chat_id:row.id});
  }
  const chat = await pool.query("INSERT INTO chats (type) VALUES ('dm') RETURNING id");
  const chatId = chat.rows[0].id;
  await pool.query("INSERT INTO chat_members (chat_id,user_id,status) VALUES ($1,$2,'accepted'),($1,$3,'pending')",[chatId,req.user.id,otherId]);
  io.to('user:'+otherId).emit('requests-changed');
  res.json({chat_id:chatId});
});
app.post('/api/chats/group', auth, async (req,res)=>{
  const { name, emails } = req.body;
  if (!name||!name.trim()) return res.status(400).json({error:'Group name required'});
  const list = (emails||[]).map(e=>String(e).trim().toLowerCase()).filter(Boolean);
  if (!list.length) return res.status(400).json({error:'Add at least one member'});
  const users = await pool.query('SELECT id,email FROM users WHERE email = ANY($1)',[list]);
  if (users.rowCount !== list.length){
    const found = users.rows.map(r=>r.email);
    return res.status(404).json({error:'Not registered: '+list.filter(e=>!found.includes(e)).join(', ')});
  }
  const chat = await pool.query("INSERT INTO chats (type,name) VALUES ('group',$1) RETURNING id",[name.trim()]);
  const chatId = chat.rows[0].id;
  await pool.query("INSERT INTO chat_members (chat_id,user_id,status,last_read_at,is_admin) VALUES ($1,$2,'accepted',NOW(),true)",[chatId,req.user.id]);
  for (const u of users.rows){
    await pool.query("INSERT INTO chat_members (chat_id,user_id,status) VALUES ($1,$2,'pending')",[chatId,u.id]);
    io.to('user:'+u.id).emit('requests-changed');
  }
  res.json({chat_id:chatId});
});
app.post('/api/chats/:id/members', auth, async (req,res)=>{
  const chatId = Number(req.params.id);
  if (!await isMember(chatId,req.user.id)) return res.status(403).json({error:'Not a member'});
  const u = await pool.query('SELECT id FROM users WHERE email=$1',[String(req.body.email||'').toLowerCase()]);
  if (!u.rowCount) return res.status(404).json({error:'User not found'});
  await pool.query("INSERT INTO chat_members (chat_id,user_id,status) VALUES ($1,$2,'pending') ON CONFLICT DO NOTHING",[chatId,u.rows[0].id]);
  io.to('user:'+u.rows[0].id).emit('requests-changed');
  res.json({ok:true});
});

/* ---------- chat settings ---------- */
app.patch('/api/chats/:id', auth, async (req,res)=>{
  const chatId = Number(req.params.id);
  const m = await isMember(chatId,req.user.id);
  if (!m) return res.status(403).json({error:'Not a member'});
  const { name, description, icon_emoji, muted, archived, favorite } = req.body;
  if ((name!==undefined||description!==undefined||icon_emoji!==undefined) && m.status==='accepted'){
    const sets=[],vals=[];let i=1;
    if (name!==undefined){sets.push(`name=$${i++}`);vals.push(name);}
    if (description!==undefined){sets.push(`description=$${i++}`);vals.push(description);}
    if (icon_emoji!==undefined){sets.push(`icon_emoji=$${i++}`);vals.push(icon_emoji);}
    if (sets.length){ vals.push(chatId); await pool.query(`UPDATE chats SET ${sets.join(', ')} WHERE id=$${i}`,[...vals]); }
  }
  const msets=[],mvals=[];let j=1;
  if (muted!==undefined){msets.push(`muted=$${j++}`);mvals.push(!!muted);}
  if (req.body.pinned!==undefined){msets.push(`pinned=$${j++}`);mvals.push(!!req.body.pinned);}
  if (req.body.unread!==undefined){msets.push(`unread=$${j++}`);mvals.push(!!req.body.unread);}
  if (archived!==undefined){msets.push(`archived=$${j++}`);mvals.push(!!archived);}
  if (favorite!==undefined){msets.push(`favorite=$${j++}`);mvals.push(!!favorite);}
  if (msets.length){ mvals.push(chatId); mvals.push(req.user.id); await pool.query(`UPDATE chat_members SET ${msets.join(', ')} WHERE chat_id=$${j} AND user_id=$${j+1}`,[...mvals]); }
  res.json({ok:true});
});

/* ---------- delete chat ---------- */
app.delete('/api/chats/:id', auth, async (req,res)=>{
  const chatId = Number(req.params.id);
  if (!await isMember(chatId,req.user.id)) return res.status(403).json({error:'Not a member'});
  await pool.query('DELETE FROM chat_members WHERE chat_id=$1 AND user_id=$2',[chatId,req.user.id]);
  res.json({ok:true});
});

/* ---------- messages ---------- */
app.get('/api/chats/:id/messages', auth, async (req,res)=>{
  const chatId = req.params.id;
  const q = (req.query.q||'').trim();
  const filter = req.query.filter || '';
  const before = req.query.before;
  const limit = Math.min(Number(req.query.limit) || 50, 100);

  const m = await isMember(chatId,req.user.id);
  if (!m) return res.status(403).json({error:'Not a member'});
  if (m.status !== 'accepted') return res.status(403).json({error:'Chat not accepted yet'});

  const params = [chatId];
  let where = 'WHERE m.chat_id=$1 AND m.deleted_at IS NULL';
  if (before){ params.push(before); where += ` AND m.id < $${params.length}`; }
  if (q){ params.push('%'+q.toLowerCase()+'%'); where += ` AND LOWER(m.body) LIKE $${params.length}`; }
  if (filter==='media') where += ' AND m.media_url IS NOT NULL';
  if (filter==='starred'){ params.push(req.user.id); where += ` AND m.starred_by ? $${params.length}`; }
  if (filter==='links') where += ` AND m.body ~* 'https?://'`;
  params.push(limit);

  const r = await pool.query(`
    SELECT m.id, m.body, m.created_at, m.edited_at, m.sender_id, m.reactions, m.read_at,
           m.media_url, m.media_type, m.deleted_at, m.starred_by, m.pinned, m.reply_to_id,
           u.display_name, u.avatar_color, u.avatar_url, u.subscription_tier AS sender_tier, u.subscription_tier AS author_tier,
           rp.body AS reply_body,
           rp.sender_id AS reply_sender_id,
           ru.display_name AS reply_sender
    FROM messages m
    JOIN users u ON u.id = m.sender_id
    LEFT JOIN messages rp ON rp.id = m.reply_to_id
    LEFT JOIN users   ru ON ru.id = rp.sender_id
    ${where}
    ORDER BY m.pinned DESC, m.created_at DESC
    LIMIT $${params.length}
  `, params);

  const blockRow = await pool.query('SELECT blocked_ids FROM users WHERE id=$1',[req.user.id]);
  const myBlockSet = new Set(((blockRow.rows[0]||{}).blocked_ids || []).map(Number));

  let rows = r.rows.filter(x => !myBlockSet.has(Number(x.sender_id)));

  // single bulk avatar-visibility check (not per-message)
  const senderIds = [...new Set(rows.map(x => x.sender_id).filter(x => x !== req.user.id))];
  const visible = new Set();
  for (const sid of senderIds){
    try { if (await canViewPhoto(req.user.id, sid)) visible.add(sid); } catch(_){}
  }
  for (const x of rows){
    if (x.avatar_url && x.sender_id !== req.user.id && !visible.has(x.sender_id)) x.avatar_url = null;
  }

  // UI expects oldest -> newest at the bottom of the list
  rows.reverse();
  res.json(rows);
});

app.post('/api/chats/:id/messages', auth, async (req,res)=>{
  const chatId = req.params.id;
  const { body, media_url, media_type, reply_to_id } = req.body;
  const text = (body||'').trim();
  if (!text && !media_url) return res.status(400).json({error:'Empty message'});
  const m = await isMember(chatId,req.user.id);
  if (!m) return res.status(403).json({error:'Not a member'});
  if (m.status!=='accepted') return res.status(403).json({error:'Chat not accepted yet'});

  // block enforcement
  const other = await pool.query('SELECT user_id FROM chat_members WHERE chat_id=$1 AND user_id<>$2 LIMIT 1', [chatId, req.user.id]);
  if (other.rowCount){
    const them = other.rows[0].user_id;
    if (await isBlockedBetween(them, req.user.id)){
      return res.status(403).json({ error: 'You cannot message this user' });
    }
  }

  let row;
  if (text && !reply_to_id){
    const dup = await pool.query("SELECT id,body,created_at,sender_id,reactions,read_at,media_url,media_type,reply_to_id,edited_at,starred_by,pinned FROM messages WHERE chat_id=$1 AND sender_id=$2 AND body=$3 AND deleted_at IS NULL AND created_at > NOW() - INTERVAL '3 seconds' ORDER BY created_at DESC LIMIT 1",[chatId,req.user.id,text]);
    if (dup.rowCount) row = dup.rows[0];
  }
  if (!row){
    // disappearing messages: look up user's preference
    const mePrefsRow = await pool.query('SELECT prefs FROM users WHERE id=$1',[req.user.id]);
    const prefs = (mePrefsRow.rows[0] && mePrefsRow.rows[0].prefs) || {};
    const disp = prefs.disappearing || 'Off';
    let expiresAt = null;
    if (disp === '24 hours') expiresAt = new Date(Date.now() + 24*3600*1000);
    else if (disp === '7 days') expiresAt = new Date(Date.now() + 7*24*3600*1000);
    else if (disp === '90 days') expiresAt = new Date(Date.now() + 90*24*3600*1000);

    const r = await pool.query(
      'INSERT INTO messages (chat_id,sender_id,body,media_url,media_type,reply_to_id,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id,body,created_at,sender_id,reactions,read_at,media_url,media_type,reply_to_id,edited_at,starred_by,pinned,expires_at',
      [chatId,req.user.id,text,media_url||null,media_type||null,reply_to_id||null,expiresAt]
    );
    row = r.rows[0];
  }
  const me = await pool.query('SELECT display_name,avatar_color,avatar_url FROM users WHERE id=$1',[req.user.id]);
  const full = {...row, display_name:me.rows[0].display_name, avatar_color:me.rows[0].avatar_color, avatar_url:me.rows[0].avatar_url, chat_id:chatId};
  if (reply_to_id){
    const rp = await pool.query('SELECT body,sender_id,(SELECT display_name FROM users WHERE id=messages.sender_id) AS sender FROM messages WHERE id=$1',[reply_to_id]);
    if (rp.rowCount){ full.reply_body = rp.rows[0].body; full.reply_sender = rp.rows[0].sender; full.reply_sender_id = rp.rows[0].sender_id; }
  }
  io.to('chat:'+chatId).emit('message', full);
  // GISTAPP_MSG_EMAIL_HOOK — offline DM email notification (throttled 1/hr)
  try {
    (async function(){
      try {
        var _ci = await pool.query("SELECT type, name FROM chats WHERE id=$1", [chatId]);
        var _type = _ci.rows[0] ? _ci.rows[0].type : null;
        if (_type === 'dm'){
          var _others = await pool.query(
            "SELECT cm.user_id, u.email, u.display_name, u.prefs FROM chat_members cm JOIN users u ON u.id=cm.user_id WHERE cm.chat_id=$1 AND cm.user_id<>$2",
            [chatId, req.user.id]
          );
          for (var _i = 0; _i < _others.rows.length; _i++){
            var _r = _others.rows[_i];
            if (!_r.email) continue;
            var _on = onlineUsers.has(_r.user_id) && (onlineUsers.get(_r.user_id) || 0) > 0;
            if (_on) continue;
            var _pf = _r.prefs || {};
            if (_pf.message_emails === 'false') continue;
            var _last = _msgEmailLastSent.get(_r.user_id) || 0;
            if (Date.now() - _last < 60 * 60 * 1000) continue;
            _msgEmailLastSent.set(_r.user_id, Date.now());
            var _snip = String(full.body || (full.media_url ? '[media]' : '') || '(no text)');
            var _sn = full.display_name || 'Someone';
            sendMessageNotificationEmail(_r.email, _r.display_name, {
              sender_name: _sn, snippet: _snip, chat_id: chatId
            }).catch(function(){});
          }
        }
      } catch(_e){ console.warn('msg email hook:', _e && _e.message); }
    })();
  } catch(_){}
  // GISTAPP_WEBPUSH_V1 — notify other chat members
  try {
    const members = await pool.query('SELECT user_id FROM chat_members WHERE chat_id=$1 AND user_id<>$2', [chatId, req.user.id]);
    const senderName = (full.display_name || 'Someone');
    const preview = text ? text.slice(0, 100) : (media_type === 'image' ? '📷 Photo' : media_type === 'video' ? '🎥 Video' : media_type === 'audio' ? '🎙️ Voice message' : 'Sent a message');
    for (const m of members.rows){
      sendPush(m.user_id, senderName, preview, { url: '/?chat=' + chatId, tag: 'chat-' + chatId }).catch(()=>{});
    }
  } catch(_){}
  res.json(full);
});

app.patch('/api/messages/:id/edit', auth, async (req,res)=>{
  const id = Number(req.params.id);
  const { body } = req.body;
  const m = await pool.query('SELECT sender_id,chat_id FROM messages WHERE id=$1',[id]);
  if (!m.rowCount) return res.status(404).json({error:'Not found'});
  if (m.rows[0].sender_id !== req.user.id) return res.status(403).json({error:'Not yours'});
  await pool.query('UPDATE messages SET body=$1, edited_at=NOW() WHERE id=$2',[String(body||'').trim(),id]);
  io.to('chat:'+m.rows[0].chat_id).emit('message-edited',{id, body:String(body||'').trim()});
  res.json({ok:true});
});

app.patch('/api/messages/:id/star', auth, async (req,res)=>{
  const id = Number(req.params.id);
  const m = await pool.query('SELECT chat_id,starred_by FROM messages WHERE id=$1',[id]);
  if (!m.rowCount) return res.status(404).json({error:'Not found'});
  if (!await isMember(m.rows[0].chat_id,req.user.id)) return res.status(403).json({error:'Not a member'});
  const list = m.rows[0].starred_by || [];
  const has = list.includes(req.user.id);
  const next = has ? list.filter(x=>x!==req.user.id) : [...list, req.user.id];
  await pool.query('UPDATE messages SET starred_by=$1 WHERE id=$2',[next,id]);
  res.json({starred:!has});
});

app.patch('/api/messages/:id/pin', auth, async (req,res)=>{
  const id = Number(req.params.id);
  const m = await pool.query('SELECT chat_id,pinned FROM messages WHERE id=$1',[id]);
  if (!m.rowCount) return res.status(404).json({error:'Not found'});
  if (!await isMember(m.rows[0].chat_id,req.user.id)) return res.status(403).json({error:'Not a member'});
  const next = !m.rows[0].pinned;
  await pool.query('UPDATE messages SET pinned=$1 WHERE id=$2',[next,id]);
  io.to('chat:'+m.rows[0].chat_id).emit('message-pinned',{id, pinned:next});
  res.json({pinned:next});
});

app.patch('/api/messages/:id/react', auth, async (req,res)=>{
  const id = Number(req.params.id);
  const { emoji } = req.body;
  const m = await pool.query('SELECT chat_id,reactions FROM messages WHERE id=$1',[id]);
  if (!m.rowCount) return res.status(404).json({error:'Not found'});
  if (!await isMember(m.rows[0].chat_id,req.user.id)) return res.status(403).json({error:'Not a member'});
  const rx = m.rows[0].reactions || {};
  const arr = Array.isArray(rx[emoji]) ? rx[emoji] : [];
  rx[emoji] = arr.includes(req.user.id) ? arr.filter(x=>x!==req.user.id) : [...arr, req.user.id];
  if (!rx[emoji].length) delete rx[emoji];
  await pool.query('UPDATE messages SET reactions=$1 WHERE id=$2',[rx,id]);
  io.to('chat:'+m.rows[0].chat_id).emit('reaction',{id, reactions:rx});
  res.json({id, reactions:rx});
});

app.delete('/api/messages/:id', auth, async (req,res)=>{
  const id = Number(req.params.id);
  const m = await pool.query('SELECT chat_id,sender_id FROM messages WHERE id=$1',[id]);
  if (!m.rowCount) return res.status(404).json({error:'Not found'});
  if (m.rows[0].sender_id !== req.user.id) return res.status(403).json({error:'Not yours'});
  await pool.query('UPDATE messages SET deleted_at=NOW(), body=NULL, media_url=NULL WHERE id=$1',[id]);
  io.to('chat:'+m.rows[0].chat_id).emit('message-deleted',{id});
  res.json({ok:true});
});

/* ---------- forward ---------- */
app.post('/api/messages/:id/forward', auth, async (req,res)=>{
  const id = Number(req.params.id);
  const { to_chat } = req.body;
  const src = await pool.query('SELECT body,media_url,media_type FROM messages WHERE id=$1',[id]);
  if (!src.rowCount) return res.status(404).json({error:'Not found'});
  if (!await isMember(to_chat,req.user.id)) return res.status(403).json({error:'Not a member of target chat'});
  const r = await pool.query(
    'INSERT INTO messages (chat_id,sender_id,body,media_url,media_type) VALUES ($1,$2,$3,$4,$5) RETURNING id,body,created_at,sender_id,media_url,media_type',
    [to_chat,req.user.id,src.rows[0].body,src.rows[0].media_url,src.rows[0].media_type]
  );
  const me = await pool.query('SELECT display_name,avatar_color,avatar_url FROM users WHERE id=$1',[req.user.id]);
  const full = {...r.rows[0], display_name:me.rows[0].display_name, avatar_color:me.rows[0].avatar_color, chat_id:to_chat};
  io.to('chat:'+to_chat).emit('message',full);
  res.json(full);
});

/* ---------- read ---------- */
app.post('/api/chats/:id/read', auth, async (req,res)=>{
  await pool.query('UPDATE chat_members SET last_read_at=NOW() WHERE chat_id=$1 AND user_id=$2',[req.params.id,req.user.id]);
  await pool.query('UPDATE messages SET read_at=COALESCE(read_at,NOW()) WHERE chat_id=$1 AND sender_id<>$2',[req.params.id,req.user.id]);
  io.to('chat:'+req.params.id).emit('read',{by:req.user.id});
  res.json({ok:true});
});

/* ---------- upload ---------- */
// GISTAPP_FILESTACK_V1
// GISTAPP_UPSTASH_V1
// GISTAPP_UPSTASH_V1
/* ---------- push subscription routes ---------- GISTAPP_WEBPUSH_V1 */
app.get('/api/push/vapid-public', (req, res) => {
  res.json({ publicKey: VAPID_PUBLIC || null, enabled: WEBPUSH_OK });
});

app.post('/api/push/subscribe', auth, async (req, res) => {
  try {
    const { endpoint, keys } = req.body || {};
    if (!endpoint || !keys || !keys.p256dh || !keys.auth){
      return res.status(400).json({ error: 'Invalid subscription' });
    }
    await pool.query(`
      INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (endpoint) DO UPDATE SET user_id=EXCLUDED.user_id, p256dh=EXCLUDED.p256dh, auth=EXCLUDED.auth
    `, [req.user.id, endpoint, keys.p256dh, keys.auth]);
    res.json({ ok: true });
  } catch(e){ console.error('push/subscribe:', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/push/subscribe', auth, async (req, res) => {
  try {
    const { endpoint } = req.body || {};
    if (!endpoint) return res.status(400).json({ error: 'Missing endpoint' });
    await pool.query('DELETE FROM push_subscriptions WHERE endpoint=$1 AND user_id=$2', [endpoint, req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error('push/unsubscribe:', e.message); res.status(500).json({ error: 'Server error' }); }
});

async function sendPush(userId, title, body, data){
  if (!WEBPUSH_OK) return;
  try {
    const r = await pool.query('SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id=$1', [userId]);
    if (!r.rowCount) return;
    const payload = JSON.stringify({ title, body, url: (data && data.url) || '/', tag: (data && data.tag) || 'gistapp' });
    await Promise.all(r.rows.map(async function(row){
      const sub = { endpoint: row.endpoint, keys: { p256dh: row.p256dh, auth: row.auth } };
      try {
        await webpush.sendNotification(sub, payload);
      } catch(err){
        if (err.statusCode === 404 || err.statusCode === 410){
          // Gone — cleanup
          try { await pool.query('DELETE FROM push_subscriptions WHERE endpoint=$1', [row.endpoint]); } catch(_){}
        } else {
          console.warn('push send error:', err.statusCode, err.message);
        }
      }
    }));
  } catch(e){ console.warn('sendPush error:', e.message); }
}

app.post('/api/upload', uploadLimiter, auth, upload.single('file'), async (req,res)=>{
  if (!req.file) return res.status(400).json({error:'No file'});
  const mime = req.file.mimetype || '';
  const type = mime.startsWith('image/') ? 'image'
             : mime.startsWith('video/') ? 'video'
             : mime.startsWith('audio/') ? 'audio'
             : 'file';

  // GISTAPP_UPLOAD_SAFE: 5s Upstash timeout + automatic local fallback
  try {
    const orig = req.file.originalname || '';
    const ext = orig.includes('.') ? orig.split('.').pop().replace(/[^a-zA-Z0-9]/g, '') : 'bin';
    const key = 'gistapp/' + Date.now() + '-' + Math.random().toString(36).slice(2, 8) + '.' + ext;
    const buf = fs.readFileSync(req.file.path);
    console.log('⬆️  Uploading ' + req.file.size + ' bytes as ' + key + ' (' + (mime || 'unknown') + ')');

    let url = null;
    let cloudErr = null;

    // Try Upstash with 5s cap
    try {
      const bucket = getBlobBucket();
      const result = await Promise.race([
        bucket.put(key, buf, { contentType: mime || 'application/octet-stream' }),
        new Promise(function(_, reject){
          setTimeout(function(){ reject(new Error('Upstash timeout after 5s')); }, 5000);
        })
      ]);
      if (result && (result.url || result.downloadUrl)){
        url = result.url || result.downloadUrl;
        console.log('✅ Upstash upload OK:', url);
      } else {
        cloudErr = new Error('Upstash returned no URL');
      }
    } catch(e){
      cloudErr = e;
      console.warn('⚠️  Upstash failed:', (e && e.message) || e);
    }

    // Fallback to local disk if cloud failed
    if (!url){
      const newName = Date.now() + '-' + Math.random().toString(36).slice(2, 8) + (ext ? '.' + ext : '');
      const dest = path.join(__dirname, 'public', 'uploads', newName);
      try {
        fs.renameSync(req.file.path, dest);
      } catch(renameErr){
        try {
          fs.copyFileSync(req.file.path, dest);
          fs.unlinkSync(req.file.path);
        } catch(copyErr){
          console.error('❌ Local fallback failed:', copyErr.message);
          try { fs.unlinkSync(req.file.path); } catch(_){}
          return res.status(500).json({ error: 'Storage unavailable: ' + ((cloudErr && cloudErr.message) || 'unknown') });
        }
      }
      url = '/uploads/' + newName;
      console.warn('⚠️  Fell back to local: ' + url);
    }

    try { fs.unlinkSync(req.file.path); } catch(_){}
    res.json({
      url: url,
      type: type,
      width: null,
      height: null,
      duration: null,
      bytes: req.file.size || null
    });
  } catch(e){
    try { fs.unlinkSync(req.file.path); } catch(_){}
    console.error('❌ Upload top error:', (e && e.message) || e);
    res.status(500).json({ error: 'Upload failed: ' + ((e && e.message) || 'unknown') });
  }
});

/* ---------- change email ---------- GISTAPP_CHANGE_EMAIL_V1 */
app.post('/api/me/request-email-change', auth, async (req, res) => {
  try {
    const newEmail = String((req.body && req.body.new_email) || '').trim().toLowerCase();
    const password = String((req.body && req.body.password) || '');
    if (!newEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)){
      return res.status(400).json({ error: 'Enter a valid email address' });
    }
    if (!password) return res.status(400).json({ error: 'Password required' });

    const me = await pool.query('SELECT email, password_hash FROM users WHERE id=$1', [req.user.id]);
    if (!me.rowCount) return res.status(404).json({ error: 'User not found' });
    const u = me.rows[0];

    if (u.email && u.email.toLowerCase() === newEmail){
      return res.status(400).json({ error: 'That is already your email' });
    }
    const taken = await pool.query('SELECT 1 FROM users WHERE LOWER(email)=$1 AND id<>$2', [newEmail, req.user.id]);
    if (taken.rowCount) return res.status(409).json({ error: 'That email is already in use' });

    // Verify password (skip for Google-only users with no password)
    if (u.password_hash){
      const ok = await bcrypt.compare(password, u.password_hash);
      if (!ok) return res.status(403).json({ error: 'Incorrect password' });
    }

    // Create token + expiry (1h)
    const token = makeToken();
    const expires = new Date(Date.now() + 60 * 60 * 1000);
    await pool.query(
      'UPDATE users SET email_change_token=$1, email_change_new=$2, email_change_expires=$3 WHERE id=$4',
      [token, newEmail, expires, req.user.id]
    );

    // Send verification to the NEW email
    const baseUrl = process.env.APP_URL || 'http://localhost:3000';
    const link = baseUrl + '/verify-email-change?token=' + token;
    try {
      await mailer.sendMail({
        from: '"GistApp" <' + (process.env.GMAIL_SENDER || process.env.SMTP_USER) + '>',
        to: newEmail,
        subject: 'Confirm your new GistApp email',
        html: '<div style="font-family:Inter,sans-serif;max-width:480px;margin:0 auto;padding:24px">' +
          '<h2 style="color:#1c1c22;margin:0 0 12px">Confirm your new email</h2>' +
          '<p style="color:#4a4a55;line-height:1.6">Click the button below to switch your GistApp account email to <b>' + newEmail + '</b>. This link expires in 1 hour.</p>' +
          '<a href="' + link + '" style="display:inline-block;background:#7b8cff;color:#fff;text-decoration:none;padding:12px 24px;border-radius:10px;font-weight:700;margin-top:14px">Confirm new email</a>' +
          '<p style="color:#8e8e96;font-size:12.5px;margin-top:20px;line-height:1.5">If you did not request this change, ignore this email — your account email stays the same.</p>' +
          '</div>'
      });
      console.log('✅ Email change verification sent to', newEmail);
    } catch(mailErr){
      console.error('❌ Email change send failed:', mailErr.message);
      return res.status(500).json({ error: 'Could not send verification email. Try again later.' });
    }

    res.json({ ok: true, sent_to: newEmail });
  } catch(e){ console.error('request-email-change:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- stickers ---------- GISTAPP_STICKERS_V1 */
app.get('/api/stickers', auth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT id, url, name, created_at FROM stickers WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',
      [req.user.id]
    );
    res.json(r.rows);
  } catch(e){ console.error('stickers list:', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/stickers', auth, async (req, res) => {
  try {
    const { url, name } = req.body || {};
    if (!url) return res.status(400).json({ error: 'Missing url' });
    const count = await pool.query('SELECT COUNT(*)::int AS n FROM stickers WHERE user_id=$1', [req.user.id]);
    if (count.rows[0].n >= 50) return res.status(400).json({ error: 'Sticker limit reached (50 max)' });
    const r = await pool.query(
      'INSERT INTO stickers (user_id, url, name) VALUES ($1,$2,$3) RETURNING id, url, name, created_at',
      [req.user.id, url, (name || '').slice(0, 60)]
    );
    res.json(r.rows[0]);
  } catch(e){ console.error('sticker create:', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/stickers/:id', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid id' });
    await pool.query('DELETE FROM stickers WHERE id=$1 AND user_id=$2', [id, req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error('sticker delete:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- block ---------- */
app.post('/api/users/:id/block', auth, async (req,res)=>{
  try {
    const id = Number(req.params.id);
    if (!id || isNaN(id)) return res.status(400).json({ error: 'Invalid user id' });
    const r = await pool.query('SELECT blocked_ids FROM users WHERE id=$1',[req.user.id]);
    let list = r.rows[0].blocked_ids;
    if (!Array.isArray(list)) list = [];
    list = list.map(Number);
    const wasBlocked = list.includes(id);
    const next = wasBlocked ? list.filter(x=>x!==id) : [...list, id];
    await pool.query('UPDATE users SET blocked_ids=$1::jsonb WHERE id=$2',[JSON.stringify(next),req.user.id]);
    res.json({blocked: !wasBlocked});
  } catch(e){ console.error('block error', e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- blocked list ---------- */
app.get('/api/blocked', auth, async (req, res) => {
  const r = await pool.query('SELECT blocked_ids FROM users WHERE id=$1', [req.user.id]);
  const ids = r.rows[0].blocked_ids || [];
  if (!ids.length) return res.json([]);
  const u = await pool.query(
    'SELECT id, display_name, email, avatar_color, avatar_url FROM users WHERE id = ANY($1)',
    [ids]
  );
  res.json(u.rows);
});

/* ---------- delete my account ---------- */
app.delete('/api/me', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id=$1', [req.user.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- export my data ---------- */
app.get('/api/export', auth, async (req, res) => {
  try {
    const me = await pool.query('SELECT id,email,display_name,avatar_color,dark_mode,font_size,prefs,created_at FROM users WHERE id=$1', [req.user.id]);
    const chats = await pool.query('SELECT c.id,c.type,c.name FROM chats c JOIN chat_members m ON m.chat_id=c.id AND m.user_id=$1', [req.user.id]);
    const messages = await pool.query(`
      SELECT m.id, m.chat_id, m.body, m.created_at, m.media_url, m.media_type, m.deleted_at
      FROM messages m
      JOIN chat_members cm ON cm.chat_id=m.chat_id AND cm.user_id=$1
      ORDER BY m.created_at ASC
    `, [req.user.id]);
    res.json({
      exported_at: new Date().toISOString(),
      account: me.rows[0],
      chats: chats.rows,
      messages: messages.rows
    });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/search', auth, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    if (!q) return res.json([]);
    const r = await pool.query(`
      SELECT m.id, m.chat_id, m.body, m.created_at, u.display_name
      FROM messages m
      JOIN users u ON u.id=m.sender_id
      JOIN chat_members cm ON cm.chat_id=m.chat_id AND cm.user_id=$1 AND cm.status='accepted'
      WHERE m.deleted_at IS NULL AND LOWER(m.body) LIKE $2
      ORDER BY m.created_at DESC LIMIT 50
    `, [req.user.id, '%' + q.toLowerCase() + '%']);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- two-step verification ---------- */
app.post('/api/2fa/setup', auth, async (req, res) => {
  try {
    const secret = speakeasy.generateSecret({
      name: 'GistApp (' + req.user.email + ')',
      issuer: 'GistApp'
    });
    const qr = await qrcode.toDataURL(secret.otpauth_url);
    // store secret but DO NOT enable yet — user must verify a code first
    await pool.query('UPDATE users SET totp_secret=$1 WHERE id=$2', [secret.base32, req.user.id]);
    res.json({ secret: secret.base32, qr });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/2fa/enable', auth, async (req, res) => {
  try {
    const { code } = req.body;
    const r = await pool.query('SELECT totp_secret FROM users WHERE id=$1', [req.user.id]);
    const secret = r.rows[0].totp_secret;
    if (!secret) return res.status(400).json({ error: 'Run setup first' });
    const ok = speakeasy.totp.verify({ secret, encoding:'base32', token: String(code||'').trim(), window: 1 });
    if (!ok) return res.status(400).json({ error: 'Invalid code' });
    await pool.query('UPDATE users SET totp_enabled=true WHERE id=$1', [req.user.id]);
    // GISTAPP_SECURITY_ALERT
    try {
      const _me = await pool.query('SELECT email, display_name FROM users WHERE id=$1', [req.user.id]);
      if (_me.rowCount) sendSecurityAlertEmail(_me.rows[0].email, _me.rows[0].display_name, '2fa_enabled', { ip: req.ip }).catch(function(){});
    } catch(_){}
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/2fa/disable', auth, async (req, res) => {
  try {
    const { password } = req.body;
    const r = await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.user.id]);
    const ok = await bcrypt.compare(String(password||''), r.rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Wrong password' });
    await pool.query('UPDATE users SET totp_enabled=false, totp_secret=NULL WHERE id=$1', [req.user.id]);
    // GISTAPP_SECURITY_ALERT
    try {
      const _me = await pool.query('SELECT email, display_name FROM users WHERE id=$1', [req.user.id]);
      if (_me.rowCount) sendSecurityAlertEmail(_me.rows[0].email, _me.rows[0].display_name, '2fa_disabled', { ip: req.ip }).catch(function(){});
    } catch(_){}
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- change email ---------- */
app.post('/api/me/change-email', auth, async (req, res) => {
  try {
    const { password, new_email } = req.body;
    const target = String(new_email||'').toLowerCase().trim();
    if (!target || !target.includes('@')) return res.status(400).json({ error: 'Invalid email' });
    if (target === req.user.email) return res.status(400).json({ error: 'Same as current email' });
    const dup = await pool.query('SELECT id FROM users WHERE email=$1', [target]);
    if (dup.rowCount) return res.status(409).json({ error: 'That email is already in use' });
    const me = await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.user.id]);
    const ok = await bcrypt.compare(String(password||''), me.rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Wrong password' });
    const token = makeToken();
    const expires = new Date(Date.now() + 24*3600*1000);
    await pool.query(
      'UPDATE users SET email_change_token=$1, email_change_new=$2, email_change_expires=$3 WHERE id=$4',
      [token, target, expires, req.user.id]
    );
    // send verification link to the NEW email
    const baseUrl = process.env.APP_URL || 'http://localhost:3000';
    const link = baseUrl + '/verify-email-change?token=' + token;
    res.json({ ok: true, sent_to: target });
    mailer.sendMail({
      from: '"GistApp" <' + process.env.SMTP_USER + '>',
      to: target,
      subject: 'Confirm your new GistApp email',
      html: '<p>Tap the link below to confirm this email address for your GistApp account:</p>' +
            '<p><a href="' + link + '">' + link + '</a></p>' +
            '<p>Link expires in 24 hours.</p>'
    }).then(() => console.log('✅ Change-email verification sent to', target))
      .catch(mailErr => console.error('❌ Change-email send failed:', mailErr.message));
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/verify-email-change', async (req, res) => {
  const token = (req.query.token||'').trim();
  if (!token) return res.status(400).send('<h2>Missing token</h2>');
  const r = await pool.query(
    'SELECT id, email, display_name, email_change_new FROM users WHERE email_change_token=$1 AND email_change_expires > NOW()',
    [token]
  );
  if (!r.rowCount) return res.send('<h2>Link expired or invalid</h2>');
  const newEmail = r.rows[0].email_change_new;
  await pool.query(
    'UPDATE users SET email=$1, email_change_token=NULL, email_change_new=NULL, email_change_expires=NULL WHERE id=$2',
    [newEmail, r.rows[0].id]
  );
  // GISTAPP_SECURITY_ALERT — notify OLD email
  try {
    var _old = r.rows[0].email;
    var _dn = r.rows[0].display_name || null;
    if (_old && _old !== newEmail){
      sendSecurityAlertEmail(_old, _dn, 'email_changed', { newEmail: newEmail, ip: req.ip }).catch(function(){});
    }
  } catch(_){}
  res.send('<html><body style="font-family:Inter,sans-serif;text-align:center;padding:60px"><h1 style="color:#25d366">✅ Email updated</h1><p>You can now log in with ' + newEmail + '</p><a href="/">Open GistApp</a></body></html>');
});

/* ---------- resend verification ---------- */
app.post('/api/verify/resend', resendLimiter, async (req, res) => {
  try {
    const email = (req.body.email || '').toLowerCase().trim();
    if (!email) return res.status(400).json({ error: 'Email required' });
    const r = await pool.query('SELECT id, display_name, verified FROM users WHERE email=$1', [email]);
    if (!r.rowCount) return res.status(404).json({ error: 'No account with that email' });
    if (r.rows[0].verified) return res.json({ ok: true, message: 'Already verified' });
    const token = makeToken();
    const expires = new Date(Date.now() + 24 * 3600 * 1000);
    await pool.query('UPDATE users SET verify_token=$1, verify_expires=$2 WHERE id=$3', [token, expires, r.rows[0].id]);
    res.json({ ok: true, message: 'Sending…' });
    sendVerificationEmail(email, token, r.rows[0].display_name)
      .then(() => console.log('✅ Resent verification to', email))
      .catch(e => console.error('❌ Resend failed:', e.message));
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- CALL HISTORY ---------- */
app.get('/api/calls', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT c.id, c.kind, c.status, c.started_at, c.answered_at, c.ended_at, c.duration_sec,
        c.caller_id, c.callee_id,
        CASE WHEN c.caller_id=$1 THEN c.callee_id ELSE c.caller_id END AS other_id,
        u.display_name AS other_name, u.avatar_color AS other_color, u.avatar_url AS other_url,
        (c.caller_id = $1) AS outgoing
      FROM calls c
      JOIN users u ON u.id = CASE WHEN c.caller_id=$1 THEN c.callee_id ELSE c.caller_id END
      WHERE c.caller_id=$1 OR c.callee_id=$1
      ORDER BY c.started_at DESC LIMIT 100
    `, [req.user.id]);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/calls/log', auth, async (req, res) => {
  try {
    const { callee_id, kind, status, duration_sec } = req.body;
    if (!callee_id || !kind) return res.status(400).json({ error: 'Missing fields' });
    const r = await pool.query(
      'INSERT INTO calls (caller_id, callee_id, kind, status, answered_at, ended_at, duration_sec) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id',
      [req.user.id, callee_id, kind, status || 'ended',
       status === 'answered' ? new Date() : null,
       new Date(), duration_sec || 0]
    );
    res.json({ ok: true, id: r.rows[0].id });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- report user ---------- */
app.post('/api/users/:id/report', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id || isNaN(id)) return res.status(400).json({ error: 'Invalid id' });
    const { reason } = req.body;
    if (!reason || !String(reason).trim()) return res.status(400).json({ error: 'Reason required' });
    await pool.query(
      'INSERT INTO reports (reporter_id, reported_id, reason) VALUES ($1,$2,$3)',
      [req.user.id, id, String(reason).trim().slice(0, 500)]
    );
    console.log('🚩 Report:', req.user.id, '→', id, '|', reason);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- STATUS / STORIES ---------- */
app.post('/api/statuses', auth, async (req, res) => {
  try {
    const { media_url, media_type, caption } = req.body;
    if (!media_url || !media_type) return res.status(400).json({ error: 'Media required' });
    const r = await pool.query(
      'INSERT INTO statuses (user_id, media_url, media_type, caption) VALUES ($1,$2,$3,$4) RETURNING id, media_url, media_type, caption, created_at, expires_at',
      [req.user.id, media_url, media_type, String(caption||'').slice(0,200)]
    );
    // broadcast to all online users so their stories row refreshes
    io.emit('status-added', { userId: req.user.id });
    res.json(r.rows[0]);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/statuses/feed', auth, async (req, res) => {
  try {
    // active statuses grouped by user
    const r = await pool.query(`
      SELECT s.user_id, u.display_name, u.avatar_color, u.avatar_url,
        COUNT(s.id) AS status_count,
        MAX(s.created_at) AS latest_at,
        BOOL_AND(CASE WHEN sv.viewer_id IS NOT NULL THEN true ELSE false END) AS all_seen
      FROM statuses s
      JOIN users u ON u.id = s.user_id
      LEFT JOIN status_views sv ON sv.status_id = s.id AND sv.viewer_id = $1
      WHERE s.expires_at > NOW() AND s.user_id <> $1
      GROUP BY s.user_id, u.display_name, u.avatar_color, u.avatar_url
      ORDER BY all_seen ASC, latest_at DESC
    `, [req.user.id]);

    // Filter by status visibility pref
    const filtered = [];
    for (const row of r.rows){
      const ok = await canViewField(req.user.id, row.user_id, 'status');
      if (ok) filtered.push(row);
    }

    // my own statuses
    const mine = await pool.query(`
      SELECT id, media_url, media_type, caption, created_at, expires_at
      FROM statuses WHERE user_id = $1 AND expires_at > NOW()
      ORDER BY created_at ASC
    `, [req.user.id]);

    res.json({ others: filtered, mine: mine.rows });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/statuses/user/:id', auth, async (req, res) => {
  try {
    const uid = Number(req.params.id);
    const allowed = await canViewField(req.user.id, uid, 'status');
    if (!allowed) return res.json([]);
    const r = await pool.query(`
      SELECT s.id, s.media_url, s.media_type, s.caption, s.created_at,
        EXISTS(SELECT 1 FROM status_views WHERE status_id=s.id AND viewer_id=$1) AS seen
      FROM statuses s
      WHERE s.user_id=$2 AND s.expires_at > NOW()
      ORDER BY s.created_at ASC
    `, [req.user.id, uid]);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/statuses/:id/view', auth, async (req, res) => {
  try {
    const sid = Number(req.params.id);
    await pool.query(
      'INSERT INTO status_views (status_id, viewer_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [sid, req.user.id]
    );
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/statuses/:id', auth, async (req, res) => {
  try {
    const sid = Number(req.params.id);
    const r = await pool.query('DELETE FROM statuses WHERE id=$1 AND user_id=$2 RETURNING id', [sid, req.user.id]);
    if (!r.rowCount) return res.status(404).json({ error: 'Not found' });
    io.emit('status-added', { userId: req.user.id });
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

/* ---------- status viewers ---------- */
app.get('/api/statuses/:id/viewers', auth, async (req, res) => {
  try {
    const sid = Number(req.params.id);
    // only the owner can see viewers
    const own = await pool.query('SELECT 1 FROM statuses WHERE id=$1 AND user_id=$2', [sid, req.user.id]);
    if (!own.rowCount) return res.status(403).json({ error: 'Not your status' });
    const r = await pool.query(`
      SELECT u.id, u.display_name, u.avatar_color, u.avatar_url, sv.viewed_at
      FROM status_views sv
      JOIN users u ON u.id = sv.viewer_id
      WHERE sv.status_id = $1
      ORDER BY sv.viewed_at DESC
    `, [sid]);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/statuses/mine/counts', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT s.id, COUNT(sv.viewer_id) AS viewers
      FROM statuses s
      LEFT JOIN status_views sv ON sv.status_id = s.id
      WHERE s.user_id = $1 AND s.expires_at > NOW()
      GROUP BY s.id
      ORDER BY s.created_at ASC
    `, [req.user.id]);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- FEED / POSTS ---------- */
app.post('/api/posts', auth, async (req, res) => {
  try {
    const { body, media_url, media_type, community } = req.body;
    const text = String(body || '').trim();
    if (!text && !media_url) return res.status(400).json({ error: 'Empty post' });
    const r = await pool.query(
      'INSERT INTO posts (user_id, body, media_url, media_type, community) VALUES ($1,$2,$3,$4,$5) RETURNING id, body, media_url, media_type, community, created_at',
      [req.user.id, text, media_url || null, media_type || null, community || null]
    );
    const me = await pool.query('SELECT id, display_name, avatar_color, avatar_url FROM users WHERE id=$1', [req.user.id]);
    io.emit('feed-new-post', { id: r.rows[0].id });
    res.json({ ...r.rows[0], author: me.rows[0] });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/feed', auth, async (req, res) => {
  try {
    const tab = req.query.tab || 'foryou';
    const uid = req.user.id;

    const r = await pool.query(`
      SELECT
        p.id, p.body, p.media_url, p.media_type, p.community, p.created_at, p.user_id,
        u.display_name, u.avatar_color, u.avatar_url,
        COALESCE(lc.like_count, 0)::int     AS like_count,
        COALESCE(vc.up, 0)::int             AS upvotes,
        COALESCE(vc.down, 0)::int           AS downvotes,
        COALESCE(cc.comment_count, 0)::int  AS comment_count,
        (ml.user_id IS NOT NULL)            AS liked,
        (ms.user_id IS NOT NULL)            AS saved,
        mv.vote                             AS my_vote,
        (COALESCE(lc.like_count,0) * 2 + COALESCE(vc.up,0) * 3) AS score
      FROM posts p
      JOIN users u ON u.id = p.user_id
      LEFT JOIN (SELECT post_id, COUNT(*) AS like_count FROM post_likes GROUP BY post_id) lc ON lc.post_id = p.id
      LEFT JOIN (SELECT post_id,
                        COUNT(*) FILTER (WHERE vote=1) AS up,
                        COUNT(*) FILTER (WHERE vote=-1) AS down
                 FROM post_votes GROUP BY post_id) vc ON vc.post_id = p.id
      LEFT JOIN (SELECT post_id, COUNT(*) AS comment_count FROM post_comments GROUP BY post_id) cc ON cc.post_id = p.id
      LEFT JOIN post_likes ml ON ml.post_id = p.id AND ml.user_id = $1
      LEFT JOIN post_saves ms ON ms.post_id = p.id AND ms.user_id = $1
      LEFT JOIN post_votes mv ON mv.post_id = p.id AND mv.user_id = $1
      WHERE p.deleted_at IS NULL
      ORDER BY ${tab === 'foryou' ? 'score DESC, p.created_at DESC' : 'p.created_at DESC'}
      LIMIT 60
    `, [uid]);

    // GISTAPP_LIVE_BADGE_BE — mark live users
    try {
      const liveIds = await getLiveUserIds();
      r.rows.forEach(function(p){ p.author_is_live = liveIds.has(Number(p.user_id)); });
    } catch(_){}
    res.json(r.rows);
  } catch(e){ console.error('feed error', e); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/posts/:id', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query('SELECT user_id FROM posts WHERE id=$1', [id]);
    if (!r.rowCount) return res.status(404).json({ error: 'Not found' });
    if (r.rows[0].user_id !== req.user.id) return res.status(403).json({ error: 'Not yours' });
    await pool.query('UPDATE posts SET deleted_at=NOW() WHERE id=$1', [id]);
    io.emit('feed-delete-post', { id });
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/posts/:id/like', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const has = await pool.query('SELECT 1 FROM post_likes WHERE post_id=$1 AND user_id=$2', [id, req.user.id]);
    if (has.rowCount){
      await pool.query('DELETE FROM post_likes WHERE post_id=$1 AND user_id=$2', [id, req.user.id]);
    } else {
      await pool.query('INSERT INTO post_likes (post_id, user_id) VALUES ($1,$2)', [id, req.user.id]);
    }
    const c = await pool.query('SELECT COUNT(*) FROM post_likes WHERE post_id=$1', [id]);
    io.emit('feed-post-update', { id, like_count: Number(c.rows[0].count) });
    res.json({ liked: !has.rowCount, like_count: Number(c.rows[0].count) });
    // GISTAPP_WEBPUSH_V1 — notify post author
    try {
      const p = await pool.query('SELECT user_id FROM posts WHERE id=$1', [id]);
      if (p.rowCount && p.rows[0].user_id !== req.user.id){
        const u = await pool.query('SELECT display_name FROM users WHERE id=$1', [req.user.id]);
        sendPush(p.rows[0].user_id, '❤️ New like', (u.rows[0] && u.rows[0].display_name) + ' liked your post', { url: '/?post=' + id }).catch(()=>{});
      }
    } catch(_){}

  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/posts/:id/vote', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const vote = Number(req.body.vote);
    if (![1,-1].includes(vote)) return res.status(400).json({ error: 'vote must be 1 or -1' });
    const cur = await pool.query('SELECT vote FROM post_votes WHERE post_id=$1 AND user_id=$2', [id, req.user.id]);
    if (cur.rowCount && cur.rows[0].vote === vote){
      await pool.query('DELETE FROM post_votes WHERE post_id=$1 AND user_id=$2', [id, req.user.id]);
    } else if (cur.rowCount){
      await pool.query('UPDATE post_votes SET vote=$1 WHERE post_id=$2 AND user_id=$3', [vote, id, req.user.id]);
    } else {
      await pool.query('INSERT INTO post_votes (post_id, user_id, vote) VALUES ($1,$2,$3)', [id, req.user.id, vote]);
    }
    const c = await pool.query(
      'SELECT COUNT(*) FILTER (WHERE vote=1) AS up, COUNT(*) FILTER (WHERE vote=-1) AS down FROM post_votes WHERE post_id=$1', [id]);
    res.json({ my_vote: (cur.rowCount && cur.rows[0].vote === vote) ? 0 : vote, up: Number(c.rows[0].up), down: Number(c.rows[0].down) });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/posts/:id/save', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const has = await pool.query('SELECT 1 FROM post_saves WHERE post_id=$1 AND user_id=$2', [id, req.user.id]);
    if (has.rowCount){
      await pool.query('DELETE FROM post_saves WHERE post_id=$1 AND user_id=$2', [id, req.user.id]);
    } else {
      await pool.query('INSERT INTO post_saves (post_id, user_id) VALUES ($1,$2)', [id, req.user.id]);
    }
    res.json({ saved: !has.rowCount });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/posts/:id/comments', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query(`
      SELECT c.id, c.body, c.created_at, c.audio_url, c.audio_duration, c.kind, c.poll_data, c.media_urls, c.sticker_url,
             u.id AS user_id, u.display_name, u.avatar_color, u.avatar_url
      FROM post_comments c
      JOIN users u ON u.id = c.user_id
      WHERE c.post_id = $1
      ORDER BY c.created_at ASC
      LIMIT 200
    `, [id]);
    // Fetch reactions for all comments
    if (r.rows.length){
      const cids = r.rows.map(function(c){ return c.id; });
      const rx = await pool.query(
        'SELECT comment_id, emoji, COUNT(*)::int AS n FROM comment_reactions WHERE comment_id = ANY($1) GROUP BY comment_id, emoji',
        [cids]
      );
      const myRx = await pool.query(
        'SELECT comment_id, emoji FROM comment_reactions WHERE comment_id = ANY($1) AND user_id=$2',
        [cids, req.user.id]
      );
      const tally = {};
      rx.rows.forEach(function(x){ if (!tally[x.comment_id]) tally[x.comment_id] = {}; tally[x.comment_id][x.emoji] = x.n; });
      const mine = {};
      myRx.rows.forEach(function(x){ if (!mine[x.comment_id]) mine[x.comment_id] = []; mine[x.comment_id].push(x.emoji); });
      r.rows.forEach(function(c){
        c.reactions = tally[c.id] || {};
        c.my_reactions = mine[c.id] || [];
      });
    }
    // For poll comments, fetch vote counts + my vote
    const polls = r.rows.filter(function(x){ return x.kind === 'poll' && x.poll_data; });
    if (polls.length){
      const ids = polls.map(function(p){ return p.id; });
      const votes = await pool.query(
        'SELECT comment_id, option_index, COUNT(*)::int AS n FROM comment_poll_votes WHERE comment_id = ANY($1) GROUP BY comment_id, option_index',
        [ids]
      );
      const mine = await pool.query(
        'SELECT comment_id, option_index FROM comment_poll_votes WHERE comment_id = ANY($1) AND user_id=$2',
        [ids, req.user.id]
      );
      const tally = {};
      votes.rows.forEach(function(v){
        if (!tally[v.comment_id]) tally[v.comment_id] = {};
        tally[v.comment_id][v.option_index] = v.n;
      });
      const myPick = {};
      mine.rows.forEach(function(v){ myPick[v.comment_id] = v.option_index; });
      r.rows.forEach(function(c){
        if (c.kind === 'poll'){
          c.poll_tally = tally[c.id] || {};
          c.poll_my_vote = myPick[c.id] != null ? myPick[c.id] : null;
        }
      });
    }
    res.json(r.rows);
  } catch(e){ console.error('comments get:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* GISTAPP_BATCH2 — sticker comments + report status */
(async function(){
  try {
    await pool.query(`ALTER TABLE post_comments ADD COLUMN IF NOT EXISTS sticker_url TEXT`);
    await pool.query(`ALTER TABLE reports ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pending'`);
    await pool.query(`ALTER TABLE reports ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ`);
    await pool.query(`ALTER TABLE reports ADD COLUMN IF NOT EXISTS notes TEXT`);
    console.log('✅ batch2 migrations ready');
  } catch(e){ console.warn('batch2 migration:', e.message); }
})();

/* GISTAPP_BATCH2 — my submitted reports */
app.get('/api/reports/mine', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT r.id, r.reported_id, r.reason, r.created_at, r.status, r.reviewed_at, r.notes,
              u.display_name AS reported_name, u.username AS reported_username,
              u.avatar_url AS reported_avatar, u.avatar_color AS reported_color
       FROM reports r
       LEFT JOIN users u ON u.id = r.reported_id
       WHERE r.reporter_id = $1
       ORDER BY r.created_at DESC
       LIMIT 100`,
      [req.user.id]
    );
    res.json({ reports: r.rows });
  } catch(e){ console.error('reports mine:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* GISTAPP_CAROUSEL_REACT — photo carousel + reactions */
(async function(){
  try {
    await pool.query(`ALTER TABLE post_comments ADD COLUMN IF NOT EXISTS media_urls JSONB`);
    await pool.query(`CREATE TABLE IF NOT EXISTS comment_reactions (
      comment_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      emoji TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (comment_id, user_id, emoji)
    )`);
    console.log('✅ carousel + reactions migrations ready');
  } catch(e){ console.warn('carousel migration:', e.message); }
})();

/* GISTAPP_CAROUSEL_REACT — toggle reaction on a comment */
app.post('/api/comments/:cid/react', auth, async (req, res) => {
  try {
    const cid = Number(req.params.cid);
    const emoji = String((req.body && req.body.emoji) || '').slice(0, 8);
    const allowed = ['👍','❤️','😂','😮','😢','🔥'];
    if (!cid || !emoji || allowed.indexOf(emoji) === -1) return res.status(400).json({ error: 'Invalid emoji' });
    const existing = await pool.query('SELECT 1 FROM comment_reactions WHERE comment_id=$1 AND user_id=$2 AND emoji=$3', [cid, req.user.id, emoji]);
    if (existing.rowCount){
      await pool.query('DELETE FROM comment_reactions WHERE comment_id=$1 AND user_id=$2 AND emoji=$3', [cid, req.user.id, emoji]);
    } else {
      await pool.query('INSERT INTO comment_reactions (comment_id, user_id, emoji) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [cid, req.user.id, emoji]);
    }
    const tally = await pool.query('SELECT emoji, COUNT(*)::int AS n FROM comment_reactions WHERE comment_id=$1 GROUP BY emoji', [cid]);
    const mine = await pool.query('SELECT emoji FROM comment_reactions WHERE comment_id=$1 AND user_id=$2', [cid, req.user.id]);
    const out = {};
    tally.rows.forEach(function(r){ out[r.emoji] = r.n; });
    res.json({ ok: true, reactions: out, my_reactions: mine.rows.map(function(r){ return r.emoji; }) });
  } catch(e){ console.error('react:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* GISTAPP_COMMUNITY_HUB — community stats + guidelines + top creators */
app.get('/api/community/overview', auth, async (req, res) => {
  try {
    const statsR = await pool.query(`
      SELECT
        (SELECT COUNT(*)::int FROM users WHERE verified=true) AS members,
        (SELECT COUNT(*)::int FROM posts) AS posts,
        (SELECT COUNT(*)::int FROM live_streams WHERE status='ended' OR status='live') AS streams,
        (SELECT COUNT(*)::int FROM live_gifts) AS gifts_sent,
        (SELECT COUNT(*)::int FROM post_comments) AS comments
    `);
    const stats = statsR.rows[0];

    // Trending hashtags from last 30 days
    // GISTAPP_COMMUNITY_HUB_FIX — use LATERAL for set-returning fn in FROM
    const hashtagR = await pool.query(`
      SELECT LOWER(m.tag_arr[1]) AS tag, COUNT(*)::int AS n
      FROM posts p
      CROSS JOIN LATERAL regexp_matches(p.body, '#([A-Za-z0-9_]{2,30})', 'g') AS m(tag_arr)
      WHERE p.created_at > NOW() - INTERVAL '30 days'
      GROUP BY LOWER(m.tag_arr[1])
      ORDER BY n DESC, tag ASC
      LIMIT 8
    `);

    // Top creators by follower count
    const topR = await pool.query(`
      SELECT u.id, u.display_name, u.username, u.avatar_url, u.avatar_color,
             u.subscription_tier,
             COALESCE(f.followers, 0)::int AS followers
      FROM users u
      LEFT JOIN (SELECT following_id, COUNT(*)::int AS followers FROM user_follows GROUP BY following_id) f
        ON f.following_id = u.id
      WHERE u.verified = true
      ORDER BY followers DESC NULLS LAST, u.id ASC
      LIMIT 6
    `);

    res.json({
      stats: stats,
      trending_hashtags: hashtagR.rows,
      top_creators: topR.rows,
      guidelines: {
        can: [
          'Chat, post, and go live with anyone on the platform.',
          'Share content you own or have the right to share.',
          'Earn coins from gifts and withdraw your balance.',
          'Block, mute, or report anyone who crosses a line.',
          'Delete your account and data at any time.'
        ],
        cannot: [
          'Harass, threaten, or abuse other members.',
          'Post illegal, adult, or sexually explicit content.',
          'Impersonate anyone or misrepresent who you are.',
          'Spam, scam, or run unauthorised promotions.',
          "Share someone else's private information without consent.",
          'Use the app if you are under 18 years old.'
        ]
      }
    });
  } catch(e){ console.error('community overview:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* GISTAPP_COMMUNITY_V1 — poll create + vote */
app.post('/api/posts/:id/comment-poll', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const postR = await pool.query('SELECT user_id FROM posts WHERE id=$1', [id]);
    if (!postR.rowCount) return res.status(404).json({ error: 'Post not found' });
    if (postR.rows[0].user_id !== req.user.id) return res.status(403).json({ error: 'Polls only on your own posts' });
    const question = String((req.body && req.body.question) || '').slice(0, 200).trim();
    const options = Array.isArray(req.body && req.body.options) ? req.body.options.map(function(o){ return String(o || '').slice(0, 60).trim(); }).filter(Boolean).slice(0, 5) : [];
    if (!question) return res.status(400).json({ error: 'Question required' });
    if (options.length < 2) return res.status(400).json({ error: 'At least 2 options required' });
    const pollData = { question: question, options: options };
    const r = await pool.query(
      'INSERT INTO post_comments (post_id, user_id, body, kind, poll_data) VALUES ($1,$2,$3,$4,$5) RETURNING id, body, created_at, kind, poll_data',
      [id, req.user.id, question, 'poll', JSON.stringify(pollData)]
    );
    const me = await pool.query('SELECT display_name, avatar_color, avatar_url FROM users WHERE id=$1', [req.user.id]);
    const full = { ...r.rows[0], user_id: req.user.id, poll_tally: {}, poll_my_vote: null, ...me.rows[0] };
    io.emit('feed-new-comment', { post_id: id, comment: full });
    res.json(full);
  } catch(e){ console.error('poll create:', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/comment-polls/:cid/vote', auth, async (req, res) => {
  try {
    const cid = Number(req.params.cid);
    const optionIndex = Number(req.body && req.body.option_index);
    const c = await pool.query("SELECT id, poll_data FROM post_comments WHERE id=$1 AND kind='poll'", [cid]);
    if (!c.rowCount) return res.status(404).json({ error: 'Poll not found' });
    const opts = (c.rows[0].poll_data && c.rows[0].poll_data.options) || [];
    if (!Number.isInteger(optionIndex) || optionIndex < 0 || optionIndex >= opts.length) return res.status(400).json({ error: 'Invalid option' });
    // upsert vote
    await pool.query(
      'INSERT INTO comment_poll_votes (comment_id, user_id, option_index) VALUES ($1,$2,$3) ON CONFLICT (comment_id, user_id) DO UPDATE SET option_index=EXCLUDED.option_index',
      [cid, req.user.id, optionIndex]
    );
    const votes = await pool.query('SELECT option_index, COUNT(*)::int AS n FROM comment_poll_votes WHERE comment_id=$1 GROUP BY option_index', [cid]);
    const tally = {};
    votes.rows.forEach(function(v){ tally[v.option_index] = v.n; });
    res.json({ ok: true, poll_tally: tally, poll_my_vote: optionIndex });
  } catch(e){ console.error('poll vote:', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/posts/:id/comments', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const body = String(req.body.body || '').trim();
    const audio_url = req.body.audio_url ? String(req.body.audio_url).slice(0, 500) : null;
    const audio_duration = req.body.audio_duration ? Number(req.body.audio_duration) : null;
    // GISTAPP_CAROUSEL_REACT — up to 9 photo URLs
    let media_urls = null;
    if (Array.isArray(req.body.media_urls) && req.body.media_urls.length){
      media_urls = req.body.media_urls.slice(0, 9).map(function(u){ return String(u).slice(0, 500); }).filter(Boolean);
      if (!media_urls.length) media_urls = null;
    }
    const sticker_url = req.body.sticker_url ? String(req.body.sticker_url).slice(0, 500) : null;  // GISTAPP_BATCH2
    if (!body && !audio_url && !media_urls && !sticker_url) return res.status(400).json({ error: 'Empty comment' });

    // GISTAPP_COMMUNITY_V1 — comment controls
    const postR = await pool.query('SELECT user_id FROM posts WHERE id=$1', [id]);
    if (!postR.rowCount) return res.status(404).json({ error: 'Post not found' });
    const postOwnerId = postR.rows[0].user_id;
    if (postOwnerId !== req.user.id){
      const ownerR = await pool.query('SELECT prefs FROM users WHERE id=$1', [postOwnerId]);
      const ownerPrefs = (ownerR.rows[0] && ownerR.rows[0].prefs) || {};
      const cc = ownerPrefs.comment_control || 'everyone';
      if (cc === 'nobody') return res.status(403).json({ error: 'Comments are turned off on this post' });
      if (cc === 'friends'){
        // require mutual follow: owner follows me AND I follow owner
        const followA = await pool.query('SELECT 1 FROM user_follows WHERE follower_id=$1 AND following_id=$2', [postOwnerId, req.user.id]);
        const followB = await pool.query('SELECT 1 FROM user_follows WHERE follower_id=$1 AND following_id=$2', [req.user.id, postOwnerId]);
        if (!followA.rowCount || !followB.rowCount) return res.status(403).json({ error: 'Only friends can comment on this post' });
      }
      // Keyword filter
      const kw = Array.isArray(ownerPrefs.comment_keywords) ? ownerPrefs.comment_keywords : [];
      if (kw.length && body){
        const lower = body.toLowerCase();
        for (let i = 0; i < kw.length; i++){
          const k = String(kw[i] || '').toLowerCase().trim();
          if (k && lower.indexOf(k) !== -1){
            return res.status(403).json({ error: 'Comment blocked by word filter' });
          }
        }
      }
    }

    const r = await pool.query(
      'INSERT INTO post_comments (post_id, user_id, body, audio_url, audio_duration, media_urls, sticker_url) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, body, created_at, audio_url, audio_duration, media_urls, sticker_url',
      [id, req.user.id, body.slice(0, 500), audio_url, audio_duration, media_urls ? JSON.stringify(media_urls) : null, sticker_url]
    );
    const me = await pool.query('SELECT display_name, avatar_color, avatar_url FROM users WHERE id=$1', [req.user.id]);
    const full = { ...r.rows[0], user_id: req.user.id, kind: 'text', ...me.rows[0] };
    io.emit('feed-new-comment', { post_id: id, comment: full });
    res.json(full);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- APP LOCK / CHAT LOCK ---------- */
app.post('/api/lock/set-pin', auth, async (req, res) => {
  try {
    const { pin, password } = req.body;
    if (!/^\d{4}$/.test(String(pin||''))) return res.status(400).json({ error: 'PIN must be 4 digits' });
    const me = await pool.query('SELECT pin_hash, password_hash FROM users WHERE id=$1', [req.user.id]);
    const u = me.rows[0];
    // If a PIN already exists, require the current password to change it
    if (u.pin_hash) {
      const ok = password ? await bcrypt.compare(String(password), u.password_hash) : false;
      if (!ok) return res.status(401).json({ error: 'Enter your account password to change the PIN' });
    }
    const hash = await bcrypt.hash(String(pin), 10);
    await pool.query('UPDATE users SET pin_hash=$1, app_lock_enabled=true, pin_attempts=0, pin_lockout_until=NULL WHERE id=$2', [hash, req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/lock/verify-pin', auth, async (req, res) => {
  try {
    const { pin } = req.body;
    const me = await pool.query('SELECT pin_hash, pin_attempts, pin_lockout_until FROM users WHERE id=$1', [req.user.id]);
    const u = me.rows[0];
    if (!u.pin_hash) return res.status(400).json({ error: 'PIN not set' });
    if (u.pin_lockout_until && new Date(u.pin_lockout_until) > new Date()){
      const secs = Math.ceil((new Date(u.pin_lockout_until) - new Date()) / 1000);
      return res.status(429).json({ error: 'Too many attempts. Wait ' + secs + 's' });
    }
    const ok = await bcrypt.compare(String(pin||''), u.pin_hash);
    if (!ok){
      const attempts = (u.pin_attempts || 0) + 1;
      let lockout = null;
      if (attempts >= 5) lockout = new Date(Date.now() + 5 * 60 * 1000); // 5 min
      await pool.query('UPDATE users SET pin_attempts=$1, pin_lockout_until=$2 WHERE id=$3', [attempts, lockout, req.user.id]);
      return res.status(401).json({ error: 'Incorrect PIN', attempts, remaining: Math.max(0, 5 - attempts) });
    }
    await pool.query('UPDATE users SET pin_attempts=0, pin_lockout_until=NULL WHERE id=$1', [req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/lock/reset-pin', auth, async (req, res) => {
  try {
    const { code, password, new_pin } = req.body;
    if (!/^\d{4}$/.test(String(new_pin||''))) return res.status(400).json({ error: 'New PIN must be 4 digits' });
    const me = await pool.query('SELECT totp_secret, totp_enabled, password_hash FROM users WHERE id=$1', [req.user.id]);
    const u = me.rows[0];

    const hasRealPassword = u.password_hash && u.password_hash !== 'google-oauth';
    const hasTotp = u.totp_enabled && u.totp_secret;

    let ok = false;

    // Case 1: User has NEITHER 2FA NOR a real password → they're a pure Google user.
    // They're already authenticated via JWT, so allow reset.
    if (!hasTotp && !hasRealPassword){
      ok = true;
    }
    // Case 2: User has 2FA → verify with TOTP code
    else if (hasTotp && code){
      try {
        ok = speakeasy.totp.verify({
          secret: u.totp_secret,
          encoding: 'base32',
          token: String(code).trim(),
          window: 1
        });
      } catch(_){ ok = false; }
    }
    // Case 3: User has a real password → verify with password
    if (!ok && password && hasRealPassword){
      try { ok = await bcrypt.compare(String(password), u.password_hash); } catch(_){ ok = false; }
    }

    if (!ok) return res.status(401).json({ error: 'Invalid 2FA code or password' });

    const hash = await bcrypt.hash(String(new_pin), 10);
    await pool.query(
      'UPDATE users SET pin_hash=$1, pin_attempts=0, pin_lockout_until=NULL WHERE id=$2',
      [hash, req.user.id]
    );
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// GISTAPP_LOCK_STATUS_GUARD
app.get('/api/lock/status', auth, async (req, res) => {
  try {
    const me = await pool.query('SELECT pin_hash, app_lock_enabled, app_lock_timeout_min, chat_lock_enabled, locked_chats, totp_enabled FROM users WHERE id=$1', [req.user.id]);
    const u = me.rows[0];
    // If user doesn't exist (deleted account / stale token), return safe defaults
    if (!u){
      return res.json({
        pin_set: false,
        app_lock_enabled: false,
        app_lock_timeout_min: 0,
        chat_lock_enabled: false,
        locked_chats: [],
        totp_enabled: false,
        user_missing: true
      });
    }
    res.json({
      pin_set: !!u.pin_hash,
      app_lock_enabled: !!u.app_lock_enabled,
      app_lock_timeout_min: u.app_lock_timeout_min || 0,
      chat_lock_enabled: !!u.chat_lock_enabled,
      locked_chats: Array.isArray(u.locked_chats) ? u.locked_chats : [],
      totp_enabled: !!u.totp_enabled
    });
  } catch(e){ console.error('lock/status error:', e && e.message); res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/lock/settings', auth, async (req, res) => {
  try {
    const { app_lock_enabled, app_lock_timeout_min, chat_lock_enabled } = req.body;
    const sets=[], vals=[]; let i=1;
    if (app_lock_enabled !== undefined) { sets.push('app_lock_enabled=$' + (i++)); vals.push(!!app_lock_enabled); }
    if (app_lock_timeout_min !== undefined) { sets.push('app_lock_timeout_min=$' + (i++)); vals.push(Number(app_lock_timeout_min) || 0); }
    if (chat_lock_enabled !== undefined) { sets.push('chat_lock_enabled=$' + (i++)); vals.push(!!chat_lock_enabled); }
    if (!sets.length) return res.json({ ok: true });
    vals.push(req.user.id);
    const r = await pool.query('UPDATE users SET ' + sets.join(', ') + ' WHERE id=$' + i + ' RETURNING pin_hash, app_lock_enabled, app_lock_timeout_min, chat_lock_enabled, locked_chats', vals);
    const u = r.rows[0];
    res.json({
      pin_set: !!u.pin_hash,
      app_lock_enabled: !!u.app_lock_enabled,
      app_lock_timeout_min: u.app_lock_timeout_min || 0,
      chat_lock_enabled: !!u.chat_lock_enabled,
      locked_chats: Array.isArray(u.locked_chats) ? u.locked_chats : []
    });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/chats/:id/lock', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, req.user.id]);
    if (!mem.rowCount) return res.status(403).json({ error: 'Not a member' });
    const r = await pool.query('SELECT locked_chats FROM users WHERE id=$1', [req.user.id]);
    let list = Array.isArray(r.rows[0].locked_chats) ? r.rows[0].locked_chats.map(Number) : [];
    const has = list.includes(chatId);
    const next = has ? list.filter(function(x){ return x !== chatId; }) : list.concat([chatId]);
    await pool.query('UPDATE users SET locked_chats=$1::jsonb, chat_lock_enabled=$2 WHERE id=$3', [JSON.stringify(next), next.length > 0, req.user.id]);
    res.json({ locked: !has, locked_chats: next });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- WEBAUTHN BIOMETRIC ---------- */
const RP_NAME = 'GistApp';
function getRpId(req){
  try {
    const origin = req.headers.origin || req.headers.referer || '';
    const u = new URL(origin);
    return u.hostname;
  } catch(_){ return 'localhost'; }
}
function getOrigin(req){
  return req.headers.origin || ('http://' + getRpId(req));
}

app.post('/api/webauthn/register-start', auth, async (req, res) => {
  try {
    const me = await pool.query('SELECT id, email, display_name, webauthn_credentials FROM users WHERE id=$1', [req.user.id]);
    const u = me.rows[0];
    const existing = Array.isArray(u.webauthn_credentials) ? u.webauthn_credentials : [];
    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: getRpId(req),
      userID: Buffer.from(String(u.id)),
      userName: u.email,
      userDisplayName: u.display_name || u.email,
      attestationType: 'none',
      excludeCredentials: existing.map(function(c){ return { id: c.credentialID }; }),
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'preferred',
        residentKey: 'discouraged'
      }
    });
    await pool.query('UPDATE users SET webauthn_challenge=$1 WHERE id=$2', [options.challenge, req.user.id]);
    res.json(options);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/webauthn/register-finish', auth, async (req, res) => {
  try {
    const me = await pool.query('SELECT webauthn_challenge, webauthn_credentials FROM users WHERE id=$1', [req.user.id]);
    const expectedChallenge = me.rows[0].webauthn_challenge;
    if (!expectedChallenge) return res.status(400).json({ error: 'No challenge' });
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: getOrigin(req),
      expectedRPID: getRpId(req),
      requireUserVerification: false
    });
    if (!verification.verified) return res.status(400).json({ error: 'Verification failed' });
    const info = verification.registrationInfo;
    const cred = {
      credentialID: info.credentialID || info.credential?.id,
      credentialPublicKey: Buffer.from(info.credentialPublicKey || info.credential?.publicKey).toString('base64'),
      counter: info.counter || info.credential?.counter || 0,
      createdAt: new Date().toISOString()
    };
    let list = Array.isArray(me.rows[0].webauthn_credentials) ? me.rows[0].webauthn_credentials : [];
    list.push(cred);
    await pool.query('UPDATE users SET webauthn_credentials=$1::jsonb, webauthn_challenge=NULL WHERE id=$2', [JSON.stringify(list), req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: e.message || 'Server error' }); }
});

app.post('/api/webauthn/auth-start', auth, async (req, res) => {
  try {
    const me = await pool.query('SELECT webauthn_credentials FROM users WHERE id=$1', [req.user.id]);
    const list = Array.isArray(me.rows[0].webauthn_credentials) ? me.rows[0].webauthn_credentials : [];
    if (!list.length) return res.status(400).json({ error: 'No biometric enrolled' });
    const options = await generateAuthenticationOptions({
      rpID: getRpId(req),
      allowCredentials: list.map(function(c){ return { id: c.credentialID }; }),
      userVerification: 'preferred'
    });
    await pool.query('UPDATE users SET webauthn_challenge=$1 WHERE id=$2', [options.challenge, req.user.id]);
    res.json(options);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/webauthn/auth-finish', auth, async (req, res) => {
  try {
    const me = await pool.query('SELECT webauthn_challenge, webauthn_credentials FROM users WHERE id=$1', [req.user.id]);
    const expectedChallenge = me.rows[0].webauthn_challenge;
    const list = Array.isArray(me.rows[0].webauthn_credentials) ? me.rows[0].webauthn_credentials : [];
    const credentialId = req.body.id;
    const stored = list.find(function(c){ return c.credentialID === credentialId; });
    if (!stored) return res.status(400).json({ error: 'Credential not found' });
    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: getOrigin(req),
      expectedRPID: getRpId(req),
      credential: {
        id: stored.credentialID,
        publicKey: Buffer.from(stored.credentialPublicKey, 'base64'),
        counter: stored.counter || 0
      },
      requireUserVerification: false
    });
    if (!verification.verified) return res.status(401).json({ error: 'Biometric failed' });
    // update counter
    stored.counter = verification.authenticationInfo.newCounter;
    await pool.query('UPDATE users SET webauthn_credentials=$1::jsonb, webauthn_challenge=NULL WHERE id=$2', [JSON.stringify(list), req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: e.message || 'Server error' }); }
});

app.post('/api/webauthn/remove', auth, async (req, res) => {
  try {
    await pool.query('UPDATE users SET webauthn_credentials=$1::jsonb WHERE id=$2', [JSON.stringify([]), req.user.id]);
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

/* ---------- PIN RESET VIA EMAIL ---------- */
function makeNumericCode(len){
  let out = '';
  for (let i=0;i<len;i++) out += Math.floor(Math.random()*10);
  return out;
}

app.post('/api/lock/request-reset', auth, async (req, res) => {
  try {
    const me = await pool.query('SELECT email, display_name, totp_enabled FROM users WHERE id=$1', [req.user.id]);
    if (!me.rowCount) return res.status(400).json({ error: 'No user' });
    const u = me.rows[0];
    const code = makeNumericCode(6);
    const hash = await bcrypt.hash(code, 10);
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 min
    await pool.query('UPDATE users SET reset_code_hash=$1, reset_code_expires=$2 WHERE id=$3', [hash, expires, req.user.id]);

    const baseUrl = process.env.APP_URL || 'http://localhost:4000';
    try {
      await mailer.sendMail({
        from: '"GistApp" <' + process.env.SMTP_USER + '>',
        to: u.email,
        subject: 'GistApp PIN reset code',
        html: '<div style="font-family:Inter,sans-serif;max-width:480px;margin:0 auto;padding:28px;background:#f7f5ff;border-radius:20px">' +
          '<h2 style="color:#1c1c22;margin:0 0 12px">Reset your PIN</h2>' +
          '<p style="color:#4a4568;font-size:14px;line-height:1.6">Your 6-digit code is:</p>' +
          '<div style="font-size:32px;font-weight:800;letter-spacing:8px;color:#7b8cff;background:#fff;padding:16px;border-radius:14px;text-align:center;margin:16px 0">' + code + '</div>' +
          '<p style="color:#8e8e93;font-size:12.5px">Code expires in 10 minutes. If you didn\'t request this, ignore this email.</p>' +
          '</div>'
      });
      res.json({ ok: true, sent_to: u.email.replace(/^(..).*(@.*)$/, '$1***$2'), totp_enabled: !!u.totp_enabled });
    } catch(mailErr){
      console.error('Reset code email failed', mailErr.message);
      res.status(500).json({ error: 'Could not send email' });
    }
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/lock/verify-reset', auth, async (req, res) => {
  try {
    const { code, new_pin } = req.body;
    if (!/^\d{4}$/.test(String(new_pin||''))) return res.status(400).json({ error: 'New PIN must be 4 digits' });
    const me = await pool.query('SELECT reset_code_hash, reset_code_expires FROM users WHERE id=$1', [req.user.id]);
    const u = me.rows[0];
    if (!u.reset_code_hash || !u.reset_code_expires) return res.status(400).json({ error: 'No reset requested' });
    if (new Date(u.reset_code_expires) < new Date()) return res.status(400).json({ error: 'Code expired' });
    const ok = await bcrypt.compare(String(code||''), u.reset_code_hash);
    if (!ok) return res.status(401).json({ error: 'Incorrect code' });
    const hash = await bcrypt.hash(String(new_pin), 10);
    await pool.query('UPDATE users SET pin_hash=$1, reset_code_hash=NULL, reset_code_expires=NULL, pin_attempts=0, pin_lockout_until=NULL WHERE id=$2', [hash, req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- UNIFIED RESET ACTION ---------- */
app.post('/api/lock/reset-action', auth, async (req, res) => {
  try {
    const { method, code, action, new_pin, new_password } = req.body;
    if (!method || !code || !action) return res.status(400).json({ error: 'Missing fields' });
    const me = await pool.query('SELECT totp_secret, totp_enabled, reset_code_hash, reset_code_expires, password_hash FROM users WHERE id=$1', [req.user.id]);
    const u = me.rows[0];
    let verified = false;

    if (method === 'totp'){
      if (!u.totp_enabled || !u.totp_secret) return res.status(400).json({ error: '2FA not enabled' });
      try { verified = speakeasy.totp.verify({ secret: u.totp_secret, encoding:'base32', token: String(code).trim(), window: 1 }); } catch(_){}
    } else if (method === 'email'){
      if (!u.reset_code_hash || !u.reset_code_expires) return res.status(400).json({ error: 'Request a code first' });
      if (new Date(u.reset_code_expires) < new Date()) return res.status(400).json({ error: 'Code expired' });
      verified = await bcrypt.compare(String(code).trim(), u.reset_code_hash);
    }
    if (!verified) return res.status(401).json({ error: 'Invalid code' });

    if (action === 'set_pin'){
      if (!/^\d{4}$/.test(String(new_pin||''))) return res.status(400).json({ error: 'PIN must be 4 digits' });
      const hash = await bcrypt.hash(String(new_pin), 10);
      await pool.query('UPDATE users SET pin_hash=$1, pin_attempts=0, pin_lockout_until=NULL, reset_code_hash=NULL, reset_code_expires=NULL WHERE id=$2', [hash, req.user.id]);
      return res.json({ ok: true, message: 'PIN updated' });
    }
    if (action === 'set_password'){
      if (!new_password || String(new_password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
      const hash = await bcrypt.hash(String(new_password), 10);
      await pool.query('UPDATE users SET password_hash=$1, reset_code_hash=NULL, reset_code_expires=NULL WHERE id=$2', [hash, req.user.id]);
      return res.json({ ok: true, message: 'Password updated' });
    }
    if (action === 'disable_lock'){
      await pool.query('UPDATE users SET app_lock_enabled=false, pin_hash=NULL, pin_attempts=0, pin_lockout_until=NULL, reset_code_hash=NULL, reset_code_expires=NULL WHERE id=$1', [req.user.id]);
      return res.json({ ok: true, message: 'App lock disabled' });
    }
    res.status(400).json({ error: 'Unknown action' });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ================= PASSWORD RESET ================= */
app.post('/api/pw-reset/request', pwResetLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').toLowerCase().trim();
    if (!email) return res.status(400).json({ error: 'Email required' });
    const r = await pool.query('SELECT id, display_name FROM users WHERE email=$1', [email]);
    if (!r.rowCount) return res.json({ ok: true });
    const u = r.rows[0];
    const token = makeToken();
    const expires = new Date(Date.now() + 30 * 60 * 1000);
    await pool.query('UPDATE users SET pw_reset_token=$1, pw_reset_expires=$2 WHERE id=$3', [token, expires, u.id]);
    const baseUrl = process.env.APP_URL || 'http://localhost:4000';
    const link = baseUrl + '/reset-password?token=' + token;
    try {
      await mailer.sendMail({
        from: '"GistApp" <' + process.env.SMTP_USER + '>',
        to: email,
        subject: 'Reset your GistApp password',
        html: '<p>Hi ' + (u.display_name || 'there') + ',</p><p>Reset your password: <a href="' + link + '">' + link + '</a></p><p>Link expires in 30 minutes.</p>'
      });
    } catch(_){}
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/reset-password', async (req, res) => {
  const token = String(req.query.token || '').trim();
  if (!token) return res.status(400).send('<h2>Missing token</h2>');
  const r = await pool.query('SELECT id FROM users WHERE pw_reset_token=$1 AND pw_reset_expires > NOW()', [token]);
  if (!r.rowCount) return res.send('<html><body style="font-family:sans-serif;text-align:center;padding:60px;background:#050505;color:#fff"><h2 style="color:#ff453a">Link expired</h2><a href="/" style="color:#7b8cff">Back to app</a></body></html>');
  const safeToken = JSON.stringify(token);
  res.send('<html><head><meta name=viewport content="width=device-width,initial-scale=1"><style>body{font-family:Inter,sans-serif;background:#050505;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}.c{background:#fff;color:#1c1c22;max-width:400px;width:100%;padding:32px 24px;border-radius:24px;box-shadow:0 20px 60px rgba(0,0,0,.5);box-sizing:border-box}h2{margin:0 0 8px;font-size:22px}p{color:#8e8e96;margin:0 0 20px;font-size:14px}input{width:100%;height:50px;border-radius:14px;border:1.5px solid #e8e5f0;background:#faf9fd;padding:0 16px;font-size:15px;margin-bottom:12px;box-sizing:border-box;outline:none}button{width:100%;height:52px;background:#14141a;color:#fff;border:none;border-radius:16px;font-size:15px;font-weight:700;cursor:pointer}.e{color:#e5484d;font-size:13px;min-height:18px;font-weight:600;margin-bottom:6px}</style></head><body><div class=c><h2>Set a new password</h2><p>Minimum 6 characters.</p><div class=e id=e></div><input id=p1 type=password placeholder="New password"><input id=p2 type=password placeholder="Confirm password"><button onclick="save()">Save password</button></div><script>async function save(){var e=document.getElementById("e");e.textContent="";var p1=document.getElementById("p1").value;var p2=document.getElementById("p2").value;if(p1.length<6){e.textContent="Password must be at least 6 characters";return}if(p1!==p2){e.textContent="Passwords do not match";return}try{const r=await fetch("/api/pw-reset/complete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:' + safeToken + ',password:p1})});const j=await r.json();if(!r.ok)throw new Error(j.error||"Failed");document.body.innerHTML="<div style=font-family:Inter;background:#050505;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;padding:20px><div><div style=font-size:60px>OK</div><h2>Password updated</h2><a href=/ style=color:#7b8cff>Open GistApp</a></div></div>"}catch(err){e.textContent=err.message}}</script></body></html>');
});

app.post('/api/pw-reset/complete', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password || password.length < 6) return res.status(400).json({ error: 'Invalid input' });
    const r = await pool.query('SELECT id FROM users WHERE pw_reset_token=$1 AND pw_reset_expires > NOW()', [token]);
    if (!r.rowCount) return res.status(400).json({ error: 'Token expired or invalid' });
    const hash = await bcrypt.hash(String(password), 10);
    await pool.query('UPDATE users SET password_hash=$1, pw_reset_token=NULL, pw_reset_expires=NULL WHERE id=$2', [hash, r.rows[0].id]);
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

/* ================= GROUP ADMIN ================= */
app.post('/api/chats/:id/members/add', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const me = await pool.query("SELECT is_admin FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='accepted'", [chatId, req.user.id]);
    if (!me.rowCount || !me.rows[0].is_admin) return res.status(403).json({ error: 'Only admins can add members' });
    const email = String(req.body.email || '').toLowerCase().trim();
    const u = await pool.query('SELECT id, display_name FROM users WHERE email=$1', [email]);
    if (!u.rowCount) return res.status(404).json({ error: 'No user with that email' });
    const uid = u.rows[0].id;
    const existing = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, uid]);
    if (existing.rowCount) return res.status(409).json({ error: 'Already a member' });
    await pool.query("INSERT INTO chat_members (chat_id,user_id,status) VALUES ($1,$2,'pending')", [chatId, uid]);
    io.to('user:' + uid).emit('requests-changed');
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/chats/:id/members/remove', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const me = await pool.query("SELECT is_admin FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='accepted'", [chatId, req.user.id]);
    if (!me.rowCount || !me.rows[0].is_admin) return res.status(403).json({ error: 'Only admins can remove' });
    const uid = Number(req.body.user_id);
    if (uid === req.user.id) return res.status(400).json({ error: 'Use Leave group instead' });
    await pool.query('DELETE FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, uid]);
    io.to('user:' + uid).emit('chats-changed');
    io.to('chat:' + chatId).emit('chats-changed');
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/chats/:id/members/promote', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const me = await pool.query("SELECT is_admin FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='accepted'", [chatId, req.user.id]);
    if (!me.rowCount || !me.rows[0].is_admin) return res.status(403).json({ error: 'Only admins' });
    await pool.query('UPDATE chat_members SET is_admin=true WHERE chat_id=$1 AND user_id=$2', [chatId, Number(req.body.user_id)]);
    io.to('chat:' + chatId).emit('chats-changed');
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/chats/:id/members/demote', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const me = await pool.query("SELECT is_admin FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='accepted'", [chatId, req.user.id]);
    if (!me.rowCount || !me.rows[0].is_admin) return res.status(403).json({ error: 'Only admins' });
    await pool.query('UPDATE chat_members SET is_admin=false WHERE chat_id=$1 AND user_id=$2', [chatId, Number(req.body.user_id)]);
    io.to('chat:' + chatId).emit('chats-changed');
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/chats/:id/members', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const ok = await pool.query("SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='accepted'", [chatId, req.user.id]);
    if (!ok.rowCount) return res.status(403).json({ error: 'Not a member' });
    const r = await pool.query("SELECT u.id, u.display_name, u.email, u.avatar_color, u.avatar_url, m.is_admin, m.status FROM chat_members m JOIN users u ON u.id=m.user_id WHERE m.chat_id=$1 ORDER BY m.is_admin DESC, u.display_name ASC", [chatId]);
    res.json(r.rows);
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/chats/:id/leave', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    await pool.query('DELETE FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, req.user.id]);
    const others = await pool.query('SELECT user_id FROM chat_members WHERE chat_id=$1', [chatId]);
    others.rows.forEach(function(row){ io.to('user:' + row.user_id).emit('chats-changed'); });
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/chats/:id/info', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const me = await pool.query("SELECT is_admin FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='accepted'", [chatId, req.user.id]);
    if (!me.rowCount || !me.rows[0].is_admin) return res.status(403).json({ error: 'Only admins' });
    const { name, description, icon_emoji } = req.body;
    const sets = []; const vals = []; let i = 1;
    if (name !== undefined){ sets.push('name=$' + (i++)); vals.push(String(name).trim().slice(0, 80)); }
    if (description !== undefined){ sets.push('description=$' + (i++)); vals.push(String(description).slice(0, 500)); }
    if (icon_emoji !== undefined){ sets.push('icon_emoji=$' + (i++)); vals.push(String(icon_emoji).slice(0, 8)); }
    if (!sets.length) return res.json({ ok: true });
    vals.push(chatId);
    await pool.query('UPDATE chats SET ' + sets.join(', ') + ' WHERE id=$' + i, vals);
    io.to('chat:' + chatId).emit('chats-changed');
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

/* ================= GLOBAL MESSAGE SEARCH ================= */
app.get('/api/search/messages', auth, async (req, res) => {
  try {
    const q = String(req.query.q || '').trim();
    if (!q || q.length < 2) return res.json([]);
    const r = await pool.query("SELECT m.id, m.chat_id, m.body, m.created_at, m.media_url, m.media_type, u.display_name AS sender_name, u.avatar_color AS sender_color, u.avatar_url AS sender_url, c.type AS chat_type, c.name AS chat_name FROM messages m JOIN chat_members cm ON cm.chat_id=m.chat_id AND cm.user_id=$1 AND cm.status='accepted' JOIN users u ON u.id=m.sender_id JOIN chats c ON c.id=m.chat_id WHERE m.deleted_at IS NULL AND LOWER(m.body) LIKE $2 ORDER BY m.created_at DESC LIMIT 80", [req.user.id, '%' + q.toLowerCase() + '%']);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ================= EDIT POST ================= */
app.patch('/api/posts/:id', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const p = await pool.query('SELECT user_id FROM posts WHERE id=$1', [id]);
    if (!p.rowCount) return res.status(404).json({ error: 'Not found' });
    if (p.rows[0].user_id !== req.user.id) return res.status(403).json({ error: 'Not yours' });
    const body = String(req.body.body || '').trim().slice(0, 1000);
    await pool.query('UPDATE posts SET body=$1, edited_at=NOW() WHERE id=$2', [body, id]);
    io.emit('feed-update-post', { id: id, body: body });
    res.json({ ok: true, body: body });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

/* ================= SHARE / REPOST ================= */
app.post('/api/posts/:id/share', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const orig = await pool.query('SELECT body, media_url, media_type, user_id FROM posts WHERE id=$1', [id]);
    if (!orig.rowCount) return res.status(404).json({ error: 'Not found' });
    await pool.query('INSERT INTO post_shares (post_id,user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [id, req.user.id]);
    const caption = String(req.body.caption || '').trim().slice(0, 500);
    const r = await pool.query('INSERT INTO posts (user_id, body, original_post_id) VALUES ($1,$2,$3) RETURNING id, created_at', [req.user.id, caption, id]);
    io.emit('feed-new-post', { id: r.rows[0].id });
    res.json({ ok: true, id: r.rows[0].id });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ================= FOLLOW / FOLLOWERS ================= */
app.post('/api/users/:id/follow', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (id === req.user.id) return res.status(400).json({ error: 'Cannot follow yourself' });
    const has = await pool.query('SELECT 1 FROM user_follows WHERE follower_id=$1 AND following_id=$2', [req.user.id, id]);
    if (has.rowCount){
      await pool.query('DELETE FROM user_follows WHERE follower_id=$1 AND following_id=$2', [req.user.id, id]);
      res.json({ following: false });
    // GISTAPP_WEBPUSH_V1 — notify target of new follow
    try {
      const u = await pool.query('SELECT display_name FROM users WHERE id=$1', [req.user.id]);
      sendPush(id, '👤 New follower', (u.rows[0] && u.rows[0].display_name) + ' started following you', { url: '/?user=' + req.user.id }).catch(()=>{});
    } catch(_){}

    } else {
      await pool.query('INSERT INTO user_follows (follower_id, following_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, id]);
      res.json({ following: true });
    }
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});



/* ---------- /verify (email verification link) ---------- */
app.get('/verify', async (req, res) => {
  const token = String(req.query.token || '').trim();
  if (!token) return res.status(400).send('<h2>Missing token</h2>');
  try {
    const r = await pool.query('SELECT id, email, display_name FROM users WHERE verify_token=$1 AND verify_expires > NOW()', [token]);
    if (!r.rowCount) {
      return res.send('<html><body style="font-family:Inter,system-ui,sans-serif;background:#050505;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;padding:20px"><div style="background:#fff;color:#1c1c22;max-width:400px;padding:40px 30px;border-radius:24px;box-shadow:0 20px 60px rgba(0,0,0,.5)"><div style="font-size:56px;margin-bottom:10px">\u26A0\uFE0F</div><h2 style="margin:0 0 10px;color:#e5484d">Link expired</h2><p style="color:#8e8e96;font-size:14px;line-height:1.5">This verification link is invalid or has already been used.</p><a href="/" style="color:#7b8cff;font-weight:700;margin-top:20px;display:inline-block">Back to app</a></div></body></html>');
    }
    await pool.query('UPDATE users SET verified=true, verify_token=NULL, verify_expires=NULL WHERE id=$1', [r.rows[0].id]);
    // GISTAPP_WELCOME_EMAIL — fire and forget, do not block the response
    sendWelcomeEmail(r.rows[0].email, r.rows[0].display_name).catch(function(e){ console.warn('welcome email failed:', e && e.message); });
    // GISTAPP_VERIFY_AUTOLOGIN — sign fresh JWT, inject into localStorage, redirect to app
    // Fixes the case where the verify link opens in a different browser context (e.g. Gmail in-app)
    try {
      const _full = await pool.query('SELECT * FROM users WHERE id=$1', [r.rows[0].id]);
      if (_full.rowCount){
        const _sid = await rotateUserSession(r.rows[0].id);
        const _u = Object.assign({}, _full.rows[0], { session_id: _sid });
        const _jwt = sign(_u);
        const _safeTok = JSON.stringify(_jwt);
        const _name = r.rows[0].display_name || '';
        const _html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Email verified</title><style>body{font-family:Inter,-apple-system,system-ui,sans-serif;background:#050505;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;padding:20px}.c{background:#fff;color:#1c1c22;max-width:400px;width:100%;padding:40px 30px;border-radius:24px;box-shadow:0 20px 60px rgba(0,0,0,.5);box-sizing:border-box}.spin{width:32px;height:32px;border:3px solid #e6e5f0;border-top-color:#7b8cff;border-radius:50%;animation:s 0.9s linear infinite;margin:16px auto 0}@keyframes s{to{transform:rotate(360deg)}}</style></head><body><div class="c"><div style="font-size:56px;margin-bottom:10px">\u2705</div><h2 style="margin:0 0 10px">Email verified!</h2><p style="color:#8e8e96;font-size:14px;line-height:1.5;margin:0">Welcome, ' + _name + '. Taking you to setup\u2026</p><div class="spin"></div></div><script>(function(){try{var t=' + _safeTok + ';localStorage.setItem("token",t);}catch(e){}setTimeout(function(){location.replace("/")},800);})();</script></body></html>';
        return res.send(_html);
      }
    } catch(_autologErr){
      console.warn('verify autologin failed:', _autologErr && _autologErr.message);
    }
  } catch(e){ console.error(e); res.status(500).send('<h2>Verification failed</h2>'); }
});

/* ---------- BLOCKS LIST ---------- */
app.get('/api/blocks', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT blocked_ids FROM users WHERE id=$1', [req.user.id]);
    const ids = (r.rows[0].blocked_ids || []).map(Number);
    if (!ids.length) return res.json([]);
    const u = await pool.query('SELECT id, display_name, email, avatar_color, avatar_url FROM users WHERE id = ANY($1)', [ids]);
    res.json(u.rows);
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});


/* ---------- WHATSAPP-STYLE CHAT ACTIONS ---------- */
app.post('/api/chats/:id/pin', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query('SELECT pinned FROM chat_members WHERE chat_id=$1 AND user_id=$2', [id, req.user.id]);
    if (!r.rowCount) return res.status(403).json({ error: 'Not a member' });
    const next = !r.rows[0].pinned;
    // Limit 3 pins
    if (next){
      const c = await pool.query('SELECT COUNT(*) FROM chat_members WHERE user_id=$1 AND pinned=true', [req.user.id]);
      if (Number(c.rows[0].count) >= 3) return res.status(400).json({ error: 'Max 3 pinned chats' });
    }
    await pool.query('UPDATE chat_members SET pinned=$1 WHERE chat_id=$2 AND user_id=$3', [next, id, req.user.id]);
    res.json({ pinned: next });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/chats/:id/unread', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query('SELECT unread FROM chat_members WHERE chat_id=$1 AND user_id=$2', [id, req.user.id]);
    if (!r.rowCount) return res.status(403).json({ error: 'Not a member' });
    const next = !r.rows[0].unread;
    await pool.query('UPDATE chat_members SET unread=$1 WHERE chat_id=$2 AND user_id=$3', [next, id, req.user.id]);
    res.json({ unread: next });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/chats/:id/mute', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { duration } = req.body; // '8h' | '1w' | 'always' | 'off'
    let until = null;
    if (duration === '8h') until = new Date(Date.now() + 8*3600*1000);
    else if (duration === '1w') until = new Date(Date.now() + 7*24*3600*1000);
    else if (duration === 'always') until = new Date('2100-01-01');
    else until = null;
    await pool.query('UPDATE chat_members SET muted=$1, mute_until=$2 WHERE chat_id=$3 AND user_id=$4',
      [!!until, until, id, req.user.id]);
    res.json({ muted: !!until, mute_until: until });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/chats/:id/messages', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [id, req.user.id]);
    if (!mem.rowCount) return res.status(403).json({ error: 'Not a member' });
    await pool.query('DELETE FROM messages WHERE chat_id=$1', [id]);
    io.to('chat:' + id).emit('chats-changed');
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

/* ---------- STAR / PIN MESSAGES ---------- */
app.patch('/api/messages/:id/star', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const m = await pool.query('SELECT chat_id, starred_by FROM messages WHERE id=$1', [id]);
    if (!m.rowCount) return res.status(404).json({ error: 'Not found' });
    const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [m.rows[0].chat_id, req.user.id]);
    if (!mem.rowCount) return res.status(403).json({ error: 'Not a member' });
    const list = Array.isArray(m.rows[0].starred_by) ? m.rows[0].starred_by : [];
    const has = list.indexOf(req.user.id) !== -1;
    const next = has ? list.filter(function(x){ return x !== req.user.id; }) : list.concat([req.user.id]);
    await pool.query('UPDATE messages SET starred_by=$1 WHERE id=$2', [JSON.stringify(next), id]);
    res.json({ starred: !has });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/messages/:id/pin', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const m = await pool.query('SELECT chat_id, pinned FROM messages WHERE id=$1', [id]);
    if (!m.rowCount) return res.status(404).json({ error: 'Not found' });
    const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [m.rows[0].chat_id, req.user.id]);
    if (!mem.rowCount) return res.status(403).json({ error: 'Not a member' });
    const next = !m.rows[0].pinned;
    await pool.query('UPDATE messages SET pinned=$1 WHERE id=$2', [next, id]);
    io.to('chat:' + m.rows[0].chat_id).emit('message-pinned', { id: id, pinned: next });
    res.json({ pinned: next });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/messages/:id/forward', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { to_chat } = req.body;
    const src = await pool.query('SELECT body, media_url, media_type FROM messages WHERE id=$1', [id]);
    if (!src.rowCount) return res.status(404).json({ error: 'Not found' });
    const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [to_chat, req.user.id]);
    if (!mem.rowCount) return res.status(403).json({ error: 'Not a member of target' });
    const r = await pool.query(
      'INSERT INTO messages (chat_id, sender_id, body, media_url, media_type) VALUES ($1,$2,$3,$4,$5) RETURNING id, body, created_at, sender_id, media_url, media_type',
      [to_chat, req.user.id, src.rows[0].body, src.rows[0].media_url, src.rows[0].media_type]
    );
    const u = await pool.query('SELECT display_name, avatar_color FROM users WHERE id=$1', [req.user.id]);
    const full = Object.assign({}, r.rows[0], { display_name: u.rows[0].display_name, avatar_color: u.rows[0].avatar_color, chat_id: to_chat });
    io.to('chat:' + to_chat).emit('message', full);
    res.json(full);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- Custom notifications + media visibility on chat_members ---------- */
app.patch('/api/chats/:id/prefs', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { custom_notif, media_visible } = req.body;
    const sets = []; const vals = []; let i = 1;
    if (custom_notif !== undefined){ sets.push('custom_notif=$' + (i++)); vals.push(!!custom_notif); }
    if (media_visible !== undefined){ sets.push('media_visible=$' + (i++)); vals.push(!!media_visible); }
    if (!sets.length) return res.json({ ok: true });
    vals.push(id); vals.push(req.user.id);
    await pool.query('UPDATE chat_members SET ' + sets.join(', ') + ' WHERE chat_id=$' + i + ' AND user_id=$' + (i+1), vals);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});


/* ---------- USER PROFILE with visibility enforcement ---------- */
app.get('/api/users/:id/profile', auth, async (req, res) => {
  try {
    const uid = Number(req.params.id);
    const r = await pool.query('SELECT id, display_name, username, email, avatar_color, avatar_url, cover_url, bio, last_seen_at, prefs FROM users WHERE id=$1', [uid]);
    if (!r.rowCount) return res.status(404).json({ error: 'Not found' });
    const u = r.rows[0];
    const out = {
      id: u.id,
      display_name: u.display_name,
      username: u.username,
      avatar_color: u.avatar_color
    };
    // Avatar
    if (Number(req.user.id) === uid || await canViewField(req.user.id, uid, 'profile_photo')) out.avatar_url = u.avatar_url;
    // Cover
    if (Number(req.user.id) === uid || await canViewField(req.user.id, uid, 'profile_photo')) out.cover_url = u.cover_url;
    // Bio / About
    if (Number(req.user.id) === uid || await canViewField(req.user.id, uid, 'about')) out.bio = u.bio;
    // Email — only to self
    if (Number(req.user.id) === uid) out.email = u.email;
    // Last seen
    if (Number(req.user.id) === uid || await canViewField(req.user.id, uid, 'last_seen')) out.last_seen_at = u.last_seen_at;

    res.json(out);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});



/* ---------- COMMUNITIES ---------- */
app.get('/api/communities', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT c.id, c.slug, c.name, c.description, c.emoji, c.category,
        (SELECT COUNT(*) FROM community_members WHERE community_id=c.id) AS member_count,
        EXISTS(SELECT 1 FROM community_members WHERE community_id=c.id AND user_id=$1) AS joined
      FROM communities c
      ORDER BY c.category ASC, c.name ASC
    `, [req.user.id]);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: e.message }); }
});

app.get('/api/communities/mine', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT c.id, c.slug, c.name, c.description, c.emoji, c.category,
        (SELECT COUNT(*) FROM community_members WHERE community_id=c.id) AS member_count
      FROM communities c
      JOIN community_members m ON m.community_id=c.id AND m.user_id=$1
      ORDER BY c.name ASC
    `, [req.user.id]);
    res.json(r.rows);
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/communities/:id/toggle', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const has = await pool.query('SELECT 1 FROM community_members WHERE community_id=$1 AND user_id=$2', [id, req.user.id]);
    if (has.rowCount){
      await pool.query('DELETE FROM community_members WHERE community_id=$1 AND user_id=$2', [id, req.user.id]);
      return res.json({ joined: false });
    }
    await pool.query('INSERT INTO community_members (community_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [id, req.user.id]);
    res.json({ joined: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- USER LIKE / STATS ---------- */
app.post('/api/users/:id/like', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (id === req.user.id) return res.status(400).json({ error: 'Cannot like yourself' });
    const has = await pool.query('SELECT 1 FROM user_likes WHERE liker_id=$1 AND liked_id=$2', [req.user.id, id]);
    if (has.rowCount){
      await pool.query('DELETE FROM user_likes WHERE liker_id=$1 AND liked_id=$2', [req.user.id, id]);
      return res.json({ liked: false });
    }
    await pool.query('INSERT INTO user_likes (liker_id, liked_id) VALUES ($1,$2)', [req.user.id, id]);
    res.json({ liked: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/users/:id/stats', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const followers = await pool.query('SELECT COUNT(*) FROM user_follows WHERE following_id=$1', [id]);
    const following = await pool.query('SELECT COUNT(*) FROM user_follows WHERE follower_id=$1', [id]);
    const likes = await pool.query('SELECT COUNT(*) FROM user_likes WHERE liked_id=$1', [id]);
    const posts = await pool.query('SELECT COUNT(*) FROM posts WHERE user_id=$1 AND deleted_at IS NULL', [id]);
    const isFollowing = await pool.query('SELECT 1 FROM user_follows WHERE follower_id=$1 AND following_id=$2', [req.user.id, id]);
    const isLiked = await pool.query('SELECT 1 FROM user_likes WHERE liker_id=$1 AND liked_id=$2', [req.user.id, id]);
    res.json({
      followers: Number(followers.rows[0].count),
      following: Number(following.rows[0].count),
      likes: Number(likes.rows[0].count),
      posts: Number(posts.rows[0].count),
      is_following: isFollowing.rowCount > 0,
      is_liked: isLiked.rowCount > 0
    });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});


app.get('/api/users/suggested', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT id, display_name, username, avatar_color, avatar_url
      FROM users
      WHERE id <> $1
      ORDER BY created_at DESC
      LIMIT 30
    `, [req.user.id]);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});


/* ---------- FOLLOWERS / FOLLOWING / LIKES LISTS ---------- */
app.get('/api/users/:id/followers', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query(`
      SELECT u.id, u.display_name, u.username, u.avatar_color, u.avatar_url, f.created_at
      FROM user_follows f JOIN users u ON u.id = f.follower_id
      WHERE f.following_id = $1
      ORDER BY f.created_at DESC LIMIT 200
    `, [id]);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/users/:id/following', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query(`
      SELECT u.id, u.display_name, u.username, u.avatar_color, u.avatar_url, f.created_at
      FROM user_follows f JOIN users u ON u.id = f.following_id
      WHERE f.follower_id = $1
      ORDER BY f.created_at DESC LIMIT 200
    `, [id]);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/users/:id/likers', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query(`
      SELECT u.id, u.display_name, u.username, u.avatar_color, u.avatar_url, l.created_at
      FROM user_likes l JOIN users u ON u.id = l.liker_id
      WHERE l.liked_id = $1
      ORDER BY l.created_at DESC LIMIT 200
    `, [id]);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- USER PROFILE with gender + counts ---------- */
app.get('/api/users/:id/profile-card', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query(`
      SELECT u.id, u.display_name, u.username, u.avatar_color, u.subscription_tier, u.avatar_url, u.cover_url, u.bio, u.gender,
        (SELECT COUNT(*) FROM user_follows WHERE following_id=u.id) AS followers,
        (SELECT COUNT(*) FROM user_follows WHERE follower_id=u.id) AS following,
        (SELECT COUNT(*) FROM user_likes WHERE liked_id=u.id) AS likes,
        (SELECT COUNT(*) FROM posts WHERE user_id=u.id AND deleted_at IS NULL) AS posts,
        EXISTS(SELECT 1 FROM user_follows WHERE follower_id=$2 AND following_id=u.id) AS is_following,
        EXISTS(SELECT 1 FROM user_likes WHERE liker_id=$2 AND liked_id=u.id) AS is_liked
      FROM users u WHERE u.id=$1
    `, [id, req.user.id]);
    if (!r.rowCount) return res.status(404).json({ error: 'Not found' });
    // GISTAPP_LIVE_BADGE_BE
      try { const _li = await getLiveUserIds(); r.rows[0].is_live = _li.has(Number(r.rows[0].id)); } catch(_){ r.rows[0].is_live = false; }
      res.json(r.rows[0]);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- profile insights ---------- GISTAPP_INSIGHTS_V1 */
app.post('/api/users/:id/view-profile', auth, async (req, res) => {
  try {
    const target = Number(req.params.id);
    if (!target || target === Number(req.user.id)) return res.json({ ok: true, skipped: true });
    // Avoid duplicate views within 1 hour from same viewer
    const existing = await pool.query(
      `SELECT 1 FROM profile_views WHERE viewer_id=$1 AND viewed_id=$2 AND viewed_at > NOW() - INTERVAL '1 hour'`,
      [req.user.id, target]
    );
    if (!existing.rowCount){
      await pool.query('INSERT INTO profile_views (viewer_id, viewed_id) VALUES ($1,$2)', [req.user.id, target]);
    }
    res.json({ ok: true });
  } catch(e){ console.error('view-profile:', e.message); res.json({ ok: false }); }
});

// GISTAPP_INSIGHTS_ME — same as :id/insights but uses JWT for id
app.get('/api/me/insights', auth, async (req, res) => {
  req.params.id = req.user.id;
  try {
    const uid = Number(req.user.id);
    const viewsTotal = await pool.query('SELECT COUNT(*)::int AS n FROM profile_views WHERE viewed_id=$1', [uid]);
    const views7d    = await pool.query("SELECT COUNT(*)::int AS n FROM profile_views WHERE viewed_id=$1 AND viewed_at > NOW() - INTERVAL '7 days'", [uid]);
    const likesTotal = await pool.query('SELECT COUNT(*)::int AS n FROM post_likes pl JOIN posts p ON p.id=pl.post_id WHERE p.user_id=$1 AND p.deleted_at IS NULL', [uid]);
    const followersTotal = await pool.query('SELECT COUNT(*)::int AS n FROM user_follows WHERE following_id=$1', [uid]);
    const topPosts = await pool.query(`
      SELECT p.id, p.body, p.media_url, p.media_type, p.created_at,
        (SELECT COUNT(*) FROM post_likes WHERE post_id=p.id)::int AS like_count,
        (SELECT COUNT(*) FROM post_comments WHERE post_id=p.id)::int AS comment_count
      FROM posts p
      WHERE p.user_id=$1 AND p.deleted_at IS NULL
      ORDER BY like_count DESC, p.created_at DESC
      LIMIT 3
    `, [uid]);
    const recentViewers = await pool.query(`
      SELECT DISTINCT ON (pv.viewer_id)
        u.id, u.display_name, u.username, u.avatar_color, u.avatar_url, pv.viewed_at
      FROM profile_views pv
      JOIN users u ON u.id = pv.viewer_id
      WHERE pv.viewed_id=$1
      ORDER BY pv.viewer_id, pv.viewed_at DESC
      LIMIT 10
    `, [uid]);
    recentViewers.rows.sort((a,b) => new Date(b.viewed_at) - new Date(a.viewed_at));
    res.json({
      views_total: viewsTotal.rows[0].n,
      views_7d: views7d.rows[0].n,
      likes_total: likesTotal.rows[0].n,
      followers_total: followersTotal.rows[0].n,
      top_posts: topPosts.rows,
      recent_viewers: recentViewers.rows
    });
  } catch(e){ console.error('me/insights:', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/users/:id/insights', auth, async (req, res) => {
  try {
    const uid = Number(req.params.id);
    if (!uid) return res.status(400).json({ error: 'Invalid id' });
    // Only self can view insights
    if (uid !== Number(req.user.id)) return res.status(403).json({ error: 'Not your profile' });

    // Total views + last 7 days
    const viewsTotal = await pool.query('SELECT COUNT(*)::int AS n FROM profile_views WHERE viewed_id=$1', [uid]);
    const views7d    = await pool.query("SELECT COUNT(*)::int AS n FROM profile_views WHERE viewed_id=$1 AND viewed_at > NOW() - INTERVAL '7 days'", [uid]);

    // Likes on my posts
    const likesTotal = await pool.query('SELECT COUNT(*)::int AS n FROM post_likes pl JOIN posts p ON p.id=pl.post_id WHERE p.user_id=$1 AND p.deleted_at IS NULL', [uid]);

    // Followers
    const followersTotal = await pool.query('SELECT COUNT(*)::int AS n FROM user_follows WHERE following_id=$1', [uid]);

    // Top 3 posts by likes
    const topPosts = await pool.query(`
      SELECT p.id, p.body, p.media_url, p.media_type, p.created_at,
        (SELECT COUNT(*) FROM post_likes WHERE post_id=p.id)::int AS like_count,
        (SELECT COUNT(*) FROM post_comments WHERE post_id=p.id)::int AS comment_count
      FROM posts p
      WHERE p.user_id=$1 AND p.deleted_at IS NULL
      ORDER BY like_count DESC, p.created_at DESC
      LIMIT 3
    `, [uid]);

    // Recent viewers (last 10 unique, most recent first)
    const recentViewers = await pool.query(`
      SELECT DISTINCT ON (pv.viewer_id)
        u.id, u.display_name, u.username, u.avatar_color, u.avatar_url, pv.viewed_at
      FROM profile_views pv
      JOIN users u ON u.id = pv.viewer_id
      WHERE pv.viewed_id=$1
      ORDER BY pv.viewer_id, pv.viewed_at DESC
      LIMIT 10
    `, [uid]);
    // Re-sort by viewed_at desc
    recentViewers.rows.sort((a,b) => new Date(b.viewed_at) - new Date(a.viewed_at));

    res.json({
      views_total: viewsTotal.rows[0].n,
      views_7d: views7d.rows[0].n,
      likes_total: likesTotal.rows[0].n,
      followers_total: followersTotal.rows[0].n,
      top_posts: topPosts.rows,
      recent_viewers: recentViewers.rows
    });
  } catch(e){ console.error('insights:', e.message); res.status(500).json({ error: 'Server error' }); }
});


/* ---------- STATUS view count for own statuses ---------- */
app.get('/api/statuses/mine/views', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT s.id, (SELECT COUNT(*) FROM status_views WHERE status_id=s.id) AS views
      FROM statuses s WHERE s.user_id=$1 AND s.expires_at > NOW()
    `, [req.user.id]);
    const total = r.rows.reduce(function(sum, row){ return sum + Number(row.views); }, 0);
    res.json({ total: total, per_status: r.rows });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});


/* ---------- USER SUGGESTIONS (for onboarding + "find friends") ---------- */
app.get('/api/users/suggestions', auth, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 30, 60);
    const r = await pool.query(`
      SELECT id, display_name, username, avatar_color, avatar_url, bio
      FROM users
      WHERE id <> $1
        AND onboarded = true
      ORDER BY last_seen_at DESC NULLS LAST, created_at DESC
      LIMIT $2
    `, [req.user.id, limit]);

    // Mark whether I already follow each
    const mine = await pool.query('SELECT follows FROM users WHERE id=$1', [req.user.id]);
    const follows = (mine.rows[0] && Array.isArray(mine.rows[0].follows)) ? mine.rows[0].follows : [];

    const out = r.rows.map(function(u){
      return {
        id: u.id,
        display_name: u.display_name,
        username: u.username,
        avatar_color: u.avatar_color,
        avatar_url: u.avatar_url,
        bio: u.bio,
        following: follows.indexOf('user_' + u.id) !== -1
      };
    });
    res.json(out);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- socket ---------- */
io.use((socket,next)=>{
  const token = socket.handshake.auth&&socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try { socket.user = jwt.verify(token,JWT_SECRET); next(); }
  catch { next(new Error('Bad token')); }
});
io.on('connection', socket=>{
  const uid = Number(socket.user.id);
  socket.join('user:'+uid);
  onlineUsers.set(uid,(onlineUsers.get(uid)||0)+1);
  io.emit('presence',{userId:uid,online:true});
  socket.emit('presence-list',[...onlineUsers.keys()]);
  socket.on('join',chatId=>socket.join('chat:'+chatId));
    // GISTAPP_PRESENCE_FIX — explicit presence fetch
    socket.on('request-presence', () => {
      try { socket.emit('presence-list', [...onlineUsers.keys()]); } catch(_){}
    });
    // GISTAPP_PRESENCE_KEEPALIVE — host re-broadcasts own presence while live
    socket.on('live-presence-ping', () => {
      try { io.emit('presence', { userId: uid, online: true }); } catch(_){}
    });
  socket.on('leave',chatId=>socket.leave('chat:'+chatId));
    socket.on('live-join-room', (sid)=>{ if (sid) socket.join('live:' + sid); });
    socket.on('live-leave-room', (sid)=>{ if (sid) socket.leave('live:' + sid); });
  socket.on('typing',({chatId,typing})=>socket.to('chat:'+chatId).emit('typing',{userId:uid,typing}));
    /* ========== CALL SIGNALING ========== */
  /* ========== GISTAPP_GROUP_CALLS_V1 ========== */
  // In-memory group rooms: roomId -> { host, kind, participants: [{userId}], createdAt }
  // (placed on the io instance so all sockets share)
  if (!io._groupRooms) io._groupRooms = new Map();

  socket.on('call:group-start', ({ invitees, kind }) => {
    try {
      const roomId = 'grp_' + uid + '_' + Date.now();
      const parts = [{ userId: uid }].concat((invitees || []).map(function(x){ return { userId: Number(x) }; }));
      io._groupRooms.set(roomId, {
        host: uid,
        kind: kind || 'video',
        participants: parts,
        createdAt: Date.now(),
        accepted: new Set([uid])
      });
      // Notify invitees
      (invitees || []).forEach(function(inv){
        io.to('user:' + inv).emit('call:group-incoming', {
          roomId, from: uid, kind: kind || 'video',
          participantCount: parts.length
        });
      });
      // Ack to host with the room state
      socket.emit('call:group-ready', {
        roomId,
        participants: parts.map(function(p){ return p.userId; })
      });
      console.log('👥 group call started', roomId, 'participants:', parts.length);
    } catch(e){ console.error('group-start:', e.message); }
  });

  socket.on('call:group-join', ({ roomId }) => {
    try {
      const room = io._groupRooms.get(roomId);
      if (!room){ socket.emit('call:group-error', { roomId, error: 'Room not found' }); return; }
      room.accepted.add(uid);
      if (!room.participants.find(function(p){ return p.userId === uid; })){
        room.participants.push({ userId: uid });
      }
      // Tell everyone currently in the room that a new participant joined
      room.participants.forEach(function(p){
        if (p.userId !== uid){
          io.to('user:' + p.userId).emit('call:group-participant-joined', {
            roomId, userId: uid
          });
        }
      });
      // Tell the joiner who else is in the room
      const others = room.participants.filter(function(p){ return p.userId !== uid; }).map(function(p){ return p.userId; });
      socket.emit('call:group-joined', { roomId, kind: room.kind, participants: others, hostId: room.host });
      console.log('👥 group join', uid, '->', roomId);
    } catch(e){ console.error('group-join:', e.message); }
  });

  socket.on('call:group-leave', ({ roomId }) => {
    try {
      const room = io._groupRooms.get(roomId);
      if (!room) return;
      room.participants = room.participants.filter(function(p){ return p.userId !== uid; });
      room.participants.forEach(function(p){
        io.to('user:' + p.userId).emit('call:group-participant-left', { roomId, userId: uid });
      });
      if (room.participants.length <= 1){
        // Room empty — clean up
        room.participants.forEach(function(p){
          io.to('user:' + p.userId).emit('call:group-ended', { roomId });
        });
        io._groupRooms.delete(roomId);
        console.log('👥 group call ended', roomId);
      }
    } catch(e){ console.error('group-leave:', e.message); }
  });

  socket.on('call:group-end', ({ roomId }) => {
    try {
      const room = io._groupRooms.get(roomId);
      if (!room) return;
      if (room.host !== uid) return; // only host ends
      room.participants.forEach(function(p){
        io.to('user:' + p.userId).emit('call:group-ended', { roomId });
      });
      io._groupRooms.delete(roomId);
      console.log('👥 group call ended by host', roomId);
    } catch(e){ console.error('group-end:', e.message); }
  });

  socket.on('call:group-signal', ({ roomId, to, payload }) => {
    try {
      io.to('user:' + to).emit('call:group-signal', { roomId, from: uid, payload });
    } catch(e){ console.error('group-signal:', e.message); }
  });

  socket.on('call:group-reject', ({ roomId }) => {
    const room = io._groupRooms.get(roomId);
    if (!room) return;
    if (room.host){
      io.to('user:' + room.host).emit('call:group-rejected', { roomId, userId: uid });
    }
  });

  socket.on('call:initiate', ({ to, kind }) => {
    const callId = 'call_' + uid + '_' + to + '_' + Date.now();
    io.to('user:' + to).emit('call:incoming', { callId, from: uid, kind });
    socket.emit('call:initiated', { callId, to: Number(to), kind });
    console.log('📞 call initiated', callId, kind, uid, '->', to);
  });

  socket.on('call:accept', ({ callId }) => {
    socket.emit('call:accepted', { callId });
    socket.broadcast.emit('call:accepted', { callId });
    console.log('✅ call accepted', callId);
  });

  socket.on('call:reject', ({ callId, reason }) => {
    socket.broadcast.emit('call:rejected', { callId, reason: reason || 'declined' });
    console.log('❌ call rejected', callId);
  });

  socket.on('call:end', ({ callId }) => {
    socket.broadcast.emit('call:ended', { callId });
    console.log('🔚 call ended', callId);
  });

  socket.on('call:signal', ({ callId, to, payload }) => {
    io.to('user:' + to).emit('call:signal', { callId, from: uid, payload });
  });

socket.on('disconnect', async ()=>{
    const n = (onlineUsers.get(uid)||1)-1;
    if (n<=0){
      onlineUsers.delete(uid);
      io.emit('presence',{userId:uid,online:false});
      try { await pool.query('UPDATE users SET last_seen_at=NOW() WHERE id=$1',[uid]); } catch(_){}
    } else onlineUsers.set(uid,n);
  });
});


/* ---------- MoMo billing ---------- GISTAPP_MOMO_V1 */
const MOMO_BASE = process.env.MOMO_BASE_URL || 'https://sandbox.momodeveloper.mtn.com';
const MOMO_SUB_KEY = process.env.MOMO_SUBSCRIPTION_KEY || '';
const MOMO_API_USER = process.env.MOMO_API_USER || '';
const MOMO_API_KEY = process.env.MOMO_API_KEY || '';
const MOMO_TARGET_ENV = process.env.MOMO_TARGET_ENV || 'sandbox';
const MOMO_READY = !!(MOMO_SUB_KEY && MOMO_API_USER && MOMO_API_KEY);
// GISTAPP_TIERS_V1 — multi-tier plans
const PLANS = {
  free:     { name: 'Free',     price: 0,     days: 0,   badge: null   },
  pro:      { name: 'Pro',      price: 7500,  days: 30,  badge: 'gold' },
  business: { name: 'Business', price: 25000, days: 30,  badge: 'blue' }
};
const PREMIUM_PRICE = PLANS.pro.price;   // legacy fallback
const PREMIUM_DAYS = 30;

console.log(MOMO_READY ? '✅ MoMo billing ready (₦' + PREMIUM_PRICE + '/mo)' : 'ℹ️  MoMo billing disabled (missing env vars)');

let _momoToken = { token: null, exp: 0 };
async function momoGetToken(){
  if (_momoToken.token && Date.now() < _momoToken.exp - 60000) return _momoToken.token;
  const creds = Buffer.from(MOMO_API_USER + ':' + MOMO_API_KEY).toString('base64');
  const r = await fetch(MOMO_BASE + '/collection/token/', {
    method: 'POST',
    headers: {
      'Authorization': 'Basic ' + creds,
      'Ocp-Apim-Subscription-Key': MOMO_SUB_KEY
    }
  });
  const data = await r.json().catch(()=>({}));
  if (!data.access_token) throw new Error('MoMo token failed: ' + JSON.stringify(data).slice(0,200));
  _momoToken.token = data.access_token;
  _momoToken.exp = Date.now() + (data.expires_in || 3600) * 1000;
  return _momoToken.token;
}

function momoFormatPhone(raw){
  let s = String(raw || '').replace(/\D/g, '');
  if (s.startsWith('234')) return s;
  if (s.startsWith('0')) return '234' + s.slice(1);
  if (s.length === 10) return '234' + s;
  return s;
}

async function momoRequestToPay({ phone, amount, referenceId, payerMessage, payeeNote }){
  // GISTAPP_MOMO_MOCK — simulate payment when MTN sandbox is unavailable
  if (process.env.MOMO_MOCK === 'true'){
    console.log('🎭 MOCK: requestToPay', { phone, amount, referenceId });
    // Simulate MTN accepting the request
    return { ok: true, referenceId: referenceId, mock: true };
  }
  if (!MOMO_READY) return { ok: false, error: 'MoMo not configured' };
  try {
    const token = await momoGetToken();
    const msisdn = momoFormatPhone(phone);
    const r = await fetch(MOMO_BASE + '/collection/v1_0/requesttopay', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'X-Reference-Id': referenceId,
        'X-Target-Environment': MOMO_TARGET_ENV,
        'Ocp-Apim-Subscription-Key': MOMO_SUB_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        amount: String(amount),
        currency: 'NGN',
        externalId: referenceId,
        payer: { partyIdType: 'MSISDN', partyId: msisdn },
        payerMessage: payerMessage || 'GistApp Premium',
        payeeNote: payeeNote || 'Subscription'
      })
    });
    if (r.status === 202) return { ok: true, referenceId: referenceId };
    const err = await r.text();
    return { ok: false, error: 'HTTP ' + r.status + ': ' + err.slice(0, 250) };
  } catch(e){ return { ok: false, error: e.message }; }
}

async function momoCheckStatus(referenceId){
  // GISTAPP_MOMO_MOCK — auto-succeed 5s after request when mocked
  if (process.env.MOMO_MOCK === 'true'){
    try {
      const r = await pool.query('SELECT created_at FROM payments WHERE reference_id=$1', [referenceId]);
      if (r.rowCount && (Date.now() - new Date(r.rows[0].created_at).getTime()) > 5000){
        return { ok: true, status: 'SUCCESSFUL', reason: 'mock' };
      }
      return { ok: true, status: 'PENDING' };
    } catch(_){ return { ok: true, status: 'PENDING' }; }
  }
  if (!MOMO_READY) return { ok: false, error: 'MoMo not configured' };
  try {
    const token = await momoGetToken();
    const r = await fetch(MOMO_BASE + '/collection/v1_0/requesttopay/' + referenceId, {
      headers: {
        'Authorization': 'Bearer ' + token,
        'X-Target-Environment': MOMO_TARGET_ENV,
        'Ocp-Apim-Subscription-Key': MOMO_SUB_KEY
      }
    });
    if (!r.ok) return { ok: false, error: 'HTTP ' + r.status };
    const data = await r.json();
    return { ok: true, status: data.status, reason: data.reason || null, raw: data };
  } catch(e){ return { ok: false, error: e.message }; }
}

async function isPremium(userId){
  try {
    const r = await pool.query('SELECT subscription_tier, subscription_status, subscription_ends_at FROM users WHERE id=$1', [userId]);
    if (!r.rowCount) return false;
    const u = r.rows[0];
    if (u.subscription_tier !== 'premium') return false;
    if (u.subscription_status !== 'active') return false;
    if (u.subscription_ends_at && new Date(u.subscription_ends_at) < new Date()) return false;
    return true;
  } catch(_){ return false; }
}

/* GISTAPP_EARNINGS_PDF — download earnings report as PDF */
app.get('/api/analytics/earnings/pdf', auth, async (req, res) => {
  try {
    const range = String(req.query.range || '30d');
    const pdfBuf = await generateEarningsPDF(req.user.id, range);
    const date = new Date().toISOString().slice(0, 10);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="GistApp-Earnings-' + date + '.pdf"');
    res.setHeader('Content-Length', pdfBuf.length);
    res.send(pdfBuf);
  } catch(e){
    console.error('earnings pdf:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

/* GISTAPP_INVOICES_ENDPOINT — list of user's past payments + PDF download */
app.get('/api/billing/invoices', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, reference_id, amount, currency, plan, method, status, completed_at, created_at
       FROM payments
       WHERE user_id=$1 AND status='success'
       ORDER BY completed_at DESC NULLS LAST, created_at DESC
       LIMIT 50`,
      [req.user.id]
    );
    res.json({ invoices: r.rows });
  } catch(e){ console.error('invoices list:', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/billing/invoices/:id/pdf', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query(
      `SELECT p.*, u.email, u.display_name FROM payments p
       JOIN users u ON u.id = p.user_id
       WHERE p.id=$1 AND p.user_id=$2 AND p.status='success'`,
      [id, req.user.id]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'Invoice not found' });
    const pdfBuf = await generateInvoicePDF(r.rows[0]);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="GistApp-Invoice-' + String(id).padStart(5, '0') + '.pdf"');
    res.setHeader('Content-Length', pdfBuf.length);
    res.send(pdfBuf);
  } catch(e){ console.error('invoice pdf:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// GET /api/billing/status
app.get('/api/billing/status', auth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT subscription_tier, subscription_status, subscription_ends_at, auto_renew, momo_number FROM users WHERE id=$1',
      [req.user.id]
    );
    const u = r.rows[0] || {};
    const isPrem = u.subscription_tier === 'premium' && u.subscription_status === 'active'
      && (!u.subscription_ends_at || new Date(u.subscription_ends_at) > new Date());
    const paystackMode = PAYSTACK_SECRET.startsWith('sk_live_') ? 'live' : (PAYSTACK_SECRET.startsWith('sk_test_') ? 'test' : 'off');
    res.json({
      paystack_mode: paystackMode,
      tier: u.subscription_tier || 'free',
      status: u.subscription_status || null,
      ends_at: u.subscription_ends_at || null,
      auto_renew: !!u.auto_renew,
      momo_number: u.momo_number || null,
      is_premium: isPrem,
      price: PREMIUM_PRICE,
      currency: 'NGN',
      momo_ready: MOMO_READY,
      momo_mock: process.env.MOMO_MOCK === 'true',
      plans: PLANS,
      current_plan: u.subscription_tier || 'free'
    });
  } catch(e){ console.error('billing status:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* GISTAPP_MOMO_SUB_REMOVED — Paystack handles subscribe/verify now */

// POST /api/billing/cancel
app.post('/api/billing/cancel', auth, async (req, res) => {
  try {
    await pool.query('UPDATE users SET auto_renew=false WHERE id=$1', [req.user.id]);
    res.json({ ok: true, message: 'Auto-renewal disabled. Access continues until period ends.' });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

// Auto-renewal scheduler — every 6h, check subscriptions expiring in <=5 days
async function momoRenewalCheck(){
  if (!MOMO_READY) return;
  try {
    const soon = await pool.query(`
      SELECT id, momo_number, subscription_ends_at, auto_renew
      FROM users
      WHERE subscription_tier IN ('pro','business')  -- GISTAPP_RENEWAL_REMINDER fix
        AND subscription_status='active'
        AND auto_renew=true
        AND subscription_ends_at IS NOT NULL
        AND subscription_ends_at < NOW() + INTERVAL '5 days'
        AND subscription_ends_at > NOW() - INTERVAL '7 days'
        AND momo_number IS NOT NULL
      LIMIT 20
    `);
    for (const u of soon.rows){
      const pending = await pool.query(
        `SELECT 1 FROM payments WHERE user_id=$1 AND status='pending' AND created_at > NOW() - INTERVAL '2 days' LIMIT 1`,
        [u.id]
      );
      if (pending.rowCount) continue;
      const referenceId = require('crypto').randomUUID();
      await pool.query(
        `INSERT INTO payments (user_id, reference_id, amount, phone, status) VALUES ($1,$2,$3,$4,'pending')`,
        [u.id, referenceId, PREMIUM_PRICE, u.momo_number]
      );
      const r = await momoRequestToPay({ phone: u.momo_number, amount: PREMIUM_PRICE, referenceId: referenceId });
      console.log(r.ok ? '💳 renewal sent → user ' + u.id : '💳 renewal failed → user ' + u.id + ': ' + r.error);
    }
  } catch(e){ console.warn('renewal check:', e.message); }
}

// Auto-poll pending payments every 30s
async function momoCheckPending(){
  if (!MOMO_READY) return;
  try {
    const r = await pool.query(`SELECT id, user_id, reference_id FROM payments WHERE status='pending' AND created_at > NOW() - INTERVAL '1 hour'`);
    for (const p of r.rows){
      const s = await momoCheckStatus(p.reference_id);
      if (!s.ok) continue;
      if (s.status === 'SUCCESSFUL'){
        await pool.query('UPDATE payments SET status=$1, momo_status=$2, completed_at=NOW() WHERE id=$3', ['success', 'SUCCESSFUL', p.id]);
        const pl = await pool.query('SELECT plan FROM payments WHERE id=$1', [p.id]);
        const planKey = (pl.rows[0] && pl.rows[0].plan) || 'pro';
        const plan = PLANS[planKey] || PLANS.pro;
        await pool.query(`
          UPDATE users
          SET subscription_tier=$2,
              subscription_status='active',
              subscription_ends_at = NOW() + INTERVAL '1 day' * $3
          WHERE id=$1
        `, [p.user_id, planKey, plan.days]);
        console.log('✅ MoMo payment confirmed → user', p.user_id);
        // GISTAPP_ALL_SUBS_RECEIPT — send receipt for MoMo renewal
        try {
          const _u = await pool.query('SELECT email, display_name FROM users WHERE id=$1', [p.user_id]);
          if (_u.rowCount){
            sendPaymentReceiptEmailWithInvoice(_u.rows[0].email, _u.rows[0].display_name, {
              plan: planKey,
              amount: plan.price || 7500,
              method: 'momo',
              reference: p.reference_id || ('MOMO-' + p.id),
              completed_at: new Date().toISOString(),
              days: plan.days,
              payment_id: p.id
            }).catch(function(){});
          }
        } catch(_){}
      } else if (s.status === 'FAILED'){
        await pool.query('UPDATE payments SET status=$1, momo_status=$2 WHERE id=$3', ['failed', 'FAILED', p.id]);
      }
    }
    // Expire overdue subscriptions
    await pool.query(`
      UPDATE users SET subscription_status='past_due'
      WHERE subscription_tier='premium' AND subscription_status='active'
        AND subscription_ends_at < NOW() - INTERVAL '2 days'
    `);
  } catch(e){ console.warn('check pending:', e.message); }
}

setTimeout(momoRenewalCheck, 60 * 1000);
setInterval(momoRenewalCheck, 6 * 60 * 60 * 1000);
// GISTAPP_RENEWAL_REMINDER — check every 6h, email on 5d and 1d milestones
setInterval(checkSubscriptionRenewals, 6 * 60 * 60 * 1000);
setTimeout(checkSubscriptionRenewals, 3 * 60 * 1000); // first run 3min after boot
setInterval(momoCheckPending, 30 * 1000);

/* ---------- Paystack billing ---------- GISTAPP_PAYSTACK_V1 */
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY || '';
const PAYSTACK_PUBLIC = process.env.PAYSTACK_PUBLIC_KEY || '';
const PAYSTACK_BASE = 'https://api.paystack.co';
const PAYSTACK_READY = !!PAYSTACK_SECRET;

const PAYSTACK_APP_URL = process.env.APP_URL || 'http://localhost:4000';

console.log(PAYSTACK_READY ? '✅ Paystack billing ready' : 'ℹ️  Paystack disabled (missing PAYSTACK_SECRET_KEY)');

async function paystackRequest(method, path, body){
  const r = await fetch(PAYSTACK_BASE + path, {
    method: method,
    headers: {
      'Authorization': 'Bearer ' + PAYSTACK_SECRET,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await r.json().catch(()=>({}));
  return { ok: r.ok && data && data.status, status: r.status, data: data };
}

// POST /api/billing/subscribe — creates Paystack transaction
app.post('/api/billing/subscribe', auth, async (req, res) => {
  try {
    if (!PAYSTACK_READY) return res.status(503).json({ error: 'Billing not configured' });
    const planKey = String((req.body && req.body.plan) || 'pro').toLowerCase();
    const plan = PLANS[planKey];
    if (!plan || planKey === 'free') return res.status(400).json({ error: 'Invalid plan' });

    // Get user email (Paystack requires it)
    const u = await pool.query('SELECT email, display_name FROM users WHERE id=$1', [req.user.id]);
    if (!u.rowCount) return res.status(404).json({ error: 'User not found' });
    const userEmail = u.rows[0].email;
    const userName = u.rows[0].display_name || 'User';

    // Create a payment record first
    const referenceId = 'gist_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    await pool.query(
      `INSERT INTO payments (user_id, reference_id, amount, phone, status, plan) VALUES ($1,$2,$3,$4,'pending',$5)`,
      [req.user.id, referenceId, plan.price, 'paystack', planKey]
    );

    // Initialize Paystack transaction
    const callbackUrl = PAYSTACK_APP_URL + '/?payment=success&ref=' + encodeURIComponent(referenceId);
    const init = await paystackRequest('POST', '/transaction/initialize', {
      email: userEmail,
      amount: plan.price * 100,       // kobo (Paystack uses subunits)
      currency: 'NGN',
      reference: referenceId,
      callback_url: callbackUrl,
      metadata: {
        user_id: req.user.id,
        plan: planKey,
        custom_fields: [
          { display_name: 'Plan', variable_name: 'plan', value: plan.name },
          { display_name: 'User', variable_name: 'user', value: userName }
        ]
      }
    });

    if (!init.ok){
      await pool.query('UPDATE payments SET status=$1 WHERE reference_id=$2', ['failed', referenceId]);
      console.error('paystack init failed:', JSON.stringify(init.data).slice(0, 300));
      return res.status(500).json({ error: (init.data && init.data.message) || 'Paystack init failed' });
    }

    res.json({
      ok: true,
      reference: referenceId,
      authorization_url: init.data.data.authorization_url,
      access_code: init.data.data.access_code,
      amount: plan.price,
      currency: 'NGN'
    });
  } catch(e){ console.error('subscribe:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// GET /api/billing/verify/:ref — verify with Paystack
app.get('/api/billing/verify/:ref', auth, async (req, res) => {
  try {
    const ref = String(req.params.ref);
    const p = await pool.query('SELECT id, status, plan FROM payments WHERE reference_id=$1 AND user_id=$2', [ref, req.user.id]);
    if (!p.rowCount) return res.status(404).json({ error: 'Payment not found' });
    if (p.rows[0].status === 'success') return res.json({ status: 'success' });

    if (!PAYSTACK_READY) return res.json({ status: 'pending' });

    const v = await paystackRequest('GET', '/transaction/verify/' + encodeURIComponent(ref));
    if (!v.ok) return res.json({ status: 'pending' });

    const d = v.data.data;
    if (d.status === 'success'){
      await pool.query('UPDATE payments SET status=$1, completed_at=NOW(), raw_response=$2 WHERE id=$3',
        ['success', JSON.stringify(d).slice(0, 2000), p.rows[0].id]);

      const planKey = (p.rows[0].plan || 'pro');
      const plan = PLANS[planKey] || PLANS.pro;
      await pool.query(`
        UPDATE users
        SET subscription_tier=$2,
            subscription_status='active',
            subscription_ends_at = NOW() + INTERVAL '1 day' * $3
        WHERE id=$1
      `, [req.user.id, planKey, plan.days]);

      // GISTAPP_PAYMENT_RECEIPT — send receipt email (fire and forget)
      try {
        const _u = await pool.query('SELECT email, display_name FROM users WHERE id=$1', [req.user.id]);
        if (_u.rowCount){
          sendPaymentReceiptEmailWithInvoice(_u.rows[0].email, _u.rows[0].display_name, {
            plan: planKey,
            amount: d.amount ? Math.round(d.amount / 100) : (plan.price || 0),
            method: 'paystack',
            reference: ref,
            completed_at: new Date().toISOString(),
            days: plan.days,
            payment_id: p.rows[0].id
          }).catch(function(){});
        }
      } catch(_){}

      return res.json({ status: 'success' });
    }
    if (d.status === 'failed' || d.status === 'abandoned'){
      await pool.query('UPDATE payments SET status=$1, momo_status=$2 WHERE id=$3', ['failed', d.status, p.rows[0].id]);
      return res.json({ status: 'failed', reason: d.gateway_response || d.status });
    }
    res.json({ status: 'pending', gateway: d.status });
  } catch(e){ console.error('verify:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/billing/webhook — Paystack webhook
app.post('/api/billing/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const crypto = require('crypto');
    const hash = crypto.createHmac('sha512', PAYSTACK_SECRET).update(req.body).digest('hex');
    if (hash !== req.headers['x-paystack-signature']){
      console.warn('⚠️  Paystack webhook signature mismatch');
      return res.status(401).send('Invalid signature');
    }
    const event = JSON.parse(req.body.toString());
    console.log('📥 Paystack webhook:', event.event);

    if (event.event === 'charge.success'){
      const ref = event.data.reference;
      const p = await pool.query('SELECT id, user_id, status, plan FROM payments WHERE reference_id=$1', [ref]);
      if (p.rowCount && p.rows[0].status !== 'success'){
        await pool.query('UPDATE payments SET status=$1, completed_at=NOW(), raw_response=$2 WHERE id=$3',
          ['success', JSON.stringify(event.data).slice(0, 2000), p.rows[0].id]);
        const planKey = (p.rows[0].plan || 'pro');
        const plan = PLANS[planKey] || PLANS.pro;
        await pool.query(`
          UPDATE users
          SET subscription_tier=$2, subscription_status='active',
              subscription_ends_at = NOW() + INTERVAL '1 day' * $3
          WHERE id=$1
        `, [p.rows[0].user_id, planKey, plan.days]);
        console.log('✅ Paystack webhook activated user', p.rows[0].user_id, 'plan', planKey);
        // GISTAPP_ALL_SUBS_RECEIPT — send receipt for webhook-activated payment
        try {
          const _u = await pool.query('SELECT email, display_name FROM users WHERE id=$1', [p.rows[0].user_id]);
          if (_u.rowCount){
            sendPaymentReceiptEmailWithInvoice(_u.rows[0].email, _u.rows[0].display_name, {
              plan: planKey,
              amount: event.data.amount ? Math.round(event.data.amount / 100) : (plan.price || 7500),
              method: 'paystack',
              reference: ref,
              completed_at: new Date().toISOString(),
              days: plan.days,
              payment_id: p.rows[0].id
            }).catch(function(){});
          }
        } catch(_){}
      }
    }
    res.sendStatus(200);
  } catch(e){ console.error('webhook:', e.message); res.status(500).end(); }
});

// GET /api/billing/paystack-public — returns public key for frontend
app.get('/api/billing/paystack-public', (req, res) => {
  res.json({ public_key: PAYSTACK_PUBLIC, enabled: PAYSTACK_READY });
});

/* ---------- live badge helper ---------- GISTAPP_LIVE_BADGE_BE */
let _liveUserCache = { ids: new Set(), exp: 0 };
async function getLiveUserIds(){
  if (Date.now() < _liveUserCache.exp) return _liveUserCache.ids;
  try {
    const r = await pool.query("SELECT DISTINCT streamer_id FROM live_streams WHERE status='live' AND started_at > NOW() - INTERVAL '4 hours'");
    _liveUserCache.ids = new Set(r.rows.map(function(x){ return Number(x.streamer_id); }));
    _liveUserCache.exp = Date.now() + 5000; // cache 5s
  } catch(_){}
  return _liveUserCache.ids;
}

/* ---------- LiveKit live streaming ---------- GISTAPP_LIVEKIT_V1 */
// GISTAPP_LIVEKIT_SANITIZE — strip whitespace from env vars
function _clean(v){ return String(v || '').trim().replace(/^["']|["']$/g, ''); }
const LIVEKIT_URL = _clean(process.env.LIVEKIT_URL);
const LIVEKIT_API_KEY = _clean(process.env.LIVEKIT_API_KEY);
const LIVEKIT_API_SECRET = _clean(process.env.LIVEKIT_API_SECRET);
const LIVEKIT_READY = !!(LIVEKIT_URL && LIVEKIT_API_KEY && LIVEKIT_API_SECRET);

let _livekitSdk = null;
function getLiveKitSdk(){
  if (_livekitSdk) return _livekitSdk;
  try {
    _livekitSdk = require('livekit-server-sdk');
  } catch(e){
    console.warn('livekit-server-sdk not installed:', e.message);
    _livekitSdk = null;
  }
  return _livekitSdk;
}

// GISTAPP_LIVEKIT_DEBUG — safe diagnostic (no secret leaked)
console.log('🔍 LiveKit env check:');
console.log('   URL:      ' + (LIVEKIT_URL ? JSON.stringify(LIVEKIT_URL) : 'MISSING'));
console.log('   API Key:  ' + (LIVEKIT_API_KEY ? JSON.stringify(LIVEKIT_API_KEY) + ' (len ' + LIVEKIT_API_KEY.length + ')' : 'MISSING'));
console.log('   API Secret: ' + (LIVEKIT_API_SECRET ? LIVEKIT_API_SECRET.length + ' chars, first4=' + LIVEKIT_API_SECRET.slice(0,4) + ', last4=' + LIVEKIT_API_SECRET.slice(-4) : 'MISSING'));
if (LIVEKIT_API_SECRET && LIVEKIT_API_SECRET !== LIVEKIT_API_SECRET.trim()){
  console.log('   ⚠️  API Secret has whitespace!');
}
if (LIVEKIT_API_KEY && LIVEKIT_API_KEY !== LIVEKIT_API_KEY.trim()){
  console.log('   ⚠️  API Key has whitespace!');
}
console.log(LIVEKIT_READY ? '✅ LiveKit ready' : 'ℹ️  LiveKit disabled (missing env vars)');

async function livekitCreateRoom(roomName){
  const sdk = getLiveKitSdk();
  if (!sdk || !LIVEKIT_READY) throw new Error('LiveKit not configured');
  const { RoomServiceClient } = sdk;
  const svc = new RoomServiceClient(LIVEKIT_URL.replace('wss://', 'https://'), LIVEKIT_API_KEY, LIVEKIT_API_SECRET);
  try {
    const room = await svc.createRoom({
      name: roomName,
      emptyTimeout: 300,
      maxParticipants: 500
    });
    return room;
  } catch(e){
    // Room may already exist
    if (e.message && e.message.includes('already exists')) return { name: roomName };
    throw e;
  }
}

async function livekitGenerateToken(roomName, identity, name, isPublisher){
  const sdk = getLiveKitSdk();
  if (!sdk || !LIVEKIT_READY) throw new Error('LiveKit not configured');
  const { AccessToken } = sdk;
  const at = new AccessToken(LIVEKIT_API_KEY, LIVEKIT_API_SECRET, {
    identity: String(identity),
    name: name || 'User',
    ttl: '6h'
  });
  at.addGrant({
    roomJoin: true,
    room: roomName,
    canPublish: !!isPublisher,
    canSubscribe: true,
    canPublishData: true
  });
  return await at.toJwt();
}

async function livekitGetViewerCount(roomName){
  const sdk = getLiveKitSdk();
  if (!sdk || !LIVEKIT_READY) return null;
  const { RoomServiceClient } = sdk;
  const svc = new RoomServiceClient(LIVEKIT_URL.replace('wss://', 'https://'), LIVEKIT_API_KEY, LIVEKIT_API_SECRET);
  try {
    const parts = await svc.listParticipants(roomName);
    // Subtract 1 for the host/streamer
    return Math.max(0, (parts || []).length - 1);
  } catch(e){
    return null;
  }
}
// GISTAPP_VIEWER_COUNT_FIX

async function livekitDeleteRoom(roomName){
  const sdk = getLiveKitSdk();
  if (!sdk || !LIVEKIT_READY) return;
  const { RoomServiceClient } = sdk;
  const svc = new RoomServiceClient(LIVEKIT_URL.replace('wss://', 'https://'), LIVEKIT_API_KEY, LIVEKIT_API_SECRET);
  try { await svc.deleteRoom(roomName); } catch(_){}
}

async function isPremiumUser(userId){
  try {
    const r = await pool.query('SELECT subscription_tier, subscription_status, subscription_ends_at FROM users WHERE id=$1', [userId]);
    if (!r.rowCount) return false;
    const u = r.rows[0];
    if (!u.subscription_tier || u.subscription_tier === 'free') return false;
    if (u.subscription_status !== 'active') return false;
    if (u.subscription_ends_at && new Date(u.subscription_ends_at) < new Date()) return false;
    return true;
  } catch(_){ return false; }
}

// POST /api/live/start — streamer begins
/* GISTAPP_L5_SCHEDULE — schedule + RSVP endpoints */
app.post('/api/live/schedule', auth, async (req, res) => {
  try {
    const title = String((req.body && req.body.title) || '').slice(0, 120).trim();
    const description = String((req.body && req.body.description) || '').slice(0, 500).trim();
    const startsAt = req.body && req.body.starts_at ? new Date(req.body.starts_at) : null;
    if (!title) return res.status(400).json({ error: 'Title required' });
    if (!startsAt || isNaN(startsAt.getTime())) return res.status(400).json({ error: 'Valid start time required' });
    if (startsAt.getTime() < Date.now() + 60 * 1000) return res.status(400).json({ error: 'Must be at least 1 minute in the future' });
    if (startsAt.getTime() > Date.now() + 30 * 24 * 60 * 60 * 1000) return res.status(400).json({ error: 'Max 30 days ahead' });

    // Cancel any prior scheduled stream from this user
    await pool.query("UPDATE live_schedules SET status='cancelled' WHERE streamer_id=$1 AND status='scheduled'", [req.user.id]);

    const ins = await pool.query(
      "INSERT INTO live_schedules (streamer_id, title, description, starts_at) VALUES ($1,$2,$3,$4) RETURNING id, title, description, starts_at, status",
      [req.user.id, title, description || null, startsAt.toISOString()]
    );

    // Notify followers
    try {
      const followers = await pool.query('SELECT follower_id FROM user_follows WHERE following_id=$1', [req.user.id]);
      const me = await pool.query('SELECT display_name FROM users WHERE id=$1', [req.user.id]);
      const name = (me.rows[0] && me.rows[0].display_name) || 'Someone';
      followers.rows.forEach(function(f){
        io.to('user:' + f.follower_id).emit('stream-scheduled', {
          id: ins.rows[0].id, streamer_id: req.user.id, streamer_name: name,
          title: title, starts_at: ins.rows[0].starts_at
        });
        sendPush(f.follower_id, name + ' scheduled a live stream',
          title + ' — ' + new Date(startsAt).toLocaleString('en-GB', { timeZone: 'Africa/Lagos', hour: '2-digit', minute: '2-digit', day: 'numeric', month: 'short' }),
          { url: '/?schedule=' + ins.rows[0].id, tag: 'sched-' + ins.rows[0].id }).catch(function(){});
      });
    } catch(_){}

    res.json({ ok: true, schedule: ins.rows[0] });
  } catch(e){ console.error('schedule:', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/live/schedules', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT s.id, s.streamer_id, s.title, s.description, s.starts_at, s.status,
              u.display_name AS streamer_name, u.avatar_url, u.avatar_color, u.username,
              (SELECT COUNT(*)::int FROM live_rsvps WHERE schedule_id=s.id) AS rsvp_count,
              (SELECT COUNT(*)::int FROM live_rsvps WHERE schedule_id=s.id AND user_id=$1) AS i_rsvpd
       FROM live_schedules s
       JOIN users u ON u.id = s.streamer_id
       WHERE s.status='scheduled' AND s.starts_at > NOW() - INTERVAL '30 minutes'
       ORDER BY s.starts_at ASC
       LIMIT 30`,
      [req.user.id]
    );
    res.json({ schedules: r.rows });
  } catch(e){ console.error('schedules list:', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/live/schedules/:id/rsvp', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const s = await pool.query('SELECT streamer_id, status FROM live_schedules WHERE id=$1', [id]);
    if (!s.rowCount) return res.status(404).json({ error: 'Not found' });
    if (s.rows[0].status !== 'scheduled') return res.status(400).json({ error: 'Schedule not active' });
    if (s.rows[0].streamer_id === req.user.id) return res.status(400).json({ error: 'Cannot RSVP to your own stream' });
    await pool.query('INSERT INTO live_rsvps (schedule_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [id, req.user.id]);
    const cnt = await pool.query('SELECT COUNT(*)::int AS n FROM live_rsvps WHERE schedule_id=$1', [id]);
    res.json({ ok: true, rsvpd: true, count: cnt.rows[0].n });
  } catch(e){ console.error('rsvp:', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/live/schedules/:id/rsvp', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    await pool.query('DELETE FROM live_rsvps WHERE schedule_id=$1 AND user_id=$2', [id, req.user.id]);
    const cnt = await pool.query('SELECT COUNT(*)::int AS n FROM live_rsvps WHERE schedule_id=$1', [id]);
    res.json({ ok: true, rsvpd: false, count: cnt.rows[0].n });
  } catch(e){ console.error('unrsvp:', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/live/schedules/:id', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const s = await pool.query('SELECT streamer_id FROM live_schedules WHERE id=$1', [id]);
    if (!s.rowCount) return res.status(404).json({ error: 'Not found' });
    if (s.rows[0].streamer_id !== req.user.id && !req.user.is_admin) return res.status(403).json({ error: 'Only owner' });
    await pool.query("UPDATE live_schedules SET status='cancelled' WHERE id=$1", [id]);
    // Notify RSVPs
    try {
      const rsvps = await pool.query('SELECT user_id FROM live_rsvps WHERE schedule_id=$1', [id]);
      rsvps.rows.forEach(function(r){
        io.to('user:' + r.user_id).emit('stream-schedule-cancelled', { id: id });
      });
    } catch(_){}
    res.json({ ok: true });
  } catch(e){ console.error('cancel schedule:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* GISTAPP_L5_SCHEDULE — cron: fire 15-min + at-start notifications */
async function checkStreamSchedules(){
  try {
    const baseUrl = process.env.APP_URL || 'https://gistapp.onrender.com';

    // 15-min reminders
    const soon = await pool.query(
      `SELECT id, streamer_id, title, starts_at FROM live_schedules
       WHERE status='scheduled' AND notified_15min=false
         AND starts_at BETWEEN NOW() + INTERVAL '13 minutes' AND NOW() + INTERVAL '17 minutes'`
    );
    for (const s of soon.rows){
      try {
        const rsvps = await pool.query(
          'SELECT r.user_id, u.email, u.display_name, u.prefs FROM live_rsvps r JOIN users u ON u.id=r.user_id WHERE r.schedule_id=$1',
          [s.id]
        );
        const streamer = await pool.query('SELECT display_name FROM users WHERE id=$1', [s.streamer_id]);
        const sname = (streamer.rows[0] && streamer.rows[0].display_name) || 'Someone';
        const startTime = new Date(s.starts_at).toLocaleTimeString('en-GB', { timeZone: 'Africa/Lagos', hour: '2-digit', minute: '2-digit' });
        for (const r of rsvps.rows){
          sendPush(r.user_id, sname + ' is going live in 15 minutes',
            s.title + ' at ' + startTime,
            { url: '/', tag: 'sched-15-' + s.id }).catch(function(){});
          // Email
          if (r.email && (r.prefs || {}).schedule_emails !== 'false'){
            mailer.sendMail({
              from: '"GistApp" <' + GMAIL_SENDER + '>',
              to: r.email,
              replyTo: process.env.SMTP_USER,
              subject: '🔴 ' + sname + ' is going live in 15 minutes',
              html: '<!doctype html><html><body style="margin:0;padding:0;background:#f2f0fa;font-family:Inter,-apple-system,sans-serif">' +
                '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f2f0fa;padding:24px 12px"><tr><td align="center">' +
                '<table role="presentation" width="520" cellspacing="0" cellpadding="0" style="max-width:520px;width:100%;background:#fff;border-radius:20px;overflow:hidden;box-shadow:0 12px 40px rgba(51,52,76,.10)">' +
                '<tr><td style="background:linear-gradient(135deg,#ff3b30,#ff5e3a);padding:24px 32px;text-align:center">' +
                '<img src="' + baseUrl + '/icon-192.png" width="48" height="48" style="border-radius:12px;display:block;margin:0 auto 8px">' +
                '<div style="color:#fff;font-size:18px;font-weight:800">🔴 Starting in 15 minutes</div></td></tr>' +
                '<tr><td style="padding:26px 32px">' +
                '<p style="margin:0 0 12px;color:#1c1c22;font-size:16px;font-weight:700">Hi ' + (r.display_name || 'there') + ',</p>' +
                '<p style="margin:0 0 18px;color:#4a4a55;font-size:14.5px;line-height:1.6"><b>' + sname + '</b> is going live soon. You RSVP\u2019d so here\u2019s your reminder.</p>' + /* GISTAPP_L5_APOS_FIX */
                '<div style="background:#fff3cd;border:1px solid #ffe58f;border-radius:12px;padding:14px 16px;margin-bottom:18px"><div style="color:#7a5a00;font-size:13px;font-weight:800">⏰ ' + s.title + '</div><div style="color:#2b2c44;font-size:13px;margin-top:4px">Starts at ' + startTime + ' WAT</div></div>' +
                '<div style="text-align:center"><a href="' + baseUrl + '" style="background:#2b2c44;color:#fff;text-decoration:none;padding:13px 32px;border-radius:12px;font-weight:700;display:inline-block;font-size:14px">Open GistApp</a></div>' +
                '<p style="color:#8e8e93;font-size:12px;margin:22px 0 0;text-align:center">You got this because you RSVP\u2019d. Turn off in Settings \u2192 Notifications.</p>' +
                '</td></tr></table></td></tr></table></body></html>'
            }).catch(function(){});
          }
        }
        await pool.query('UPDATE live_schedules SET notified_15min=true WHERE id=$1', [s.id]);
        console.log('📅 15-min reminder sent for schedule', s.id, '(to', rsvps.rowCount, 'RSVPs)');
      } catch(inner){ console.warn('15min reminder error:', inner.message); }
    }

    // At-start notifications
    const now = await pool.query(
      `SELECT id, streamer_id, title, starts_at FROM live_schedules
       WHERE status='scheduled' AND notified_start=false
         AND starts_at BETWEEN NOW() - INTERVAL '3 minutes' AND NOW()`
    );
    for (const s of now.rows){
      try {
        const rsvps = await pool.query('SELECT user_id FROM live_rsvps WHERE schedule_id=$1', [s.id]);
        const streamer = await pool.query('SELECT display_name FROM users WHERE id=$1', [s.streamer_id]);
        const sname = (streamer.rows[0] && streamer.rows[0].display_name) || 'Someone';
        rsvps.rows.forEach(function(r){
          sendPush(r.user_id, sname + ' is going live now', s.title, { url: '/', tag: 'sched-now-' + s.id }).catch(function(){});
        });
        await pool.query('UPDATE live_schedules SET notified_start=true WHERE id=$1', [s.id]);
        console.log('📅 At-start push sent for schedule', s.id, '(to', rsvps.rowCount, 'RSVPs)');
      } catch(inner){ console.warn('at-start error:', inner.message); }
    }

    // Auto-expire schedules that started >30 min ago
    await pool.query("UPDATE live_schedules SET status='expired' WHERE status='scheduled' AND starts_at < NOW() - INTERVAL '30 minutes'");
  } catch(e){ console.warn('checkStreamSchedules:', e.message); }
}
setInterval(checkStreamSchedules, 5 * 60 * 1000);
setTimeout(checkStreamSchedules, 90 * 1000);

// POST /api/live/start — creates a LiveKit room + returns host token
app.post('/api/live/start', auth, async (req, res) => {
  try {
    if (!LIVEKIT_READY) return res.status(503).json({ error: 'Live streaming not configured' });
    const premium = await isPremiumUser(req.user.id);
    if (!premium) return res.status(403).json({ error: 'Live streaming requires Premium', needs_premium: true });

    // Kill any existing active stream by this user
    await pool.query(
      "UPDATE live_streams SET status='ended', ended_at=NOW() WHERE streamer_id=$1 AND status='live'",
      [req.user.id]
    );

    const title = String((req.body && req.body.title) || '').trim().slice(0, 120) || 'Live stream';
    const roomName = 'live_' + req.user.id + '_' + Date.now();
    const sdk = getLiveKitSdk();
    if (!sdk) return res.status(500).json({ error: 'LiveKit SDK not installed' });

    // Create room
    try {
      await livekitCreateRoom(roomName);
    } catch(e){
      console.error('livekit createRoom:', e.message);
      return res.status(500).json({ error: 'Could not create stream' });
    }

    // Save stream row
    const ins = await pool.query(
      "INSERT INTO live_streams (streamer_id, title, room_name, status) VALUES ($1,$2,$3,'live') RETURNING id, title, room_name, started_at",
      [req.user.id, title, roomName]
    );
    const s = ins.rows[0];

    // Generate host token
    const me = await pool.query('SELECT display_name FROM users WHERE id=$1', [req.user.id]);
    const hostName = (me.rows[0] && me.rows[0].display_name) || 'Streamer';
    const token = await livekitGenerateToken(roomName, req.user.id, hostName, true);

    // Notify followers via socket
    try {
      const followers = await pool.query('SELECT follower_id FROM user_follows WHERE following_id=$1', [req.user.id]);
      followers.rows.forEach(function(f){
        io.to('user:' + f.follower_id).emit('live-started', {
          id: s.id, streamer_id: req.user.id, streamer_name: hostName, title: title
        });
      });
    } catch(_){}

    res.json({
      ok: true,
      stream: { id: s.id, title: s.title, room: roomName, started_at: s.started_at },
      token: token,
      url: LIVEKIT_URL
    });
    console.log('🎥 live stream started by user', req.user.id, 'room', roomName);
  } catch(e){ console.error('live/start:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/live/end — streamer ends
app.post('/api/live/end', auth, async (req, res) => {
  try {
    const id = Number((req.body && req.body.id) || 0);
    const r = await pool.query('SELECT id, streamer_id, room_name FROM live_streams WHERE id=$1', [id]);
    if (!r.rowCount) return res.status(404).json({ error: 'Stream not found' });
    if (r.rows[0].streamer_id !== req.user.id) return res.status(403).json({ error: 'Not your stream' });

    await pool.query("UPDATE live_streams SET status='ended', ended_at=NOW() WHERE id=$1", [id]);
    await livekitDeleteRoom(r.rows[0].room_name);

    io.emit('live-ended', { id: id, streamer_id: req.user.id });
    res.json({ ok: true });
    console.log('🎥 live stream ended:', id);
  } catch(e){ console.error('live/end:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// GET /api/live/streams — list active streams
app.get('/api/live/streams', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT l.id, l.title, l.room_name, l.viewer_count, l.peak_viewers, l.started_at,
             u.id AS streamer_id, u.display_name, u.avatar_color, u.avatar_url, u.subscription_tier
      FROM live_streams l
      JOIN users u ON u.id = l.streamer_id
      WHERE l.status='live' AND l.started_at > NOW() - INTERVAL '4 hours'
      ORDER BY l.viewer_count DESC, l.started_at DESC
      LIMIT 30
    `);

    // GISTAPP_VIEWER_COUNT_FIX: for the requester's own stream, sync real count from LiveKit
    const rows = r.rows;
    if (LIVEKIT_READY){
      const mine = rows.filter(function(x){ return Number(x.streamer_id) === Number(req.user.id); });
      for (const m of mine){
        const real = await livekitGetViewerCount(m.room_name);
        if (real !== null && real !== m.viewer_count){
          m.viewer_count = real;
          if (real > (m.peak_viewers || 0)) m.peak_viewers = real;
          try {
            await pool.query(
              'UPDATE live_streams SET viewer_count=$1, peak_viewers=GREATEST(peak_viewers, $1) WHERE id=$2',
              [real, m.id]
            );
          } catch(_){}
        }
      }
    }
    // Strip room_name from response (internal only)
    rows.forEach(function(x){ delete x.room_name; });
    res.json(rows);
  } catch(e){ console.error('live list:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// GET /api/live/join/:id — viewer gets token
app.get('/api/live/join/:id', auth, async (req, res) => {
  try {
    if (!LIVEKIT_READY) return res.status(503).json({ error: 'Live streaming not configured' });
    const id = Number(req.params.id);
    const r = await pool.query(`
      SELECT l.id, l.title, l.room_name, l.status, l.viewer_count,
             u.id AS streamer_id, u.display_name, u.avatar_color, u.avatar_url, u.subscription_tier
      FROM live_streams l
      JOIN users u ON u.id = l.streamer_id
      WHERE l.id=$1
    `, [id]);
    if (!r.rowCount) return res.status(404).json({ error: 'Stream not found' });
    const s = r.rows[0];
    if (s.status !== 'live') return res.status(410).json({ error: 'Stream ended' });

    const me = await pool.query('SELECT display_name FROM users WHERE id=$1', [req.user.id]);
    const myName = (me.rows[0] && me.rows[0].display_name) || 'Viewer';
    const token = await livekitGenerateToken(s.room_name, req.user.id, myName, false);

    // Bump viewer count (best-effort)
    await pool.query('UPDATE live_streams SET viewer_count = viewer_count + 1, peak_viewers = GREATEST(peak_viewers, viewer_count + 1) WHERE id=$1', [id]);

    res.json({
      ok: true,
      stream: {
        id: s.id, title: s.title, room: s.room_name,
        streamer_id: s.streamer_id, streamer_name: s.display_name,
        streamer_avatar_color: s.avatar_color, streamer_avatar_url: s.avatar_url,
        streamer_tier: s.subscription_tier
      },
      token: token,
      url: LIVEKIT_URL
    });
  } catch(e){ console.error('live/join:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/live/heartbeat — viewer keeps count alive
// GISTAPP_LIVE_VIEWERS_V1 — also upserts into live_viewers for the host list
app.post('/api/live/heartbeat', auth, async (req, res) => {
  try {
    const id = Number((req.body && req.body.id) || 0);
    if (!id) return res.json({ ok: false });
    // Upsert viewer row
    await pool.query(
      `INSERT INTO live_viewers (stream_id, user_id, last_ping)
       VALUES ($1, $2, NOW())
       ON CONFLICT (stream_id, user_id) DO UPDATE SET last_ping=NOW()`,
      [id, req.user.id]
    );
    // Refresh viewer_count from active viewers
    const c = await pool.query(
      "SELECT COUNT(*)::int AS n FROM live_viewers WHERE stream_id=$1 AND last_ping > NOW() - INTERVAL '60 seconds'  /* GISTAPP_LIVE_VIEWERS_V2 — 60s tolerance */",
      [id]
    );
    await pool.query('UPDATE live_streams SET viewer_count=$1 WHERE id=$2', [c.rows[0].n, id]);
    res.json({ ok: true, viewers: c.rows[0].n });
  } catch(_){ res.json({ ok: false }); }
});

// GET /api/live/:id/viewers — host only, returns active viewer list
app.get('/api/live/:id/viewers', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const own = await pool.query('SELECT streamer_id FROM live_streams WHERE id=$1', [id]);
    if (!own.rowCount) return res.status(404).json({ error: 'Stream not found' });
    if (own.rows[0].streamer_id !== req.user.id) return res.status(403).json({ error: 'Only host' });
    const r = await pool.query(
      `SELECT v.user_id, v.joined_at, v.last_ping,
              u.display_name, u.username, u.avatar_color, u.avatar_url,
              u.subscription_tier
       FROM live_viewers v
       JOIN users u ON u.id = v.user_id
       WHERE v.stream_id=$1 AND v.last_ping > NOW() - INTERVAL '60 seconds'  /* GISTAPP_LIVE_VIEWERS_V2 */
       ORDER BY v.joined_at ASC`,
      [id]
    );
    res.json({ viewers: r.rows, count: r.rowCount });
  } catch(e){ console.error('viewers:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/live/leave — viewer leaves
app.post('/api/live/leave', auth, async (req, res) => {
  try {
    const id = Number((req.body && req.body.id) || 0);
    await pool.query('UPDATE live_streams SET viewer_count = GREATEST(0, viewer_count - 1) WHERE id=$1', [id]);
    res.json({ ok: true });
  } catch(_){ res.json({ ok: false }); }
});

// Cleanup: auto-end streams older than 4 hours with no heartbeat
async function cleanupLiveStreams(){
  try {
    const r = await pool.query(`
      UPDATE live_streams
      SET status='ended', ended_at=NOW()
      WHERE status='live' AND started_at < NOW() - INTERVAL '4 hours'
      RETURNING id, streamer_id, room_name
    `);
    for (const s of r.rows){
      await livekitDeleteRoom(s.room_name);
      io.emit('live-ended', { id: s.id, streamer_id: s.streamer_id });
      console.log('🎥 auto-ended stale stream:', s.id);
    }
  } catch(e){ console.warn('cleanup live:', e.message); }
}
/* GISTAPP_VC_EMIT — push real viewer count via socket every 5s */
async function livekitSyncViewerCounts(){
  if (!LIVEKIT_READY) return;
  try {
    const r = await pool.query("SELECT id, room_name, streamer_id FROM live_streams WHERE status='live'");
    for (const s of r.rows){
      const real = await livekitGetViewerCount(s.room_name);
      if (real === null) continue;
      await pool.query(
        'UPDATE live_streams SET viewer_count=$1, peak_viewers=GREATEST(peak_viewers, $1) WHERE id=$2',
        [real, s.id]
      );
      io.to('user:' + s.streamer_id).emit('live-viewers-update', { stream_id: s.id, count: real });
    }
  } catch(e){ console.warn('vc sync:', e.message); }
}
setTimeout(livekitSyncViewerCounts, 3000);
/* GISTAPP_ANALYTICS_V1 — streamer analytics aggregation */
app.get('/api/analytics/streamer', auth, async (req, res) => {
  try {
    const uid = req.user.id;
    const range = String(req.query.range || '30d');
    let interval = "30 days";
    if (range === '7d') interval = "7 days";
    else if (range === '24h') interval = "24 hours";
    else if (range === 'all') interval = null;

    const whereTime = interval
      ? "AND ls.started_at > NOW() - INTERVAL '" + interval + "'"
      : "";

    // Totals
    const totalsR = await pool.query(
      `SELECT
         COUNT(*)::int AS streams,
         COALESCE(SUM(EXTRACT(EPOCH FROM (COALESCE(ls.ended_at, ls.started_at) - ls.started_at)) / 3600), 0)::numeric(10,1) AS hours_streamed,
         COALESCE(SUM(ls.peak_viewers), 0)::int AS peak_viewers,
         COALESCE(SUM(ls.viewer_count), 0)::int AS total_viewers,
         COALESCE(SUM(ls.gift_count), 0)::int AS gift_count,
         COALESCE(SUM(ls.follower_gain), 0)::int AS follower_gain
       FROM live_streams ls
       WHERE ls.streamer_id = $1 ${whereTime}`,
      [uid]
    );
    const t = totalsR.rows[0] || {};

    // Coins earned from these streams
    const coinsR = await pool.query(
      `SELECT COALESCE(SUM(lg.coins), 0)::int AS gross_coins
       FROM live_gifts lg
       JOIN live_streams ls ON ls.id = lg.stream_id
       WHERE ls.streamer_id = $1 ${whereTime}`,
      [uid]
    );
    const grossCoins = coinsR.rows[0] ? coinsR.rows[0].gross_coins : 0;
    const creatorCoins = Math.floor(grossCoins * 0.7);

    // Streams per day (last N days)
    const dayRange = (range === 'all') ? 30 : (range === '24h' ? 1 : (range === '7d' ? 7 : 30));
    const daysR = await pool.query(
      `WITH days AS (
         SELECT generate_series(
           (CURRENT_DATE - INTERVAL '${dayRange - 1} days')::date,
           CURRENT_DATE::date,
           INTERVAL '1 day'
         )::date AS d
       )
       SELECT d::text AS date, COALESCE(COUNT(ls.id), 0)::int AS count
       FROM days
       LEFT JOIN live_streams ls ON DATE(ls.started_at AT TIME ZONE 'Africa/Lagos') = d AND ls.streamer_id = $1
       GROUP BY d ORDER BY d`,
      [uid]
    );

    // Top 5 streams by peak_viewers
    const topR = await pool.query(
      `SELECT ls.id, ls.title, ls.peak_viewers, ls.viewer_count, ls.started_at, ls.ended_at,
              COALESCE((SELECT SUM(lg.coins) FROM live_gifts lg WHERE lg.stream_id = ls.id), 0)::int AS coins,
              COALESCE(ls.gift_count, 0)::int AS gift_count
       FROM live_streams ls
       WHERE ls.streamer_id = $1 ${whereTime}
       ORDER BY ls.peak_viewers DESC NULLS LAST, ls.started_at DESC
       LIMIT 5`,
      [uid]
    );

    // Gift breakdown
    const giftsR = await pool.query(
      `SELECT lg.gift_type, COUNT(*)::int AS count, COALESCE(SUM(lg.coins), 0)::int AS coins
       FROM live_gifts lg
       JOIN live_streams ls ON ls.id = lg.stream_id
       WHERE ls.streamer_id = $1 ${whereTime}
       GROUP BY lg.gift_type
       ORDER BY coins DESC`,
      [uid]
    );

    // A3 — GISTAPP_A3_FOLLOWERS — follower growth per day
    const follR = await pool.query(
      `WITH days AS (
         SELECT generate_series(
           (CURRENT_DATE - INTERVAL '${dayRange - 1} days')::date,
           CURRENT_DATE::date,
           INTERVAL '1 day'
         )::date AS d
       )
       SELECT d::text AS date, COALESCE(COUNT(uf.follower_id), 0)::int AS count
       FROM days
       LEFT JOIN user_follows uf ON DATE(uf.created_at AT TIME ZONE 'Africa/Lagos') = d AND uf.following_id = $1
       GROUP BY d ORDER BY d`,
      [uid]
    );

    res.json({
      range: range,
      followers_per_day: follR.rows,
      totals: {
        streams: t.streams || 0,
        hours_streamed: Number(t.hours_streamed || 0),
        peak_viewers: t.peak_viewers || 0,
        total_viewers: t.total_viewers || 0,
        gift_count: t.gift_count || 0,
        follower_gain: t.follower_gain || 0,
        gross_coins: grossCoins,
        creator_coins: creatorCoins,
        creator_ngn: Math.floor(creatorCoins / 10)
      },
      streams_per_day: daysR.rows,
      top_streams: topR.rows,
      gift_breakdown: giftsR.rows
    });
  } catch(e){ console.error('analytics:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* GISTAPP_COMMUNITY_V1 — comment controls, voice comments, polls */
(async function(){
  try {
    // Voice comments
    await pool.query(`ALTER TABLE post_comments ADD COLUMN IF NOT EXISTS audio_url TEXT`);
    await pool.query(`ALTER TABLE post_comments ADD COLUMN IF NOT EXISTS audio_duration INTEGER`);
    // Polls
    await pool.query(`ALTER TABLE post_comments ADD COLUMN IF NOT EXISTS kind TEXT DEFAULT 'text'`);
    await pool.query(`ALTER TABLE post_comments ADD COLUMN IF NOT EXISTS poll_data JSONB`);
    await pool.query(`CREATE TABLE IF NOT EXISTS comment_poll_votes (
      comment_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      option_index INTEGER NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (comment_id, user_id)
    )`);
    console.log('✅ community migrations ready');
  } catch(e){ console.warn('community migration:', e.message); }
})();

/* GISTAPP_L5_SCHEDULE — schedule + RSVP tables */
(async function(){
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS live_schedules (
      id SERIAL PRIMARY KEY,
      streamer_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      starts_at TIMESTAMPTZ NOT NULL,
      status TEXT DEFAULT 'scheduled',
      notified_15min BOOLEAN DEFAULT false,
      notified_start BOOLEAN DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS live_rsvps (
      schedule_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (schedule_id, user_id)
    )`);
    await pool.query(`CREATE INDEX IF NOT EXISTS live_schedules_upcoming_idx ON live_schedules (starts_at) WHERE status='scheduled'`);
    console.log('✅ live_schedules + live_rsvps tables ready');
  } catch(e){ console.warn('live_schedules setup:', e.message); }
})();

/* GISTAPP_LIVE_VIEWERS_V1 — table setup */
(async function(){
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS live_viewers (
      stream_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      joined_at TIMESTAMPTZ DEFAULT NOW(),
      last_ping TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (stream_id, user_id)
    )`);
    await pool.query(`CREATE INDEX IF NOT EXISTS live_viewers_stream_ping_idx ON live_viewers (stream_id, last_ping DESC)`);
    console.log('✅ live_viewers table ready');
  } catch(e){ console.warn('live_viewers setup:', e.message); }
})();
setInterval(livekitSyncViewerCounts, 5000);

setTimeout(cleanupLiveStreams, 2 * 60 * 1000);
setInterval(cleanupLiveStreams, 30 * 60 * 1000);

/* ---------- live join requests + guests ---------- GISTAPP_LIVE_REQUESTS_V1 */

// POST /api/live/:id/request — viewer requests to join as co-host
app.post('/api/live/:id/request', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query(
      "SELECT id, streamer_id, status FROM live_streams WHERE id=$1",
      [id]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'Stream not found' });
    if (r.rows[0].status !== 'live') return res.status(410).json({ error: 'Stream ended' });
    if (r.rows[0].streamer_id === req.user.id) return res.status(400).json({ error: 'You are the host' });

    const existing = await pool.query(
      "SELECT id, status FROM live_join_requests WHERE stream_id=$1 AND user_id=$2 AND status IN ('pending','approved')",
      [id, req.user.id]
    );
    if (existing.rowCount){
      return res.json({ ok: true, status: existing.rows[0].status, already: true });
    }

    const ins = await pool.query(
      "INSERT INTO live_join_requests (stream_id, user_id, status) VALUES ($1,$2,'pending') RETURNING id",
      [id, req.user.id]
    );

    const u = await pool.query('SELECT display_name, avatar_color, avatar_url FROM users WHERE id=$1', [req.user.id]);
    // Notify host via socket
    io.to('user:' + r.rows[0].streamer_id).emit('live-join-request', {
      stream_id: id,
      request_id: ins.rows[0].id,
      user_id: req.user.id,
      display_name: (u.rows[0] && u.rows[0].display_name) || 'User',
      avatar_color: u.rows[0] && u.rows[0].avatar_color,
      avatar_url: u.rows[0] && u.rows[0].avatar_url
    });

    res.json({ ok: true, status: 'pending', request_id: ins.rows[0].id });
  } catch(e){ console.error('live/request:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// GET /api/live/:id/requests — host fetches pending requests
app.get('/api/live/:id/requests', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const own = await pool.query('SELECT streamer_id FROM live_streams WHERE id=$1', [id]);
    if (!own.rowCount) return res.status(404).json({ error: 'Stream not found' });
    if (own.rows[0].streamer_id !== req.user.id) return res.status(403).json({ error: 'Not your stream' });

    const r = await pool.query(`
      SELECT r.id, r.status, r.created_at,
             u.id AS user_id, u.display_name, u.avatar_color, u.avatar_url
      FROM live_join_requests r
      JOIN users u ON u.id = r.user_id
      WHERE r.stream_id=$1 AND r.status IN ('pending','approved')
      ORDER BY r.created_at ASC
    `, [id]);
    res.json(r.rows);
  } catch(e){ console.error('live/requests:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// GET /api/live/:id/my-request — viewer checks their own status
app.get('/api/live/:id/my-request', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query(
      "SELECT id, status FROM live_join_requests WHERE stream_id=$1 AND user_id=$2 ORDER BY id DESC LIMIT 1",
      [id, req.user.id]
    );
    if (!r.rowCount) return res.json({ status: null });
    res.json({ status: r.rows[0].status, request_id: r.rows[0].id });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

/* GISTAPP_L7_INVITE — host invites a viewer to co-host directly */
app.post('/api/live/:id/invite/:uid', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const guestId = Number(req.params.uid);
    const own = await pool.query('SELECT streamer_id, room_name, title FROM live_streams WHERE id=$1 AND status=\'live\'', [id]);
    if (!own.rowCount) return res.status(404).json({ error: 'Stream not found or ended' });
    if (own.rows[0].streamer_id !== req.user.id) return res.status(403).json({ error: 'Only host' });
    if (guestId === req.user.id) return res.status(400).json({ error: 'Cannot invite yourself' });

    // Ensure guest exists
    const gu = await pool.query('SELECT id, display_name FROM users WHERE id=$1', [guestId]);
    if (!gu.rowCount) return res.status(404).json({ error: 'User not found' });

    // Upsert a join request marked as approved (auto-approve since host initiated)
    const existing = await pool.query(
      'SELECT id FROM live_join_requests WHERE stream_id=$1 AND user_id=$2',
      [id, guestId]
    );
    let rid;
    if (existing.rowCount){
      await pool.query("UPDATE live_join_requests SET status='approved', updated_at=NOW() WHERE id=$1", [existing.rows[0].id]);
      rid = existing.rows[0].id;
    } else {
      const ins = await pool.query(
        "INSERT INTO live_join_requests (stream_id, user_id, status) VALUES ($1,$2,'approved') RETURNING id",
        [id, guestId]
      );
      rid = ins.rows[0].id;
    }

    // Generate publisher token
    const me = await pool.query('SELECT display_name FROM users WHERE id=$1', [req.user.id]);
    const guestName = gu.rows[0].display_name || 'Guest';
    let token = null;
    try {
      if (typeof livekitGenerateToken === 'function' && own.rows[0].room_name){
        token = await livekitGenerateToken(own.rows[0].room_name, guestId, guestName, true);
      }
    } catch(_){}

    // Notify guest
    io.to('user:' + guestId).emit('live-join-approved', {
      stream_id: id,
      request_id: rid,
      room: own.rows[0].room_name,
      token: token,
      invited: true,
      host_name: me.rows[0] && me.rows[0].display_name
    });

    console.log('🎬 Host invited user', guestId, 'to co-host stream', id);
    res.json({ ok: true, request_id: rid });
  } catch(e){ console.error('live/invite:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/live/:id/approve/:rid — host approves a request
app.post('/api/live/:id/approve/:rid', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const rid = Number(req.params.rid);
    const own = await pool.query('SELECT streamer_id, room_name, status FROM live_streams WHERE id=$1', [id]);
    if (!own.rowCount) return res.status(404).json({ error: 'Stream not found' });
    if (own.rows[0].streamer_id !== req.user.id) return res.status(403).json({ error: 'Not your stream' });
    if (own.rows[0].status !== 'live') return res.status(410).json({ error: 'Stream ended' });

    const rq = await pool.query("SELECT id, user_id FROM live_join_requests WHERE id=$1 AND stream_id=$2 AND status='pending'", [rid, id]);
    if (!rq.rowCount) return res.status(404).json({ error: 'Request not found' });

    const guestId = rq.rows[0].user_id;
    const u = await pool.query('SELECT display_name FROM users WHERE id=$1', [guestId]);
    const guestName = (u.rows[0] && u.rows[0].display_name) || 'Guest';

    // Upgrade their token to publisher
    const pubToken = await livekitGenerateToken(own.rows[0].room_name, guestId, guestName, true);

    await pool.query("UPDATE live_join_requests SET status='approved', updated_at=NOW() WHERE id=$1", [rid]);

    // Notify guest with the new token
    io.to('user:' + guestId).emit('live-join-approved', {
      stream_id: id,
      room: own.rows[0].room_name,
      token: pubToken,
      host_name: (await pool.query('SELECT display_name FROM users WHERE id=$1', [req.user.id])).rows[0].display_name
    });

    // Also tell other viewers someone joined
    io.emit('live-guest-joined', { stream_id: id, user_id: guestId, name: guestName });

    res.json({ ok: true, guest_id: guestId });
  } catch(e){ console.error('live/approve:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/live/:id/reject/:rid — host rejects
app.post('/api/live/:id/reject/:rid', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const rid = Number(req.params.rid);
    const own = await pool.query('SELECT streamer_id FROM live_streams WHERE id=$1', [id]);
    if (!own.rowCount) return res.status(404).json({ error: 'Stream not found' });
    if (own.rows[0].streamer_id !== req.user.id) return res.status(403).json({ error: 'Not your stream' });

    const rq = await pool.query('SELECT user_id FROM live_join_requests WHERE id=$1 AND stream_id=$2', [rid, id]);
    if (!rq.rowCount) return res.status(404).json({ error: 'Request not found' });

    await pool.query("UPDATE live_join_requests SET status='rejected', updated_at=NOW() WHERE id=$1", [rid]);
    io.to('user:' + rq.rows[0].user_id).emit('live-join-rejected', { stream_id: id });
    res.json({ ok: true });
  } catch(e){ console.error('live/reject:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/live/:id/leave-guest — guest leaves co-host position
app.post('/api/live/:id/leave-guest', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    await pool.query("UPDATE live_join_requests SET status='left', updated_at=NOW() WHERE stream_id=$1 AND user_id=$2 AND status='approved'", [id, req.user.id]);
    const u = await pool.query('SELECT display_name FROM users WHERE id=$1', [req.user.id]);
    io.emit('live-guest-left', { stream_id: id, user_id: req.user.id, name: (u.rows[0] && u.rows[0].display_name) });
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

/* GISTAPP_RESUME_TOKEN — get fresh publisher token for an active stream */
app.post('/api/live/resume-token', auth, async (req, res) => {
  try {
    if (!LIVEKIT_READY) return res.status(503).json({ error: 'LiveKit not configured' });
    const id = Number(req.body && req.body.id);
    if (!id) return res.status(400).json({ error: 'Missing id' });
    const r = await pool.query('SELECT id, streamer_id, room_name, status FROM live_streams WHERE id=$1', [id]);
    if (!r.rowCount) return res.status(404).json({ error: 'Stream not found' });
    if (r.rows[0].streamer_id !== req.user.id) return res.status(403).json({ error: 'Not your stream' });
    if (r.rows[0].status !== 'live') return res.status(410).json({ error: 'Stream ended' });

    const me = await pool.query('SELECT display_name FROM users WHERE id=$1', [req.user.id]);
    const name = (me.rows[0] && me.rows[0].display_name) || 'Streamer';
    const token = await livekitGenerateToken(r.rows[0].room_name, req.user.id, name, true);
    res.json({ ok: true, url: LIVEKIT_URL, token: token, room: r.rows[0].room_name });
  } catch(e){ console.error('resume-token:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* GISTAPP_STREAM_SUMMARY — end-of-stream stats */
app.get('/api/live/:id/summary', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const s = await pool.query(
      'SELECT id, streamer_id, title, status, viewer_count, peak_viewers, gift_count, started_at, ended_at, follower_gain FROM live_streams WHERE id=$1',
      [id]
    );
    if (!s.rowCount) return res.status(404).json({ error: 'Not found' });
    const stream = s.rows[0];
    if (stream.streamer_id !== req.user.id) return res.status(403).json({ error: 'Not your stream' });

    // Duration
    const ended = stream.ended_at ? new Date(stream.ended_at) : new Date();
    const durationSec = Math.max(0, Math.floor((ended - new Date(stream.started_at)) / 1000));

    // Coins earned from this stream
    const earnR = await pool.query(
      'SELECT COALESCE(SUM(coins),0)::int AS total FROM live_gifts WHERE stream_id=$1',
      [id]
    );
    const grossCoins = earnR.rows[0].total;
    const creatorCoins = Math.floor(grossCoins * 0.7);

    // Top gifter
    const tg = await pool.query(
      'SELECT g.user_id, SUM(g.coins)::int AS total, u.display_name, u.avatar_color, u.avatar_url FROM live_gifts g JOIN users u ON u.id=g.user_id WHERE g.stream_id=$1 GROUP BY g.user_id, u.display_name, u.avatar_color, u.avatar_url ORDER BY total DESC LIMIT 1',
      [id]
    );
    const topGifter = tg.rows[0] || null;

    // Chat message count
    const cc = await pool.query("SELECT COUNT(*)::int AS n FROM live_chat_messages WHERE stream_id=$1 AND kind='chat'", [id]);

    // Join requests received
    const jr = await pool.query('SELECT COUNT(*)::int AS n FROM live_join_requests WHERE stream_id=$1', [id]);

    res.json({
      id: stream.id,
      title: stream.title,
      started_at: stream.started_at,
      ended_at: stream.ended_at,
      duration_sec: durationSec,
      peak_viewers: stream.peak_viewers || 0,
      final_viewers: stream.viewer_count || 0,
      gross_coins: grossCoins,
      creator_coins: creatorCoins,
      creator_ngn: Math.floor(creatorCoins / 10),
      gift_count: stream.gift_count || 0,
      top_gifter: topGifter,
      chat_messages: cc.rows[0].n,
      join_requests: jr.rows[0].n
    });
  } catch(e){ console.error('summary:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* GISTAPP_EARNINGS_V1 — leaderboard + wallet + withdrawals */

const GIFT_COINS = { rose: 1, heart: 5, fire: 10, star: 25, cake: 50, crown: 100, gem: 500, rocket: 1000 };
const CREATOR_SHARE = 0.7; // 70% to streamer, 30% platform
const COINS_PER_NGN = 10;   // 10 coins = ₦1
const MIN_PAYOUT_BY_REGION = { NG: 20000, US: 50000, GB: 50000, default: 50000 }; // 20k coins = ₦2000

// GET /api/live/:id/top-gifters — leaderboard
app.get('/api/live/:id/top-gifters', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query(
      'SELECT g.user_id, SUM(g.coins)::int AS total_coins, COUNT(*)::int AS gift_count, u.display_name, u.avatar_color, u.avatar_url, u.subscription_tier FROM live_gifts g JOIN users u ON u.id=g.user_id WHERE g.stream_id=$1 GROUP BY g.user_id, u.display_name, u.avatar_color, u.avatar_url, u.subscription_tier ORDER BY total_coins DESC LIMIT 10',
      [id]
    );
    res.json(r.rows);
  } catch(e){ console.error('top-gifters:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// GET /api/wallet — current balance + recent transactions
app.get('/api/wallet', auth, async (req, res) => {
  try {
    const me = await pool.query('SELECT wallet_balance_coins, lifetime_earned_coins, country, payout_method, payout_account, payout_name FROM users WHERE id=$1', [req.user.id]);
    const tx = await pool.query('SELECT id, kind, coins, meta, created_at FROM wallet_transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 30', [req.user.id]);
    const pending = await pool.query("SELECT COALESCE(SUM(coins),0)::int AS n FROM withdrawal_requests WHERE user_id=$1 AND status='pending'", [req.user.id]);
    const u = me.rows[0] || {};
    res.json({
      balance_coins: u.wallet_balance_coins || 0,
      lifetime_coins: u.lifetime_earned_coins || 0,
      pending_coins: pending.rows[0].n || 0,
      available_ngn: Math.floor(((u.wallet_balance_coins || 0) - (pending.rows[0].n || 0)) / COINS_PER_NGN),
      coins_per_ngn: COINS_PER_NGN,
      country: u.country || 'NG',
      min_payout_coins: MIN_PAYOUT_BY_REGION[u.country] || MIN_PAYOUT_BY_REGION.default,
      payout_method: u.payout_method,
      payout_account: u.payout_account,
      payout_name: u.payout_name,
      transactions: tx.rows
    });
  } catch(e){ console.error('wallet:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/wallet/payout-info — save bank/momo details
app.post('/api/wallet/payout-info', auth, async (req, res) => {
  try {
    const { method, account, name, country } = req.body || {};
    if (!method || !account || !name) return res.status(400).json({ error: 'Method, account, and name required' });
    await pool.query('UPDATE users SET payout_method=$1, payout_account=$2, payout_name=$3, country=COALESCE($4, country) WHERE id=$5',
      [String(method).slice(0,20), String(account).slice(0,40), String(name).slice(0,80), country ? String(country).slice(0,3).toUpperCase() : null, req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error('payout-info:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/wallet/withdraw — request payout
app.post('/api/wallet/withdraw', auth, async (req, res) => {
  try {
    const coins = Number((req.body && req.body.coins) || 0);
    if (!coins || coins < 100) return res.status(400).json({ error: 'Minimum 100 coins' });
    const me = await pool.query('SELECT wallet_balance_coins, payout_method, payout_account, payout_name, country FROM users WHERE id=$1', [req.user.id]);
    const u = me.rows[0] || {};
    const min = MIN_PAYOUT_BY_REGION[u.country] || MIN_PAYOUT_BY_REGION.default;
    if (coins < min) return res.status(400).json({ error: 'Minimum ' + min + ' coins for your region' });
    if (!u.payout_method || !u.payout_account || !u.payout_name) return res.status(400).json({ error: 'Add payout info first' });
    const pending = await pool.query("SELECT COALESCE(SUM(coins),0)::int AS n FROM withdrawal_requests WHERE user_id=$1 AND status='pending'", [req.user.id]);
    const available = (u.wallet_balance_coins || 0) - (pending.rows[0].n || 0);
    if (coins > available) return res.status(400).json({ error: 'Insufficient available balance' });
    const ngn = Math.floor(coins / COINS_PER_NGN);
    const ins = await pool.query(
      'INSERT INTO withdrawal_requests (user_id, coins, ngn_amount, method, account_number, account_name) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, coins, ngn_amount, status, created_at',
      [req.user.id, coins, ngn, u.payout_method, u.payout_account, u.payout_name]
    );
    await pool.query('INSERT INTO wallet_transactions (user_id, kind, coins, meta) VALUES ($1,$2,$3,$4)',
      [req.user.id, 'withdraw_request', -coins, JSON.stringify({ request_id: ins.rows[0].id, ngn }) ]);
    console.log('💰 Withdrawal requested: user', req.user.id, coins, 'coins =', ngn, 'NGN');
    res.json({ ok: true, request: ins.rows[0] });
  } catch(e){ console.error('withdraw:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// GET /api/admin/withdrawals — admin list
app.get('/api/admin/withdrawals', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query("SELECT w.id, w.user_id, w.coins, w.ngn_amount, w.method, w.account_number, w.account_name, w.status, w.created_at, u.email, u.display_name FROM withdrawal_requests w JOIN users u ON u.id=w.user_id WHERE w.status IN ('pending','processing') ORDER BY w.created_at ASC LIMIT 100");
    res.json(r.rows);
  } catch(e){ console.error('admin withdrawals:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/admin/withdrawals/:id/approve
app.post('/api/admin/withdrawals/:id/approve', auth, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const note = (req.body && req.body.note || '').slice(0, 300);
    const w = await pool.query("SELECT id, user_id, coins, status FROM withdrawal_requests WHERE id=$1", [id]);
    if (!w.rowCount) return res.status(404).json({ error: 'Not found' });
    if (w.rows[0].status === 'paid') return res.json({ ok: true, already: true });
    // Deduct from balance and mark paid
    await pool.query('UPDATE users SET wallet_balance_coins = GREATEST(0, wallet_balance_coins - $1) WHERE id=$2', [w.rows[0].coins, w.rows[0].user_id]);
    await pool.query("UPDATE withdrawal_requests SET status='paid', admin_note=$1, processed_at=NOW() WHERE id=$2", [note, id]);
    await pool.query('INSERT INTO wallet_transactions (user_id, kind, coins, meta) VALUES ($1,$2,$3,$4)',
      [w.rows[0].user_id, 'withdraw_paid', 0, JSON.stringify({ request_id: id, note }) ]);
    console.log('✅ Withdrawal paid: request', id, 'user', w.rows[0].user_id);
    res.json({ ok: true });
  } catch(e){ console.error('approve withdrawal:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/admin/withdrawals/:id/reject
app.post('/api/admin/withdrawals/:id/reject', auth, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const note = (req.body && req.body.note || '').slice(0, 300);
    const w = await pool.query("SELECT id, user_id, coins, status FROM withdrawal_requests WHERE id=$1", [id]);
    if (!w.rowCount) return res.status(404).json({ error: 'Not found' });
    await pool.query("UPDATE withdrawal_requests SET status='rejected', admin_note=$1, processed_at=NOW() WHERE id=$2", [note, id]);
    await pool.query('INSERT INTO wallet_transactions (user_id, kind, coins, meta) VALUES ($1,$2,$3,$4)',
      [w.rows[0].user_id, 'withdraw_rejected', w.rows[0].coins, JSON.stringify({ request_id: id, note }) ]);
    res.json({ ok: true });
  } catch(e){ console.error('reject withdrawal:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* GISTAPP_LIVE_BATCH_BE */

app.get('/api/live/:id/chat', auth, async (req, res) => { try { const id = Number(req.params.id); const r = await pool.query('SELECT m.id, m.text, m.kind, m.created_at, u.id AS user_id, u.display_name, u.avatar_color, u.avatar_url, u.subscription_tier FROM live_chat_messages m JOIN users u ON u.id=m.user_id WHERE m.stream_id=$1 ORDER BY m.created_at DESC LIMIT 100', [id]); res.json(r.rows.reverse()); } catch(e){ console.error('live chat list:', e.message); res.status(500).json({ error: 'Server error' }); } });
app.post('/api/live/:id/chat', auth, async (req, res) => { try { const id = Number(req.params.id); const text = String((req.body && req.body.text) || '').trim().slice(0,300); if (!text) return res.status(400).json({ error: 'Empty message' }); const s = await pool.query('SELECT id, streamer_id, status FROM live_streams WHERE id=$1', [id]); if (!s.rowCount || s.rows[0].status !== 'live') return res.status(410).json({ error: 'Stream ended' }); const ins = await pool.query("INSERT INTO live_chat_messages (stream_id, user_id, text, kind) VALUES ($1,$2,$3,'chat') RETURNING id, created_at", [id, req.user.id, text]); const u = await pool.query('SELECT display_name, avatar_color, avatar_url, subscription_tier FROM users WHERE id=$1', [req.user.id]); const full = { id: ins.rows[0].id, text, kind: 'chat', created_at: ins.rows[0].created_at, user_id: req.user.id, display_name: u.rows[0].display_name, avatar_color: u.rows[0].avatar_color, avatar_url: u.rows[0].avatar_url, subscription_tier: u.rows[0].subscription_tier }; io.to('live:'+id).emit('live-chat', full); res.json(full); } catch(e){ console.error('live chat post:', e.message); res.status(500).json({ error: 'Server error' }); } });
app.post('/api/live/:id/gift', auth, async (req, res) => { try { const id = Number(req.params.id); const giftType = String((req.body && req.body.gift) || 'heart').slice(0,40); const s = await pool.query('SELECT id, streamer_id, status FROM live_streams WHERE id=$1', [id]); if (!s.rowCount || s.rows[0].status !== 'live') return res.status(410).json({ error: 'Stream ended' }); await pool.query('UPDATE live_streams SET gift_count = gift_count + 1 WHERE id=$1', [id]);
    // GISTAPP_EARNINGS_V1 — record gift + credit streamer
    const _coins = GIFT_COINS[giftType] || 1;
    try {
      await pool.query('INSERT INTO live_gifts (stream_id, user_id, gift_type, coins) VALUES ($1,$2,$3,$4)', [id, req.user.id, giftType, _coins]);
      const _creatorShare = Math.floor(_coins * CREATOR_SHARE);
      await pool.query('UPDATE users SET wallet_balance_coins = COALESCE(wallet_balance_coins,0) + $1, lifetime_earned_coins = COALESCE(lifetime_earned_coins,0) + $1 WHERE id=$2', [_creatorShare, s.rows[0].streamer_id]);
      await pool.query('INSERT INTO wallet_transactions (user_id, kind, coins, meta) VALUES ($1,$2,$3,$4)',
        [s.rows[0].streamer_id, 'gift_earn', _creatorShare, JSON.stringify({ from_user: req.user.id, gift: giftType, stream_id: id, gross: _coins }) ]);
    } catch(_giftErr){ console.warn('gift record:', _giftErr.message); } const u = await pool.query('SELECT display_name, avatar_url, avatar_color FROM users WHERE id=$1', [req.user.id]); io.to('live:'+id).emit('live-gift', { stream_id: id, gift: giftType, user_id: req.user.id, display_name: u.rows[0].display_name, avatar_color: u.rows[0].avatar_color, avatar_url: u.rows[0].avatar_url, ts: Date.now() });
    // GISTAPP_GIFT_EMAIL — notify streamer via email if they're offline (socket disconnected)
    try {
      const _streamerId = Number(s.rows[0].streamer_id);
      const _isOnline = onlineUsers.has(_streamerId) && (onlineUsers.get(_streamerId) || 0) > 0;
      if (!_isOnline){
        const _lastSent = _giftEmailLastSent.get(_streamerId) || 0;
        const _oneHourAgo = Date.now() - 60 * 60 * 1000;
        if (_lastSent < _oneHourAgo){
          const _info = await pool.query('SELECT email, display_name, prefs FROM users WHERE id=$1', [_streamerId]);
          if (_info.rowCount && _info.rows[0].email){
            const _prefs = _info.rows[0].prefs || {};
            if (_prefs.gift_emails !== 'false'){
              _giftEmailLastSent.set(_streamerId, Date.now());
              const _streamRow = await pool.query('SELECT title FROM live_streams WHERE id=$1', [id]);
              // GISTAPP_GIFT_EMAIL_COINFIX — read actual amounts from live_gifts (avoid recompute drift)
              let _actualGiftCoins = _coins;
              let _actualCreatorShare = 0;
              try {
                const _gt = await pool.query(
                  'SELECT coins FROM live_gifts WHERE stream_id=$1 AND user_id=$2 ORDER BY id DESC LIMIT 1',
                  [id, req.user.id]
                );
                if (_gt.rowCount) _actualGiftCoins = _gt.rows[0].coins || 1;
              } catch(_){}
              _actualCreatorShare = Math.max(1, Math.floor(_actualGiftCoins * CREATOR_SHARE));
              sendGiftEmail(_info.rows[0].email, _info.rows[0].display_name, {
                sender_name: u.rows[0].display_name,
                gift_type: giftType,
                coins: _actualGiftCoins,
                creator_coins: _actualCreatorShare,
                stream_title: (_streamRow.rows[0] && _streamRow.rows[0].title) || 'your live stream'
              }).catch(function(){});
            }
          }
        }
      }
    } catch(_giftEmailErr){
      console.warn('gift email hook:', _giftEmailErr && _giftEmailErr.message);
    }
    res.json({ ok: true }); } catch(e){ console.error('live gift:', e.message); res.status(500).json({ error: 'Server error' }); } });
app.delete('/api/live/:id/chat/:mid', auth, async (req, res) => { try { const id = Number(req.params.id); const mid = Number(req.params.mid); const own = await pool.query('SELECT streamer_id FROM live_streams WHERE id=$1', [id]); if (!own.rowCount) return res.status(404).json({ error: 'Stream not found' }); if (own.rows[0].streamer_id !== req.user.id) return res.status(403).json({ error: 'Only host' }); await pool.query('DELETE FROM live_chat_messages WHERE id=$1 AND stream_id=$2', [mid, id]); io.to('live:'+id).emit('live-chat-delete', { id, message_id: mid }); res.json({ ok: true }); } catch(e){ console.error('live del chat:', e.message); res.status(500).json({ error: 'Server error' }); } });
app.post('/api/live/:id/ban/:uid', auth, async (req, res) => { try { const id = Number(req.params.id); const uid = Number(req.params.uid); const own = await pool.query('SELECT streamer_id FROM live_streams WHERE id=$1', [id]); if (!own.rowCount) return res.status(404).json({ error: 'Stream not found' }); if (own.rows[0].streamer_id !== req.user.id) return res.status(403).json({ error: 'Only host' }); await pool.query("INSERT INTO live_chat_messages (stream_id, user_id, text, kind) VALUES ($1,$2,'','ban')", [id, uid]); await pool.query("UPDATE live_join_requests SET status='kicked' WHERE stream_id=$1 AND user_id=$2", [id, uid]); io.to('user:'+uid).emit('live-kicked', { stream_id: id }); res.json({ ok: true }); } catch(e){ console.error('live ban:', e.message); res.status(500).json({ error: 'Server error' }); } });
app.post('/api/live/:id/kick-guest/:uid', auth, async (req, res) => { try { const id = Number(req.params.id); const uid = Number(req.params.uid); const own = await pool.query('SELECT streamer_id, room_name FROM live_streams WHERE id=$1', [id]); if (!own.rowCount) return res.status(404).json({ error: 'Stream not found' }); if (own.rows[0].streamer_id !== req.user.id) return res.status(403).json({ error: 'Only host' }); await pool.query("UPDATE live_join_requests SET status='kicked' WHERE stream_id=$1 AND user_id=$2", [id, uid]); io.to('user:'+uid).emit('live-kicked', { stream_id: id, reason: 'Removed by host' }); io.to('live:'+id).emit('live-guest-left', { stream_id: id, user_id: uid }); res.json({ ok: true }); } catch(e){ console.error('live kick:', e.message); res.status(500).json({ error: 'Server error' }); } });

/* ---------- OPay bank transfer ---------- GISTAPP_OPAY_V1 */
const OPAY_ACCOUNT = {
  bank: 'OPay',
  account_number: '7071690772',
  account_name: 'PERION DEVELOPMENT LTD'
};

// GET /api/billing/manual-info — returns OPay details + reference for current user
app.get('/api/billing/manual-info', auth, async (req, res) => {
  try {
    // Generate a unique reference for this user
    const r = await pool.query('SELECT id, email, display_name FROM users WHERE id=$1', [req.user.id]);
    if (!r.rowCount) return res.status(404).json({ error: 'Not found' });
    const u = r.rows[0];
    const shortId = String(u.id).padStart(4, '0');
    const ref = 'GIST-' + shortId + '-' + Math.random().toString(36).slice(2, 6).toUpperCase();

    // Store as pending payment
    const existing = await pool.query(
      "SELECT id, reference_id, plan, amount FROM payments WHERE user_id=$1 AND status='awaiting_manual' ORDER BY created_at DESC LIMIT 1",
      [req.user.id]
    );
    let payment = existing.rows[0];
    if (!payment){
      const ins = await pool.query(
        "INSERT INTO payments (user_id, reference_id, amount, phone, status, plan, method) VALUES ($1,$2,$3,'opay','awaiting_manual','pro','manual') RETURNING id, reference_id, plan, amount",
        [req.user.id, ref, 7500]
      );
      payment = ins.rows[0];
    }

    res.json({
      bank: OPAY_ACCOUNT.bank,
      account_number: OPAY_ACCOUNT.account_number,
      account_name: OPAY_ACCOUNT.account_name,
      reference: payment.reference_id,
      amount: payment.amount,
      plan: payment.plan,
      note: 'Transfer the exact amount and include the reference in the transfer description.'
    });
  } catch(e){ console.error('manual-info:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/billing/manual-submit — user says "I've paid"
app.post('/api/billing/manual-submit', auth, async (req, res) => {
  try {
    const { reference, payer_name, payer_bank, notes, plan } = req.body || {};
    if (!reference) return res.status(400).json({ error: 'Missing reference' });
    if (!payer_name) return res.status(400).json({ error: 'Enter the name on your transfer' });

    const pl = await pool.query(
      'SELECT id, plan, amount, status FROM payments WHERE reference_id=$1 AND user_id=$2',
      [reference, req.user.id]
    );
    if (!pl.rowCount) return res.status(404).json({ error: 'Payment not found' });
    if (pl.rows[0].status === 'success') return res.json({ ok: true, already: true });

    await pool.query(`
      UPDATE payments
      SET status='submitted',
          payer_name=$1,
          payer_bank=$2,
          notes=$3,
          submitted_at=NOW()
      WHERE id=$4
    `, [payer_name.slice(0,80), (payer_bank||'').slice(0,40), (notes||'').slice(0,300), pl.rows[0].id]);

    // Notify admins (log only for now — could email later)
    console.log('💰 Manual payment submitted:', reference, 'by user', req.user.id, '—', payer_name);

    res.json({ ok: true, message: 'Submitted — admin will verify and activate your plan shortly.' });
  } catch(e){ console.error('manual-submit:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// GET /api/billing/manual-status/:ref — check approval status
app.get('/api/billing/manual-status/:ref', auth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT status FROM payments WHERE reference_id=$1 AND user_id=$2',
      [req.params.ref, req.user.id]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'Not found' });
    res.json({ status: r.rows[0].status });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

// GET /api/admin/manual-payments — list pending
app.get('/api/admin/manual-payments', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT p.id, p.reference_id, p.amount, p.plan, p.payer_name, p.payer_bank, p.notes,
             p.status, p.created_at, p.submitted_at,
             u.id AS user_id, u.email, u.display_name
      FROM payments p
      JOIN users u ON u.id = p.user_id
      WHERE p.method='manual' AND p.status IN ('awaiting_manual','submitted')
      ORDER BY p.submitted_at DESC NULLS LAST, p.created_at DESC
      LIMIT 50
    `);
    res.json(r.rows);
  } catch(e){ console.error('admin manual list:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/admin/manual-approve/:id
app.post('/api/admin/manual-approve/:id', auth, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid id' });
    const p = await pool.query('SELECT id, user_id, plan, status FROM payments WHERE id=$1', [id]);
    if (!p.rowCount) return res.status(404).json({ error: 'Not found' });
    if (p.rows[0].status === 'success') return res.json({ ok: true, already: true });

    const planKey = p.rows[0].plan || 'pro';
    const plan = PLANS[planKey] || PLANS.pro;

    await pool.query(`
      UPDATE users
      SET subscription_tier=$2, subscription_status='active',
          subscription_ends_at = NOW() + INTERVAL '1 day' * $3
      WHERE id=$1
    `, [p.rows[0].user_id, planKey, plan.days]);

    await pool.query("UPDATE payments SET status='success', completed_at=NOW() WHERE id=$1", [id]);

    // GISTAPP_PAYMENT_RECEIPT — send receipt for manual (OPay) payment
    try {
      const _full = await pool.query('SELECT amount, reference_id, method FROM payments WHERE id=$1', [id]);
      const _u = await pool.query('SELECT email, display_name FROM users WHERE id=$1', [p.rows[0].user_id]);
      if (_u.rowCount && _full.rowCount){
        sendPaymentReceiptEmailWithInvoice(_u.rows[0].email, _u.rows[0].display_name, {
          plan: planKey,
          amount: _full.rows[0].amount || plan.price || 0,
          method: 'manual',
          reference: _full.rows[0].reference_id || ('PAY-' + id),
          completed_at: new Date().toISOString(),
          days: plan.days,
          payment_id: id
        }).catch(function(){});
      }
    } catch(_){}

    console.log('✅ Manual payment approved — user', p.rows[0].user_id, 'plan', planKey);
    res.json({ ok: true });
  } catch(e){ console.error('manual-approve:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/admin/manual-reject/:id
app.post('/api/admin/manual-reject/:id', auth, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const reason = (req.body && req.body.reason || 'Payment not confirmed').slice(0,200);
    await pool.query("UPDATE payments SET status='failed', notes=COALESCE(notes,'') || ' | REJECTED: ' || $1 WHERE id=$2", [reason, id]);
    res.json({ ok: true });
  } catch(e){ console.error('manual-reject:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- admin + backups ---------- GISTAPP_BACKUPS_V1 */
const ADMIN_EMAILS = new Set(['isaiahmumudevelop@gmail.com']);

// Auto-promote admin on boot
(async () => {
  try {
    for (const email of ADMIN_EMAILS){
      await pool.query('UPDATE users SET is_admin=true WHERE LOWER(email)=$1 AND (is_admin IS NULL OR is_admin=false)', [email.toLowerCase()]);
    }
  } catch(e){ console.warn('admin promote:', e.message); }
})();

async function adminOnly(req, res, next){
  try {
    const r = await pool.query('SELECT is_admin FROM users WHERE id=$1', [req.user.id]);
    if (!r.rowCount || !r.rows[0].is_admin) return res.status(403).json({ error: 'Admin only' });
    next();
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
}

/* GISTAPP_WEEKLY_DIGEST — admin trigger for testing */
app.post('/api/admin/send-digests-now', auth, adminOnly, async (req, res) => {
  try {
    const baseUrl = process.env.APP_URL || 'https://gistapp.onrender.com';
    const limit = Math.min(Number(req.body && req.body.limit) || 5, 20);
    const r = await pool.query(
      "SELECT id, email, display_name, prefs FROM users WHERE verified=true AND email IS NOT NULL AND COALESCE(prefs->>'weekly_digest','true') <> 'false' ORDER BY id DESC LIMIT $1",
      [limit]
    );
    let sent = 0, errors = [];
    for (const u of r.rows){
      try {
        const stats = await _getUserWeeklyStats(u.id);
        const html = _digestHTML(u.display_name || 'there', stats, u.id, baseUrl);
        await mailer.sendMail({
          from: '"GistApp" <' + GMAIL_SENDER + '>',
          to: u.email,
          replyTo: process.env.SMTP_USER,
          subject: 'Your week on GistApp, ' + (u.display_name || 'there') + ' 📊',
          headers: {
            'X-Priority': '3',
            'Importance': 'normal',
            'List-Unsubscribe': '<' + baseUrl + '/api/email/unsub-digest?u=' + u.id + '&t=' + _digestToken(u.id) + '>'
          },
          html: html
        });
        sent++;
        await new Promise(r => setTimeout(r, 200));
      } catch(e){ errors.push({ email: u.email, err: e.message }); }
    }
    res.json({ ok: true, sent: sent, errors: errors });
  } catch(e){ console.error('digest-admin:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* GISTAPP_CRON_ENDPOINT — external cron trigger for weekly digest */
/* Usage: GET /api/cron/weekly-digest?key=<CRON_SECRET>
   Set CRON_SECRET in Render env vars. Falls back to JWT_SECRET if unset. */
app.get('/api/cron/weekly-digest', async (req, res) => {
  const expected = process.env.CRON_SECRET || process.env.JWT_SECRET;
  const provided = String(req.query.key || '');
  if (!expected || provided !== expected){
    return res.status(403).json({ error: 'Forbidden' });
  }
  // Respond immediately — run in background so cold starts don't fail the cron
  res.json({ ok: true, triggered: true, at: new Date().toISOString() });
  setImmediate(function(){
    sendWeeklyDigests(true).catch(function(e){ console.warn('cron digest error:', e && e.message); });
  });
});

/* GISTAPP_MARKETING_EMAIL — admin broadcast to segments */
function _marketingToken(uid){
  return crypto_digest.createHmac('sha256', JWT_SECRET).update('marketing-unsub:' + uid).digest('hex').slice(0, 32);
}

function _marketingSegmentWhere(segment){
  switch(segment){
    case 'pro':      return "subscription_tier='pro'";
    case 'business': return "subscription_tier='business'";
    case 'free':     return "(subscription_tier IS NULL OR subscription_tier='free')";
    case 'active':   return "last_seen_at > NOW() - INTERVAL '30 days'";
    case 'inactive': return "(last_seen_at < NOW() - INTERVAL '30 days' OR last_seen_at IS NULL)";
    case 'all':
    default:         return "1=1";
  }
}

function _marketingHTML(subject, previewText, bodyHTML, uid, baseUrl){
  const tok = _marketingToken(uid);
  const unsubUrl = baseUrl + '/api/email/unsub-marketing?u=' + uid + '&t=' + tok;
  const settingsUrl = baseUrl + '/?settings=notifications';
  const preview = previewText ? String(previewText) : '';

  return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + subject + '</title></head>' +
  '<body style="margin:0;padding:0;background:#f2f0fa;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Inter,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased">' +
  (preview ? '<div style="display:none;font-size:1px;color:#f2f0fa;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden">' + preview + '</div>' : '') +
  '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f2f0fa;padding:24px 12px">' +
  '<tr><td align="center">' +
  '<table role="presentation" width="560" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:24px;overflow:hidden;box-shadow:0 12px 40px rgba(51,52,76,.10)">' +
  '<tr><td style="background:linear-gradient(135deg,#2b2c44 0%,#5a6cd6 55%,#7b8cff 100%);padding:24px 32px;text-align:center">' +
  '<img src="' + baseUrl + '/icon-192.png" alt="GistApp" width="48" height="48" style="border-radius:12px;display:block;margin:0 auto 8px;box-shadow:0 8px 20px rgba(0,0,0,.3)">' +
  '<div style="color:#ffffff;font-size:12px;font-weight:700;letter-spacing:1.6px;text-transform:uppercase;opacity:.85">GistApp Team</div>' +
  '</td></tr>' +
  '<tr><td style="padding:32px 32px 8px">' +
  '<h1 style="margin:0 0 16px;color:#1c1c22;font-size:22px;font-weight:800;letter-spacing:-.4px;line-height:1.3">' + subject + '</h1>' +
  '<div style="color:#4a4a55;font-size:15px;line-height:1.7">' + bodyHTML + '</div>' +
  '</td></tr>' +
  '<tr><td style="padding:28px 32px 34px;text-align:center">' +
  '<a href="' + baseUrl + '" style="background:#2b2c44;color:#ffffff;text-decoration:none;padding:14px 40px;border-radius:14px;font-weight:800;display:inline-block;font-size:14.5px;letter-spacing:.2px">Open GistApp</a>' +
  '</td></tr>' +
  '<tr><td style="background:#f7f6fc;padding:18px 32px;text-align:center;border-top:1px solid #eae7f5">' +
  '<p style="margin:0 0 8px;color:#8e8e93;font-size:11.5px;line-height:1.6">You are receiving this because you have a GistApp account.</p>' +
  '<p style="margin:0;color:#a8a5b3;font-size:11px;line-height:1.6">' +
  '<a href="' + settingsUrl + '" style="color:#5a6cd6;text-decoration:none;font-weight:600">Manage preferences</a> &middot; ' +
  '<a href="' + unsubUrl + '" style="color:#5a6cd6;text-decoration:none;font-weight:600">Unsubscribe</a>' +
  '</p>' +
  '<p style="margin:8px 0 0;color:#a8a5b3;font-size:10.5px">&copy; ' + new Date().getFullYear() + ' GistApp Community &middot; All rights reserved.</p>' +
  '</td></tr>' +
  '</table></td></tr></table></body></html>';
}

/* GISTAPP_RENEWAL_REMINDER — admin trigger for testing */
app.post('/api/admin/check-renewals-now', auth, adminOnly, async (req, res) => {
  try {
    const force = !!(req.body && req.body.force);
    if (force){
      // Force mode — ignore already-sent markers, send to test user only
      const targetId = Number((req.body && req.body.user_id) || 0) || req.user.id;
      const u = await pool.query(
        "SELECT id, email, display_name, subscription_tier, subscription_ends_at, COALESCE(auto_renew,false) AS auto_renew FROM users WHERE id=$1",
        [targetId]
      );
      if (!u.rowCount) return res.status(404).json({ error: 'User not found' });
      const row = u.rows[0];
      const endsAt = row.subscription_ends_at || new Date(Date.now() + 5 * 24 * 60 * 60 * 1000);
      const daysLeft = Math.ceil((new Date(endsAt) - Date.now()) / (24 * 60 * 60 * 1000));
      await sendRenewalReminderEmail(row.email, row.display_name, {
        plan: row.subscription_tier || 'pro',
        days_left: daysLeft,
        ends_at: endsAt,
        auto_renew: row.auto_renew
      });
      return res.json({ ok: true, force: true, sent_to: row.email, days_left: daysLeft });
    }
    await checkSubscriptionRenewals();
    res.json({ ok: true, triggered: true });
  } catch(e){ console.error('check-renewals-now:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* POST /api/admin/marketing/send
   Body: { segment, subject, preview, body, cta_url?, test? }
   - segment: all | pro | business | free | active | inactive
   - test: if true, sends only to admin's own email
   - dry: if true, returns recipient count without sending (safety)
*/
app.post('/api/admin/marketing/send', auth, adminOnly, async (req, res) => {
  try {
    const b = req.body || {};
    const segment = String(b.segment || 'all');
    const subject = String(b.subject || '').slice(0, 180).trim();
    const preview = String(b.preview || '').slice(0, 200).trim();
    const bodyRaw = String(b.body || '').slice(0, 8000).trim();
    const test = !!b.test;
    const dry = !!b.dry;

    if (!subject || !bodyRaw) return res.status(400).json({ error: 'subject and body required' });

    // Convert plaintext to safe HTML paragraphs (no arbitrary HTML injection)
    const escapeHtml = function(t){ return String(t).replace(/[&<>"']/g, function(c){ return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]; }); };
    const bodyHTML = bodyRaw.split(/\n\s*\n/).map(function(p){
      return '<p style="margin:0 0 14px">' + escapeHtml(p).replace(/\n/g, '<br>') + '</p>';
    }).join('');

    const baseUrl = process.env.APP_URL || 'https://gistapp.onrender.com';
    const whereClause = _marketingSegmentWhere(segment);

    // Recipients — exclude unsubscribed from marketing
    let sql = "SELECT id, email, display_name FROM users WHERE verified=true AND email IS NOT NULL AND COALESCE(prefs->>'marketing_emails','true') <> 'false' AND " + whereClause;

    let recipients = [];
    if (test){
      const me = await pool.query('SELECT id, email, display_name FROM users WHERE id=$1', [req.user.id]);
      recipients = me.rows;
    } else {
      const r = await pool.query(sql + ' ORDER BY id DESC LIMIT 5000');
      recipients = r.rows;
    }

    if (dry){
      return res.json({ ok: true, dry: true, segment: segment, recipients: recipients.length });
    }

    if (!test && recipients.length > 50){
      // Require explicit confirm for large batches
      if (b.confirm !== true){
        return res.status(400).json({ error: 'Batch > 50 requires confirm:true', count: recipients.length });
      }
    }

    let sent = 0, failed = 0;
    const errors = [];
    for (const u of recipients){
      try {
        const html = _marketingHTML(subject, preview, bodyHTML, u.id, baseUrl);
        await mailer.sendMail({
          from: '"GistApp Team" <' + GMAIL_SENDER + '>',
          to: u.email,
          replyTo: process.env.SMTP_USER,
          subject: subject,
          headers: {
            'X-Priority': '3',
            'Importance': 'normal',
            'List-Unsubscribe': '<' + baseUrl + '/api/email/unsub-marketing?u=' + u.id + '&t=' + _marketingToken(u.id) + '>',
            'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click'
          },
          html: html
        });
        sent++;
        if (recipients.length > 1) await new Promise(r => setTimeout(r, 220)); // throttle Gmail
      } catch(e){
        failed++;
        if (errors.length < 5) errors.push({ email: u.email, err: e.message });
      }
    }

    console.log('📣 Marketing email sent:', sent, 'failed:', failed, 'segment:', segment);
    res.json({ ok: true, sent: sent, failed: failed, total: recipients.length, errors: errors });
  } catch(e){ console.error('marketing send:', e.message); res.status(500).json({ error: 'Server error' }); }
});

/* GET /api/email/unsub-marketing — one-click unsubscribe */
app.get('/api/email/unsub-marketing', async (req, res) => {
  try {
    const uid = Number(req.query.u || 0);
    const tok = String(req.query.t || '');
    if (!uid || !tok) return res.status(400).send('<h2>Invalid link</h2>');
    const expect = _marketingToken(uid);
    if (tok !== expect) return res.status(403).send('<h2>Invalid link</h2>');
    await pool.query(
      "UPDATE users SET prefs = COALESCE(prefs,'{}'::jsonb) || jsonb_build_object('marketing_emails','false') WHERE id=$1",
      [uid]
    );
    res.send('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Unsubscribed</title></head><body style="font-family:Inter,-apple-system,system-ui,sans-serif;background:#f2f0fa;color:#1c1c22;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;padding:20px"><div style="background:#fff;max-width:420px;padding:40px 30px;border-radius:24px;box-shadow:0 12px 40px rgba(51,52,76,.10)"><div style="font-size:52px;margin-bottom:12px">✅</div><h2 style="margin:0 0 10px;font-size:22px;letter-spacing:-.3px">You are unsubscribed</h2><p style="color:#6a6a73;font-size:14px;line-height:1.6;margin:0 0 20px">You will not receive marketing emails anymore. You can re-enable it in the app under <b>Settings &rarr; Notifications</b>.</p><a href="/" style="display:inline-block;background:#2b2c44;color:#fff;text-decoration:none;padding:12px 28px;border-radius:12px;font-weight:700;font-size:14px">Back to GistApp</a></div></body></html>');
  } catch(e){ console.error('unsub-marketing:', e.message); res.status(500).send('<h2>Server error</h2>'); }
});

/* GISTAPP_WEEKLY_DIGEST — unsubscribe (public, uses HMAC token) */
app.get('/api/email/unsub-digest', async (req, res) => {
  try {
    const uid = Number(req.query.u || 0);
    const tok = String(req.query.t || '');
    if (!uid || !tok) return res.status(400).send('<h2>Invalid link</h2>');
    const expect = _digestToken(uid);
    if (tok !== expect) return res.status(403).send('<h2>Invalid or expired link</h2>');
    await pool.query(
      "UPDATE users SET prefs = COALESCE(prefs,'{}'::jsonb) || jsonb_build_object('weekly_digest', 'false') WHERE id=$1",
      [uid]
    );
    res.send('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Unsubscribed</title></head><body style="font-family:Inter,-apple-system,system-ui,sans-serif;background:#f2f0fa;color:#1c1c22;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;padding:20px"><div style="background:#fff;max-width:420px;padding:40px 30px;border-radius:24px;box-shadow:0 12px 40px rgba(51,52,76,.10)"><div style="font-size:52px;margin-bottom:12px">✅</div><h2 style="margin:0 0 10px;font-size:22px;letter-spacing:-.3px">You are unsubscribed</h2><p style="color:#6a6a73;font-size:14px;line-height:1.6;margin:0 0 20px">You will not receive the weekly recap anymore. You can re-enable it anytime in the app under <b>Settings &rarr; Notifications</b>.</p><a href="/" style="display:inline-block;background:#2b2c44;color:#fff;text-decoration:none;padding:12px 28px;border-radius:12px;font-weight:700;font-size:14px">Back to GistApp</a></div></body></html>');
  } catch(e){ console.error('unsub-digest:', e.message); res.status(500).send('<h2>Server error</h2>'); }
});

const BACKUP_TABLES = [
  'users', 'chats', 'chat_members', 'messages', 'posts',
  'post_likes', 'post_comments', 'post_votes', 'post_saves', 'post_shares',
  'user_follows', 'user_likes', 'statuses', 'status_views',
  'communities', 'community_members', 'calls', 'reports',
  'push_subscriptions', 'profile_views'
];

async function createBackup(){
  const startedAt = Date.now();
  const dump = { _meta: { created_at: new Date().toISOString(), app: 'gistapp' } };
  for (const t of BACKUP_TABLES){
    try {
      const r = await pool.query('SELECT * FROM ' + t);
      dump[t] = r.rows;
    } catch(e){
      dump[t] = { error: e.message };
    }
  }
  const json = JSON.stringify(dump);
  const buf = Buffer.from(json, 'utf8');
  const today = new Date().toISOString().slice(0, 10);
  const key = 'backups/gistapp-' + today + '-' + Date.now() + '.json';

  // Upload to Upstash
  if (typeof getBlobBucket === 'function'){
    try {
      const bucket = getBlobBucket();
      const result = await Promise.race([
        bucket.put(key, buf, { contentType: 'application/json' }),
        new Promise(function(_, rej){ setTimeout(function(){ rej(new Error('timeout')); }, 15000); })
      ]);
      const url = (result && (result.url || result.downloadUrl)) || null;
      console.log('💾 backup saved:', key, '(' + (buf.length/1024).toFixed(1) + ' KB)');
      return { ok: true, url: url, key: key, bytes: buf.length, tables: BACKUP_TABLES.length, ms: Date.now() - startedAt };
    } catch(e){
      console.warn('backup upload failed:', e.message);
      return { ok: false, error: e.message };
    }
  }
  return { ok: false, error: 'Upstash not configured' };
}

// POST /api/admin/backup — manual trigger
app.post('/api/admin/backup', auth, adminOnly, async (req, res) => {
  try {
    const r = await createBackup();
    if (!r.ok) return res.status(500).json({ error: r.error });
    res.json(r);
  } catch(e){ console.error('backup:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// GET /api/admin/backups — list (from Upstash by listing prefix)
app.get('/api/admin/backups', auth, adminOnly, async (req, res) => {
  try {
    // Upstash blob doesn't have a public list API easily here, so we
    // return a lightweight local index. For now: return recent backups
    // stored in a small JSON index inside a separate key.
    if (typeof getBlobBucket !== 'function') return res.json({ backups: [] });
    try {
      const bucket = getBlobBucket();
      const indexRes = await bucket.get('backups/_index.json').catch(()=>null);
      if (indexRes && indexRes.body){
        const text = typeof indexRes.body === 'string' ? indexRes.body : indexRes.body.toString('utf8');
        return res.json({ backups: JSON.parse(text) });
      }
    } catch(_){}
    res.json({ backups: [] });
  } catch(e){ console.error('list backups:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/admin/restore — restore from a URL
app.post('/api/admin/restore', auth, adminOnly, async (req, res) => {
  try {
    const { url } = req.body || {};
    if (!url) return res.status(400).json({ error: 'Missing url' });
    console.log('💾 restoring from', url);
    const r = await fetch(url);
    if (!r.ok) return res.status(400).json({ error: 'Could not fetch backup' });
    const dump = await r.json();
    if (!dump._meta || !dump._meta.created_at) return res.status(400).json({ error: 'Invalid backup file' });

    // Restore in a transaction, table by table. Delete-all then re-insert.
    const restored = {};
    for (const t of BACKUP_TABLES){
      if (!Array.isArray(dump[t])) continue;
      const rows = dump[t];
      if (!rows.length) continue;
      try {
        // Delete all rows (safe for empty tables)
        await pool.query('DELETE FROM ' + t);
        // Insert rows using dynamic columns
        const cols = Object.keys(rows[0]);
        const placeholders = cols.map((_, i) => '$' + (i+1)).join(',');
        const values = rows.map(r => cols.map(c => r[c]));
        // Insert in chunks of 100
        const chunkSize = 100;
        for (let i = 0; i < values.length; i += chunkSize){
          const chunk = values.slice(i, i + chunkSize);
          const flat = [];
          const groups = chunk.map(row => '(' + row.map(v => '$' + (flat.push(v)) + ')').join(',') + ')');
          await pool.query('INSERT INTO ' + t + ' (' + cols.join(',') + ') VALUES ' + groups.join(','), flat);
        }
        restored[t] = rows.length;
      } catch(e){
        console.warn('restore ' + t + ':', e.message);
        restored[t] = { error: e.message };
      }
    }
    console.log('💾 restored:', restored);
    res.json({ ok: true, restored: restored });
  } catch(e){ console.error('restore:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// Auto-scheduler: 1 backup per day, checked every 6h
/* GISTAPP_WEEKLY_DIGEST — Monday 8-10am WAT, once per 7 days */
const crypto_digest = require('crypto');

function _digestToken(uid){
  return crypto_digest.createHmac('sha256', JWT_SECRET).update('digest-unsub:' + uid).digest('hex').slice(0, 32);
}

async function _getUserWeeklyStats(uid){
  const stats = { new_followers:0, new_likes:0, new_messages:0, top_post:null, new_posts:0 };
  try {
    const r1 = await pool.query("SELECT COUNT(*)::int AS n FROM user_follows WHERE following_id=$1 AND created_at > NOW() - INTERVAL '7 days'", [uid]);
    stats.new_followers = r1.rows[0].n;
  } catch(_){}
  try {
    const r2 = await pool.query(
      "SELECT COUNT(*)::int AS n FROM post_likes pl JOIN posts p ON p.id=pl.post_id WHERE p.user_id=$1 AND pl.created_at > NOW() - INTERVAL '7 days'",
      [uid]
    );
    stats.new_likes = r2.rows[0].n;
  } catch(_){}
  try {
    const r3 = await pool.query(
      "SELECT COUNT(*)::int AS n FROM messages m JOIN chat_members cm ON cm.chat_id=m.chat_id WHERE cm.user_id=$1 AND m.sender_id<>$1 AND m.created_at > NOW() - INTERVAL '7 days'",
      [uid]
    );
    stats.new_messages = r3.rows[0].n;
  } catch(_){}
  try {
    const r4 = await pool.query("SELECT COUNT(*)::int AS n FROM posts WHERE user_id=$1 AND created_at > NOW() - INTERVAL '7 days'", [uid]);
    stats.new_posts = r4.rows[0].n;
  } catch(_){}
  try {
    const r5 = await pool.query(
      `SELECT p.id, p.body, COUNT(pl.post_id)::int AS likes
       FROM posts p LEFT JOIN post_likes pl ON pl.post_id=p.id AND pl.created_at > NOW() - INTERVAL '7 days'
       WHERE p.user_id=$1 AND p.created_at > NOW() - INTERVAL '7 days'
       GROUP BY p.id, p.body ORDER BY likes DESC NULLS LAST LIMIT 1`,
      [uid]
    );
    if (r5.rowCount && r5.rows[0].likes > 0) stats.top_post = r5.rows[0];
  } catch(_){}
  return stats;
}

function _digestHTML(name, stats, uid, baseUrl){
  const tok = _digestToken(uid);
  const unsubUrl = baseUrl + '/api/email/unsub-digest?u=' + uid + '&t=' + tok;
  const settingsUrl = baseUrl + '/?settings=notifications';
  const statCard = (emoji, num, label) =>
    '<td style="width:50%;padding:6px">' +
    '<div style="background:#f7f5ff;border:1px solid #e6e2ff;border-radius:14px;padding:18px 12px;text-align:center">' +
    '<div style="font-size:26px;line-height:1">' + emoji + '</div>' +
    '<div style="color:#2b2c44;font-size:28px;font-weight:800;line-height:1.1;margin-top:8px">' + num + '</div>' +
    '<div style="color:#6a6a73;font-size:11.5px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;margin-top:4px">' + label + '</div>' +
    '</div></td>';

  let topPostSection = '';
  if (stats.top_post && stats.top_post.body){
    const snippet = String(stats.top_post.body).slice(0, 140).replace(/[<>&]/g, function(c){ return ({'<':'&lt;','>':'&gt;','&':'&amp;'})[c]; });
    topPostSection =
      '<tr><td style="padding:24px 32px 0">' +
      '<div style="color:#8e8e93;font-size:11px;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;margin-bottom:10px">Top post of the week</div>' +
      '<div style="background:#fff;border:1px solid #eae7f5;border-left:3px solid #7b8cff;border-radius:12px;padding:14px 16px">' +
      '<div style="color:#2b2c44;font-size:14px;line-height:1.55">' + snippet + '</div>' +
      '<div style="color:#7b8cff;font-size:12.5px;font-weight:700;margin-top:8px">❤️ ' + stats.top_post.likes + ' like' + (stats.top_post.likes === 1 ? '' : 's') + '</div>' +
      '</div></td></tr>';
  }

  return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Your week on GistApp</title></head>' +
  '<body style="margin:0;padding:0;background:#f2f0fa;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Inter,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased">' +
  '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f2f0fa;padding:24px 12px">' +
  '<tr><td align="center">' +
  '<table role="presentation" width="560" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:24px;overflow:hidden;box-shadow:0 12px 40px rgba(51,52,76,.10)">' +

  '<tr><td style="background:linear-gradient(135deg,#2b2c44 0%,#5a6cd6 55%,#7b8cff 100%);padding:32px 32px 26px;text-align:center">' +
  '<img src="' + baseUrl + '/icon-192.png" alt="GistApp" width="60" height="60" style="border-radius:16px;display:block;margin:0 auto 12px;box-shadow:0 8px 24px rgba(0,0,0,.3)">' +
  '<div style="color:#ffffff;font-size:22px;font-weight:800;letter-spacing:-.4px">Your week on GistApp</div>' +
  '<div style="color:rgba(255,255,255,.85);font-size:12.5px;margin-top:6px">A quick recap for ' + name + '</div>' +
  '</td></tr>' +

  '<tr><td style="padding:26px 26px 4px">' +
  '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:separate">' +
  '<tr>' + statCard('👥', stats.new_followers, 'New followers') + statCard('❤️', stats.new_likes, 'Likes received') + '</tr>' +
  '<tr>' + statCard('💬', stats.new_messages, 'New messages') + statCard('📝', stats.new_posts, 'Posts shared') + '</tr>' +
  '</table>' +
  '</td></tr>' +

  topPostSection +

  '<tr><td style="padding:28px 32px 8px;text-align:center">' +
  '<a href="' + baseUrl + '" style="background:#2b2c44;color:#ffffff;text-decoration:none;padding:14px 40px;border-radius:14px;font-weight:800;display:inline-block;font-size:14.5px;letter-spacing:.2px">Open GistApp</a>' +
  '</td></tr>' +

  '<tr><td style="padding:8px 32px 28px;text-align:center">' +
  '<p style="margin:0;color:#8e8e93;font-size:12.5px;line-height:1.65">Keep the momentum going — post something, go live, or start a chat.</p>' +
  '</td></tr>' +

  '<tr><td style="background:#f7f6fc;padding:18px 32px;text-align:center;border-top:1px solid #eae7f5">' +
  '<p style="margin:0 0 8px;color:#8e8e93;font-size:11.5px;line-height:1.6">You are receiving this weekly recap because you have a GistApp account.</p>' +
  '<p style="margin:0;color:#a8a5b3;font-size:11px;line-height:1.6">' +
  '<a href="' + settingsUrl + '" style="color:#5a6cd6;text-decoration:none;font-weight:600">Manage preferences</a> &middot; ' +
  '<a href="' + unsubUrl + '" style="color:#5a6cd6;text-decoration:none;font-weight:600">Unsubscribe</a>' +
  '</p>' +
  '<p style="margin:8px 0 0;color:#a8a5b3;font-size:10.5px">' +
  '&copy; ' + new Date().getFullYear() + ' GistApp Community &middot; All rights reserved.' +
  '</p>' +
  '</td></tr>' +

  '</table></td></tr></table></body></html>';
}

async function sendWeeklyDigests(force){
  const baseUrl = process.env.APP_URL || 'https://gistapp.onrender.com';
  if (!force){
    const today = new Date();
    const watHour = (today.getUTCHours() + 1) % 24; // WAT = UTC+1
    const adjDay = (new Date(today.getTime() + 60*60*1000)).getUTCDay();
    if (adjDay !== 1) return;                 // Monday only
    if (watHour < 8 || watHour > 10) return;  // 8-10am WAT window
  } else {
    console.log('📧 Weekly digest run (forced via cron)');
  }

  console.log('📧 Weekly digest run starting...');
  let sent = 0, skipped = 0, failed = 0;
  try {
    const r = await pool.query(
      "SELECT id, email, display_name, prefs FROM users WHERE verified=true AND email IS NOT NULL AND COALESCE(prefs->>'weekly_digest','true') <> 'false'"
    );
    for (const u of r.rows){
      try {
        // Skip if we already sent one within the last 6 days
        const lastRaw = (u.prefs && u.prefs.last_digest_at) || null;
        if (lastRaw){
          const lastMs = Date.parse(lastRaw);
          if (!isNaN(lastMs) && (Date.now() - lastMs) < 6 * 24 * 60 * 60 * 1000){ skipped++; continue; }
        }
        const stats = await _getUserWeeklyStats(u.id);
        const total = stats.new_followers + stats.new_likes + stats.new_messages + stats.new_posts;
        if (total === 0){ skipped++; continue; } // don't spam quiet users
        const html = _digestHTML(u.display_name || 'there', stats, u.id, baseUrl);
        await mailer.sendMail({
          from: '"GistApp" <' + GMAIL_SENDER + '>',
          to: u.email,
          replyTo: process.env.SMTP_USER,
          subject: 'Your week on GistApp, ' + (u.display_name || 'there') + ' 📊',
          headers: {
            'X-Priority': '3',
            'Importance': 'normal',
            'List-Unsubscribe': '<' + baseUrl + '/api/email/unsub-digest?u=' + u.id + '&t=' + _digestToken(u.id) + '>',
            'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click'
          },
          html: html
        });
        // Stamp last_digest_at into prefs
        await pool.query(
          "UPDATE users SET prefs = COALESCE(prefs,'{}'::jsonb) || jsonb_build_object('last_digest_at', NOW()::text) WHERE id=$1",
          [u.id]
        );
        sent++;
        await new Promise(r => setTimeout(r, 250)); // throttle Gmail API
      } catch(e){
        failed++;
        console.warn('digest send failed for', u.email, e.message);
      }
    }
    console.log('📧 Weekly digest done — sent:', sent, 'skipped:', skipped, 'failed:', failed);
  } catch(e){
    console.error('weekly digest run error:', e.message);
  }
}

// Cron: check every 6 hours; runs only Monday 8-10am WAT; uses last_digest_at to prevent dupes
setInterval(sendWeeklyDigests, 6 * 60 * 60 * 1000);
// Kick off one check 2 minutes after boot (in case the server was just started during the window)
setTimeout(sendWeeklyDigests, 120 * 1000);

async function autoBackupCheck(){
  try {
    const today = new Date().toISOString().slice(0, 10);
    const marker = await pool.query('SELECT 1 FROM pg_stat_user_tables LIMIT 0').catch(()=>null);
    // Use a simple heuristic: try to read backups/_last.txt from Upstash
    let last = null;
    if (typeof getBlobBucket === 'function'){
      try {
        const r = await getBlobBucket().get('backups/_last.txt');
        if (r && r.body){
          last = typeof r.body === 'string' ? r.body : r.body.toString('utf8');
        }
      } catch(_){}
    }
    if (last === today) return;
    console.log('💾 auto-backup starting for', today);
    const r = await createBackup();
    if (r.ok && typeof getBlobBucket === 'function'){
      try {
        await getBlobBucket().put('backups/_last.txt', Buffer.from(today), { contentType: 'text/plain' });
      } catch(_){}
    }
  } catch(e){ console.warn('auto-backup:', e.message); }
}

// Run once 30s after boot, then every 6 hours
setTimeout(autoBackupCheck, 30 * 1000);
setInterval(autoBackupCheck, 6 * 60 * 60 * 1000);

async function purgeExpired(){
  try {
    const r = await pool.query('DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < NOW() RETURNING id, chat_id');
    r.rows.forEach(row => io.to('chat:' + row.chat_id).emit('message-deleted', { id: row.id }));
    if (r.rowCount) console.log('🧹 Purged ' + r.rowCount + ' expired message(s)');
  } catch(e){
    // Neon sometimes drops idle connections — silently skip this tick
    if (!String(e.message).includes('timeout') && !String(e.message).includes('terminated')){
      console.error('purge error', e.message);
    }
  }
}
setInterval(purgeExpired, 60 * 1000); // every minute
setInterval(async () => {
  try {
    const r = await pool.query('DELETE FROM statuses WHERE expires_at < NOW() RETURNING id');
    if (r.rowCount) console.log('🧹 Purged ' + r.rowCount + ' expired status(es)');
  } catch(e){ console.error('status purge', e.message); }
}, 5 * 60 * 1000); // every 5 min

const PORT = process.env.PORT || 3000;
server.listen(PORT, ()=>console.log(`Server running → http://localhost:${PORT}`));
