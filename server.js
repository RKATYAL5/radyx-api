import { createServer } from 'node:http';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import dns from 'node:dns';
import nodemailer from 'nodemailer';

// Many cloud hosts (Render included) resolve DNS to an IPv6 address but have
// no outbound IPv6 route, causing "connect ENETUNREACH" on otherwise-correct
// SMTP credentials. Preferring IPv4 avoids that entirely.
dns.setDefaultResultOrder('ipv4first');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function loadEnvFile(filePath) {
  if (!existsSync(filePath)) return;

  const raw = readFileSync(filePath, 'utf8');
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const separatorIndex = trimmed.indexOf('=');
    if (separatorIndex === -1) continue;
    const key = trimmed.slice(0, separatorIndex).trim();
    let value = trimmed.slice(separatorIndex + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) {
      process.env[key] = value;
    }
  }
}

loadEnvFile(path.join(__dirname, '.env'));

const PORT = Number(process.env.PORT || 8787);
const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'careers-db.json');
const HR_EMAIL = process.env.HR_EMAIL || 'HR@radyx.ca';
const ADMIN_EMAIL = process.env.CAREERS_ADMIN_EMAIL || 'hr-admin@radyx.ca';
const ADMIN_PASSWORD = process.env.CAREERS_ADMIN_PASSWORD || 'ChangeMeNow!';
const APP_ORIGIN = process.env.CAREERS_APP_ORIGIN || '*';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RESEND_FROM = process.env.RESEND_FROM || '';
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = process.env.SMTP_SECURE === 'true';
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASSWORD = process.env.SMTP_PASSWORD || '';
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;
const CONTACT_EMAIL = process.env.CONTACT_EMAIL || HR_EMAIL;
const HACKATHON_EMAIL = process.env.HACKATHON_EMAIL || HR_EMAIL;
const adminSessions = new Map();

let smtpTransporter = null;
async function getSmtpTransporter() {
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASSWORD) return null;
  if (smtpTransporter) return smtpTransporter;

  // Connect directly to a resolved IPv4 address instead of the hostname.
  // Some hosts (Render included) have no outbound IPv6 route, and DNS
  // preference hints alone (dns.setDefaultResultOrder, the `family` option)
  // aren't always honored by the underlying TLS socket - resolving and
  // connecting by IP directly sidesteps that entirely. `servername` keeps
  // TLS certificate hostname validation working against the real domain.
  let connectHost = SMTP_HOST;
  try {
    const addresses = await dns.promises.resolve4(SMTP_HOST);
    if (addresses[0]) connectHost = addresses[0];
  } catch (error) {
    console.error('[email] IPv4 resolution failed, falling back to hostname:', error.message);
  }

  smtpTransporter = nodemailer.createTransport({
    host: connectHost,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: { user: SMTP_USER, pass: SMTP_PASSWORD },
    family: 4,
    tls: { servername: SMTP_HOST },
    // Fail fast rather than hanging on a stuck connection for minutes -
    // makes real problems show up in seconds instead of a long silent wait.
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,
    // Each submission sends 2 emails (staff notification + confirmation).
    // Pooling lets them share one connection/login instead of two full
    // handshakes, which is the other big contributor to slow responses.
    pool: true,
    maxConnections: 3,
    maxMessages: 50,
  });
  return smtpTransporter;
}

// Which provider is active is decided once at startup based on whichever
// credentials are present. Resend is checked first if both happen to be set.
const EMAIL_PROVIDER = RESEND_API_KEY && RESEND_FROM ? 'resend' : SMTP_HOST && SMTP_USER && SMTP_PASSWORD ? 'smtp' : 'none';

const defaultDb = {
  applicants: [],
  applications: [],
  counters: {
    application: 1000,
  },
};

const statusStages = [
  'Application received',
  'Profile review',
  'Hiring manager review',
  'Interview stage',
  'Final decision',
];

async function ensureDb() {
  await mkdir(DATA_DIR, { recursive: true });
  if (!existsSync(DB_PATH)) {
    await writeFile(DB_PATH, JSON.stringify(defaultDb, null, 2), 'utf8');
  }
}

async function readDb() {
  await ensureDb();
  const raw = await readFile(DB_PATH, 'utf8');
  return JSON.parse(raw);
}

async function writeDb(db) {
  await ensureDb();
  await writeFile(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
}

function jsonBase(res, statusCode, payload, origin) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': origin || APP_ORIGIN,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, OPTIONS',
  });
  res.end(JSON.stringify(payload));
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

function createToken() {
  return crypto.randomBytes(24).toString('hex');
}

function createLoginCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function buildApplicationNumber(db) {
  db.counters.application += 1;
  return `RAD-APP-${new Date().getFullYear()}-${String(db.counters.application).padStart(4, '0')}`;
}

function normalizeApplicant(applicant) {
  const { passwordHash, ...safeApplicant } = applicant;
  return safeApplicant;
}

async function parseBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw ? JSON.parse(raw) : {};
}

function getAuthToken(req) {
  const authorization = req.headers.authorization || '';
  return authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
}

function isValidAdminToken(req) {
  const token = getAuthToken(req);
  return token ? adminSessions.get(token) === ADMIN_EMAIL : false;
}

async function findApplicantByToken(token) {
  if (!token) return null;
  const db = await readDb();
  const applicant = db.applicants.find((entry) => entry.sessionToken === token);
  return applicant ? { db, applicant } : { db, applicant: null };
}

function getUrl(req) {
  return new URL(req.url, `http://localhost:${PORT}`);
}

function logEmailFailures(context, results) {
  results.forEach((result, index) => {
    if (result.status === 'rejected') {
      console.error(`[email] ${context} - message ${index} failed:`, result.reason?.message || result.reason);
    }
  });
}

async function sendEmail({ to, subject, html, text }) {
  if (EMAIL_PROVIDER === 'resend') {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: RESEND_FROM,
        to: [to],
        subject,
        html,
        text,
      }),
    });

    if (!response.ok) {
      const message = await response.text();
      throw new Error(`Email delivery failed: ${message}`);
    }

    return { delivered: true, provider: 'resend' };
  }

  if (EMAIL_PROVIDER === 'smtp') {
    const transporter = await getSmtpTransporter();
    await transporter.sendMail({
      from: SMTP_FROM,
      to,
      subject,
      html,
      text,
    });
    return { delivered: true, provider: 'smtp' };
  }

  return { delivered: false, reason: 'No email provider configured (set RESEND_API_KEY or SMTP_* variables).' };
}

async function notifyHr(application) {
  const summary = [
    `Application number: ${application.applicationNumber}`,
    `Role: ${application.roleLabel} (${application.jobCode})`,
    `Applicant: ${application.applicantName}`,
    `Email: ${application.applicantEmail}`,
    `Phone: ${application.phone}`,
    `Eligibility: ${application.citizenshipStatus}`,
    `Security clearance: ${application.securityClearance}`,
    `Resume: ${application.resume?.fileName || 'Not provided'}`,
  ].join('\n');

  return sendEmail({
    to: HR_EMAIL,
    subject: `New RADYX application: ${application.roleLabel}`,
    text: `${summary}\n\nMessage:\n${application.message}`,
    html: `<pre>${summary}\n\nMessage:\n${application.message}</pre>`,
  });
}

async function notifyApplicant(application) {
  return sendEmail({
    to: application.applicantEmail,
    subject: `RADYX application received: ${application.applicationNumber}`,
    text: `Thank you for applying to ${application.roleLabel}. Your current status is "${application.status}". Tracking number: ${application.applicationNumber}.`,
    html: `<p>Thank you for applying to <strong>${application.roleLabel}</strong>.</p><p>Your current status is <strong>${application.status}</strong>.</p><p>Tracking number: <strong>${application.applicationNumber}</strong>.</p>`,
  });
}

async function notifyStatusChange(application) {
  return sendEmail({
    to: application.applicantEmail,
    subject: `RADYX application update: ${application.applicationNumber}`,
    text: `Your RADYX application status is now "${application.status}". Next update: ${application.nextStep}`,
    html: `<p>Your RADYX application status is now <strong>${application.status}</strong>.</p><p>${application.nextStep}</p>`,
  });
}

async function sendApplicantCode({ email, code, mode }) {
  return sendEmail({
    to: email,
    subject: `RADYX ${mode === 'signup' ? 'account' : 'sign-in'} code`,
    text: `Your RADYX verification code is ${code}. It expires in 10 minutes.`,
    html: `<p>Your RADYX verification code is <strong>${code}</strong>.</p><p>It expires in 10 minutes.</p>`,
  });
}

async function sendContactNotification({ name, email, phone, subject, message }) {
  const summary = [
    `Name: ${name}`,
    `Email: ${email}`,
    `Phone: ${phone || 'Not provided'}`,
    `Subject: ${subject || 'General inquiry'}`,
  ].join('\n');

  const results = await Promise.allSettled([
    sendEmail({
      to: CONTACT_EMAIL,
      subject: `New contact form message: ${subject || 'General inquiry'}`,
      text: `${summary}\n\nMessage:\n${message}`,
      html: `<pre>${summary}\n\nMessage:\n${message}</pre>`,
    }),
    sendEmail({
      to: email,
      subject: 'We received your message - RADYX',
      text: `Thanks for reaching out to RADYX. We received your message and will get back to you shortly.\n\nYour message:\n${message}`,
      html: `<p>Thanks for reaching out to RADYX. We received your message and will get back to you shortly.</p><p><strong>Your message:</strong></p><p>${message}</p>`,
    }),
  ]);

  logEmailFailures('contact form', results);

  const staffResult = results[0].status === 'fulfilled' ? results[0].value : { delivered: false };
  return staffResult;
}

async function sendHackathonEnrollmentNotification(fields) {
  const summary = Object.entries(fields)
    .map(([key, value]) => `${key}: ${value || 'Not provided'}`)
    .join('\n');

  const results = await Promise.allSettled([
    sendEmail({
      to: HACKATHON_EMAIL,
      subject: `New hackathon enrollment: ${fields.fullName || 'Unknown'}`,
      text: summary,
      html: `<pre>${summary}</pre>`,
    }),
    fields.email
      ? sendEmail({
          to: fields.email,
          subject: 'Hackathon enrollment received - RADYX',
          text: `Thanks for enrolling in the RADYX Monthly Hackathon. We received your enrollment for ${fields.eventDate || 'the upcoming event'}.`,
          html: `<p>Thanks for enrolling in the RADYX Monthly Hackathon.</p><p>We received your enrollment for <strong>${fields.eventDate || 'the upcoming event'}</strong>.</p>`,
        })
      : Promise.resolve({ delivered: false }),
  ]);

  logEmailFailures('hackathon enrollment', results);

  const staffResult = results[0].status === 'fulfilled' ? results[0].value : { delivered: false };
  return staffResult;
}

const server = createServer(async (req, res) => {
  const url = getUrl(req);
  // Reflect whatever origin the browser actually sent instead of relying on
  // an exact-match env var - this removes a whole class of CORS misconfiguration
  // that shows up to users as a generic, hard-to-debug "Failed to fetch".
  const requestOrigin = req.headers.origin || APP_ORIGIN;
  const json = (res, statusCode, payload) => jsonBase(res, statusCode, payload, requestOrigin);

  if (req.method === 'OPTIONS') {
    // 204 No Content must not have a body - sending one here (even "{}")
    // violates HTTP spec and can cause some browsers/proxies to abort the
    // request entirely, surfacing as a generic "Failed to fetch" error.
    res.writeHead(204, {
      'Access-Control-Allow-Origin': requestOrigin,
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, OPTIONS',
    });
    res.end();
    return;
  }

  try {
    if (req.method === 'GET' && url.pathname === '/health') {
      json(res, 200, { status: 'ok', emailProvider: EMAIL_PROVIDER });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/contact/submit') {
      const body = await parseBody(req);
      const name = String(body.name || '').trim();
      const email = String(body.email || '').trim().toLowerCase();
      const phone = String(body.phone || '').trim();
      const subject = String(body.subject || '').trim();
      const message = String(body.message || '').trim();

      if (!name || !email || !message) {
        json(res, 400, { message: 'Name, email, and message are required.' });
        return;
      }

      const result = await sendContactNotification({ name, email, phone, subject, message });
      json(res, 200, { message: 'Message received.', emailDelivered: result.delivered });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/hackathon/enroll') {
      const body = await parseBody(req);
      const fullName = String(body.fullName || '').trim();
      const email = String(body.email || '').trim().toLowerCase();

      if (!fullName || !email) {
        json(res, 400, { message: 'Full name and email are required.' });
        return;
      }

      const result = await sendHackathonEnrollmentNotification(body);
      json(res, 200, { message: 'Enrollment received.', emailDelivered: result.delivered });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/careers/auth/request-code') {
      const body = await parseBody(req);
      const db = await readDb();
      const email = String(body.email || '').trim().toLowerCase();
      const mode = body.mode === 'signin' ? 'signin' : 'signup';
      const fullName = String(body.fullName || '').trim();

      if (!email) {
        json(res, 400, { message: 'Email is required.' });
        return;
      }

      let applicant = db.applicants.find((entry) => entry.email === email);

      if (mode === 'signup') {
        if (!fullName) {
          json(res, 400, { message: 'Full name is required to create an applicant account.' });
          return;
        }

        if (applicant) {
          json(res, 409, { message: 'An applicant account already exists for this email.' });
          return;
        }

        applicant = {
          id: crypto.randomUUID(),
          fullName,
          email,
          createdAt: new Date().toISOString(),
          sessionToken: null,
        };
        db.applicants.push(applicant);
      } else if (!applicant) {
        json(res, 404, { message: 'No applicant account exists for this email yet.' });
        return;
      }

      const code = createLoginCode();
      applicant.loginCodeHash = hashCode(code);
      applicant.loginCodeExpiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
      await writeDb(db);

      const emailResult = await sendApplicantCode({ email, code, mode });

      json(res, 200, {
        message: 'Verification code created.',
        emailDelivered: emailResult.delivered,
        devCode: emailResult.delivered ? null : code,
      });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/careers/auth/verify-code') {
      const body = await parseBody(req);
      const db = await readDb();
      const email = String(body.email || '').trim().toLowerCase();
      const code = String(body.code || '').trim();
      const applicant = db.applicants.find((entry) => entry.email === email);

      if (!applicant) {
        json(res, 404, { message: 'No applicant account exists for this email.' });
        return;
      }

      if (!code || !applicant.loginCodeHash || !applicant.loginCodeExpiresAt) {
        json(res, 400, { message: 'A valid verification code is required.' });
        return;
      }

      if (new Date(applicant.loginCodeExpiresAt).getTime() < Date.now()) {
        json(res, 401, { message: 'That verification code has expired. Please request a new one.' });
        return;
      }

      if (applicant.loginCodeHash !== hashCode(code)) {
        json(res, 401, { message: 'That verification code is incorrect.' });
        return;
      }

      applicant.sessionToken = createToken();
      applicant.loginCodeHash = null;
      applicant.loginCodeExpiresAt = null;
      await writeDb(db);

      json(res, 200, {
        user: normalizeApplicant(applicant),
        token: applicant.sessionToken,
      });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/careers/session') {
      const token = getAuthToken(req);
      const email = String(url.searchParams.get('email') || '').trim().toLowerCase();
      const db = await readDb();
      const applicant = db.applicants.find(
        (entry) => (token && entry.sessionToken === token) || (!token && entry.email === email)
      );

      if (!applicant) {
        json(res, 404, { message: 'No active applicant session found.' });
        return;
      }

      json(res, 200, { user: normalizeApplicant(applicant) });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/careers/applications') {
      const token = getAuthToken(req);
      const email = String(url.searchParams.get('email') || '').trim().toLowerCase();
      const db = await readDb();

      const applicant = db.applicants.find(
        (entry) => (token && entry.sessionToken === token) || (!token && entry.email === email)
      );

      if (!applicant && email !== ADMIN_EMAIL) {
        json(res, 401, { message: 'Applicant session required.' });
        return;
      }

      const applications = email === ADMIN_EMAIL
        ? db.applications
        : db.applications.filter((application) => application.applicantEmail === applicant.email);

      json(res, 200, { applications });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/careers/applications') {
      const token = getAuthToken(req);
      const { db, applicant } = await findApplicantByToken(token);

      if (!applicant) {
        json(res, 401, { message: 'Applicant session required.' });
        return;
      }

      const body = await parseBody(req);
      const application = {
        ...body,
        id: crypto.randomUUID(),
        applicationNumber: buildApplicationNumber(db),
        applicantEmail: applicant.email,
        applicantName: applicant.fullName,
        status: body.status || 'Application received',
        statusIndex: Number.isFinite(body.statusIndex) ? body.statusIndex : 0,
        submittedAt: new Date().toISOString(),
        lastUpdatedAt: new Date().toISOString(),
      };

      db.applications.unshift(application);
      await writeDb(db);

      await Promise.allSettled([notifyHr(application), notifyApplicant(application)]);

      json(res, 201, { application });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/careers/admin/login') {
      const body = await parseBody(req);
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');

      if (email !== ADMIN_EMAIL.toLowerCase() || password !== ADMIN_PASSWORD) {
        json(res, 401, { message: 'Invalid HR admin credentials.' });
        return;
      }

      const adminToken = createToken();
      adminSessions.set(adminToken, ADMIN_EMAIL);
      json(res, 200, {
        admin: {
          email: ADMIN_EMAIL,
          token: adminToken,
        },
      });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/careers/admin/applications') {
      if (!isValidAdminToken(req)) {
        json(res, 401, { message: 'HR admin access required.' });
        return;
      }

      const db = await readDb();
      json(res, 200, { applications: db.applications });
      return;
    }

    if (req.method === 'PATCH' && url.pathname.startsWith('/careers/admin/applications/')) {
      if (!isValidAdminToken(req)) {
        json(res, 401, { message: 'HR admin access required.' });
        return;
      }

      const applicationId = url.pathname.split('/').pop();
      const body = await parseBody(req);
      const db = await readDb();
      const application = db.applications.find((entry) => entry.id === applicationId);

      if (!application) {
        json(res, 404, { message: 'Application not found.' });
        return;
      }

      application.status = body.status || application.status;
      application.statusIndex = Math.max(0, statusStages.indexOf(application.status));
      application.nextStep = body.nextStep || application.nextStep;
      application.lastUpdatedAt = new Date().toISOString();

      await writeDb(db);
      await Promise.allSettled([notifyStatusChange(application)]);

      json(res, 200, { application });
      return;
    }

    json(res, 404, { message: 'Not found' });
  } catch (error) {
    json(res, 500, { message: error.message || 'Internal server error' });
  }
});

server.listen(PORT, () => {
  console.log(`RADYX careers API running on http://localhost:${PORT}`);
});
