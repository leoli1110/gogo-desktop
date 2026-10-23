import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import { createServer as createViteServer } from "vite";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: "64kb" }));
app.use(cookieParser());

const startTime = Date.now();
const REAUTH_SECS = 5 * 60;

// ---------- In-Memory State ----------

interface User {
  id: number;
  username: string;
  passwordHash: string;
  kind: "local" | "windows";
  role: "admin" | "user";
  disabled: boolean;
  totp_enabled: boolean;
  totp_secret: string | null;
  created_at: number;
  last_login_at: number | null;
  locked_until: number;
}

interface Session {
  token: string;
  id_hash: string;
  user_id: number;
  method: string;
  ip: string;
  created_at: number;
  last_seen: number;
  expires_at: number;
  reauth_at: number;
  csrf: string;
}

interface Library {
  id: number;
  name: string;
  path: string;
  display_prefix: string | null;
  source: string;
  access: string[];
  excludes: string[];
  entries: number;
  state: "ready" | "scanning" | "idle";
  method: string;
  last_scan_at: number;
  last_scan_ms: number;
  message?: string;
}

interface IndexedItem {
  id: string;
  libraryId: number;
  name: string;
  rel_path: string;
  is_dir: boolean;
  size: number;
  mtime: number;
}

interface AuditRecord {
  id: number;
  time: number;
  event: string;
  actor: string | null;
  ip: string | null;
  details: Record<string, unknown>;
}

function hashPassword(password: string): string {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

// Initial Admin
let nextUserId = 2;
const users: User[] = [
  {
    id: 1,
    username: "admin",
    passwordHash: hashPassword("admin12345678"),
    kind: "local",
    role: "admin",
    disabled: false,
    totp_enabled: false,
    totp_secret: null,
    created_at: nowSec() - 86400 * 5,
    last_login_at: nowSec() - 3600,
    locked_until: 0,
  },
];

const sessions = new Map<string, Session>();
let nextAuditId = 1;
const auditLog: AuditRecord[] = [
  {
    id: nextAuditId++,
    time: nowSec() - 86400,
    event: "system.start",
    actor: "system",
    ip: "127.0.0.1",
    details: { version: "0.1.0", mode: "linux" },
  },
];

function recordAudit(event: string, actor: string | null, ip: string | null, details: Record<string, unknown>) {
  auditLog.unshift({
    id: nextAuditId++,
    time: nowSec(),
    event,
    actor,
    ip,
    details,
  });
  if (auditLog.length > 500) auditLog.pop();
}

let nextLibraryId = 5;
const libraries: Library[] = [
  {
    id: 1,
    name: "Projects",
    path: "/storage/Projects",
    display_prefix: "\\\\NAS\\Projects",
    source: "admin",
    access: ["role:user"],
    excludes: [".git", "node_modules", ".tmp"],
    entries: 1420,
    state: "ready",
    method: "watch",
    last_scan_at: nowSec() - 120,
    last_scan_ms: 320,
  },
  {
    id: 2,
    name: "Documents",
    path: "/storage/Documents",
    display_prefix: "\\\\NAS\\Documents",
    source: "admin",
    access: ["role:user"],
    excludes: ["~$*", ".DS_Store"],
    entries: 890,
    state: "ready",
    method: "watch",
    last_scan_at: nowSec() - 300,
    last_scan_ms: 180,
  },
  {
    id: 3,
    name: "Engineering & CAD",
    path: "/storage/Engineering",
    display_prefix: "\\\\NAS\\Engineering",
    source: "admin",
    access: ["role:user"],
    excludes: ["*.bak", "*.tmp"],
    entries: 654,
    state: "ready",
    method: "watch",
    last_scan_at: nowSec() - 600,
    last_scan_ms: 450,
  },
  {
    id: 4,
    name: "Media & Assets",
    path: "/storage/Media",
    display_prefix: "\\\\NAS\\Media",
    source: "admin",
    access: ["role:user"],
    excludes: [".cache", "Thumbs.db"],
    entries: 2310,
    state: "ready",
    method: "watch",
    last_scan_at: nowSec() - 900,
    last_scan_ms: 610,
  },
];

// Rich set of sample files to demonstrate Gogo Desktop's fast search capabilities
const fileIndex: IndexedItem[] = [
  // Projects
  { id: "1-1", libraryId: 1, name: "site-plan-rev22.dwg", rel_path: "2026/plans/site-plan-rev22.dwg", is_dir: false, size: 14857600, mtime: nowSec() - 7200 },
  { id: "1-2", libraryId: 1, name: "site-plan-rev21.dwg", rel_path: "2026/plans/site-plan-rev21.dwg", is_dir: false, size: 14210400, mtime: nowSec() - 86400 * 3 },
  { id: "1-3", libraryId: 1, name: "plans", rel_path: "2026/plans", is_dir: true, size: 0, mtime: nowSec() - 7200 },
  { id: "1-4", libraryId: 1, name: "project-specifications-v3.docx", rel_path: "2026/docs/project-specifications-v3.docx", is_dir: false, size: 452000, mtime: nowSec() - 14400 },
  { id: "1-5", libraryId: 1, name: "construction-milestones-2026.xlsx", rel_path: "2026/schedule/construction-milestones-2026.xlsx", is_dir: false, size: 820000, mtime: nowSec() - 86400 * 2 },
  { id: "1-6", libraryId: 1, name: "contractor-briefing-notes.md", rel_path: "2026/notes/contractor-briefing-notes.md", is_dir: false, size: 14500, mtime: nowSec() - 86400 },
  { id: "1-7", libraryId: 1, name: "draft-environmental-impact.pdf", rel_path: "2026/compliance/draft-environmental-impact.pdf", is_dir: false, size: 3890000, mtime: nowSec() - 86400 * 4 },
  { id: "1-8", libraryId: 1, name: "site-safety-audit-final.pdf", rel_path: "2026/safety/site-safety-audit-final.pdf", is_dir: false, size: 2150000, mtime: nowSec() - 86400 * 5 },
  { id: "1-9", libraryId: 1, name: "site-elevation-rendering.png", rel_path: "2026/renderings/site-elevation-rendering.png", is_dir: false, size: 18450000, mtime: nowSec() - 86400 * 6 },
  { id: "1-10", libraryId: 1, name: "renderings", rel_path: "2026/renderings", is_dir: true, size: 0, mtime: nowSec() - 86400 * 6 },

  // Documents
  { id: "2-1", libraryId: 2, name: "Q1_Financial_Report_2026.pdf", rel_path: "finance/2026/Q1_Financial_Report_2026.pdf", is_dir: false, size: 4890000, mtime: nowSec() - 86400 },
  { id: "2-2", libraryId: 2, name: "Q4_Annual_Review_2025.pdf", rel_path: "finance/2025/Q4_Annual_Review_2025.pdf", is_dir: false, size: 6120000, mtime: nowSec() - 86400 * 90 },
  { id: "2-3", libraryId: 2, name: "employee-handbook-rev4.pdf", rel_path: "hr/policies/employee-handbook-rev4.pdf", is_dir: false, size: 1980000, mtime: nowSec() - 86400 * 30 },
  { id: "2-4", libraryId: 2, name: "nda-standard-template.docx", rel_path: "legal/templates/nda-standard-template.docx", is_dir: false, size: 84000, mtime: nowSec() - 86400 * 180 },
  { id: "2-5", libraryId: 2, name: "vendor-master-agreement-2026.pdf", rel_path: "legal/contracts/vendor-master-agreement-2026.pdf", is_dir: false, size: 780000, mtime: nowSec() - 86400 * 12 },
  { id: "2-6", libraryId: 2, name: "quarterly-budget-allocations.xlsx", rel_path: "finance/2026/quarterly-budget-allocations.xlsx", is_dir: false, size: 1420000, mtime: nowSec() - 86400 * 3 },
  { id: "2-7", libraryId: 2, name: "office-lease-extension-signed.pdf", rel_path: "operations/office-lease-extension-signed.pdf", is_dir: false, size: 2840000, mtime: nowSec() - 86400 * 45 },

  // Engineering & CAD
  { id: "3-1", libraryId: 3, name: "structural-foundations-detail.dwg", rel_path: "structural/foundations/structural-foundations-detail.dwg", is_dir: false, size: 28400000, mtime: nowSec() - 3600 * 8 },
  { id: "3-2", libraryId: 3, name: "hvac-schematic-level3.dwg", rel_path: "mep/hvac/hvac-schematic-level3.dwg", is_dir: false, size: 19200000, mtime: nowSec() - 86400 * 2 },
  { id: "3-3", libraryId: 3, name: "electrical-single-line-diagram.pdf", rel_path: "mep/electrical/electrical-single-line-diagram.pdf", is_dir: false, size: 5400000, mtime: nowSec() - 86400 * 7 },
  { id: "3-4", libraryId: 3, name: "geotechnical-boring-logs.pdf", rel_path: "geotech/reports/geotechnical-boring-logs.pdf", is_dir: false, size: 12400000, mtime: nowSec() - 86400 * 15 },
  { id: "3-5", libraryId: 3, name: "civil-grading-cross-sections.dwg", rel_path: "civil/grading/civil-grading-cross-sections.dwg", is_dir: false, size: 31200000, mtime: nowSec() - 86400 * 4 },
  { id: "3-6", libraryId: 3, name: "seismic-calculation-notes.xlsx", rel_path: "structural/calculations/seismic-calculation-notes.xlsx", is_dir: false, size: 2450000, mtime: nowSec() - 86400 * 10 },

  // Media & Assets
  { id: "4-1", libraryId: 4, name: "site_aerial_drone_orthomosaic.tif", rel_path: "photos/2026-03/site_aerial_drone_orthomosaic.tif", is_dir: false, size: 84500000, mtime: nowSec() - 86400 * 8 },
  { id: "4-2", libraryId: 4, name: "site_progress_ground_view_01.jpg", rel_path: "photos/2026-03/site_progress_ground_view_01.jpg", is_dir: false, size: 9400000, mtime: nowSec() - 86400 * 9 },
  { id: "4-3", libraryId: 4, name: "marketing_hero_render_4k.png", rel_path: "renders/marketing_hero_render_4k.png", is_dir: false, size: 24800000, mtime: nowSec() - 86400 * 14 },
  { id: "4-4", libraryId: 4, name: "brand_guidelines_2026.pdf", rel_path: "branding/brand_guidelines_2026.pdf", is_dir: false, size: 15200000, mtime: nowSec() - 86400 * 40 },
  { id: "4-5", libraryId: 4, name: "logo_vector_lockups.svg", rel_path: "branding/logo_vector_lockups.svg", is_dir: false, size: 450000, mtime: nowSec() - 86400 * 45 },
  { id: "4-6", libraryId: 4, name: "project_time_lapse_h265.mp4", rel_path: "video/project_time_lapse_h265.mp4", is_dir: false, size: 142000000, mtime: nowSec() - 86400 * 20 },
];

function formatDisplayPath(lib: Library, relPath: string): string {
  const prefix = lib.display_prefix || lib.path;
  const isWindowsPrefix = prefix.startsWith("\\\\") || /^[A-Z]:\\/i.test(prefix);
  const sep = isWindowsPrefix ? "\\" : "/";
  const normalizedRel = isWindowsPrefix ? relPath.replace(/\//g, "\\") : relPath.replace(/\\/g, "/");
  return `${prefix}${sep}${normalizedRel}`.replace(/[\/\\]+/g, sep);
}

function formatFolderPath(lib: Library, relPath: string): string {
  const lastSlash = Math.max(relPath.lastIndexOf("/"), relPath.lastIndexOf("\\"));
  const folderRel = lastSlash > 0 ? relPath.slice(0, lastSlash) : "";
  const prefix = lib.display_prefix || lib.path;
  const isWindowsPrefix = prefix.startsWith("\\\\") || /^[A-Z]:\\/i.test(prefix);
  const sep = isWindowsPrefix ? "\\" : "/";
  if (!folderRel) return prefix;
  const normalizedRel = isWindowsPrefix ? folderRel.replace(/\//g, "\\") : folderRel.replace(/\\/g, "/");
  return `${prefix}${sep}${normalizedRel}`.replace(/[\/\\]+/g, sep);
}

// Generate simple SVG QR code for TOTP
function generateSvgQrDataUrl(text: string): string {
  const hash = crypto.createHash("md5").update(text).digest();
  let rects = "";
  for (let r = 0; r < 21; r++) {
    for (let c = 0; c < 21; c++) {
      // Corners markers
      const isCorner =
        (r < 7 && c < 7) ||
        (r < 7 && c >= 14) ||
        (r >= 14 && c < 7);
      const isInnerCorner =
        (r >= 2 && r <= 4 && c >= 2 && c <= 4) ||
        (r >= 2 && r <= 4 && c >= 16 && c <= 18) ||
        (r >= 16 && r <= 18 && c >= 2 && c <= 4);
      const isCornerBorder =
        isCorner &&
        ((r === 0 || r === 6 || c === 0 || c === 6) ||
         (r === 0 || r === 6 || c === 14 || c === 20) ||
         (r === 14 || r === 20 || c === 0 || c === 6));

      const bit = ((hash[(r * 21 + c) % hash.length] >> ((r + c) % 8)) & 1) === 1;
      if (isCornerBorder || isInnerCorner || (!isCorner && bit)) {
        rects += `<rect x="${c * 8 + 16}" y="${r * 8 + 16}" width="8" height="8" fill="#111827"/>`;
      }
    }
  }
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" width="200" height="200"><rect width="200" height="200" fill="#ffffff"/>${rects}</svg>`;
  return `data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}`;
}

// Session middleware helper
function getAuth(req: express.Request): { user: User; session: Session; token: string } | null {
  const token = req.cookies?.gogo_session || req.cookies?.["__Host-gogo_session"];
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expires_at < nowSec()) {
    sessions.delete(token);
    return null;
  }
  session.last_seen = nowSec();
  const user = users.find((u) => u.id === session.user_id);
  if (!user || user.disabled) return null;
  return { user, session, token };
}

function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  const auth = getAuth(req);
  if (!auth) {
    return res.status(401).json({ error: "please sign in", code: "signed_out" });
  }
  // Safe methods skip CSRF
  if (!["GET", "HEAD"].includes(req.method)) {
    const csrfSent = req.headers["x-csrf-token"];
    if (!csrfSent || csrfSent !== auth.session.csrf) {
      return res.status(403).json({ error: "request refused: missing or wrong CSRF token", code: "bad_csrf" });
    }
  }
  (req as any).auth = auth;
  next();
}

function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  requireAuth(req, res, () => {
    const auth = (req as any).auth as { user: User };
    if (auth.user.role !== "admin") {
      return res.status(403).json({ error: "administrators only", code: "forbidden" });
    }
    next();
  });
}

function requireRecent(auth: { session: Session }): boolean {
  return nowSec() - auth.session.reauth_at <= REAUTH_SECS;
}

// ---------- API Routes ----------

// Health
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok" });
});

// Bootstrap
app.get("/api/v1/bootstrap", (_req, res) => {
  res.json({
    product: "Gogo Desktop",
    version: "0.1.0",
    setup_required: false,
    local_accounts: "all",
    sso_enabled: false,
    same_pc_signin: false,
    require_totp_for_admins: false,
  });
});

// Setup
app.post("/api/v1/setup/totp", (req, res) => {
  const { username } = req.body;
  const secret = "JBSWY3DPEHPK3PXP";
  const url = `otpauth://totp/Gogo%20Desktop:${encodeURIComponent(username || "admin")}?secret=${secret}&issuer=Gogo%20Desktop`;
  res.json({
    secret,
    otpauth_url: url,
    qr: generateSvgQrDataUrl(url),
  });
});

app.post("/api/v1/setup", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 12) {
    return res.status(400).json({ error: "Password must be at least 12 characters", code: "weak_password" });
  }
  let admin = users.find((u) => u.role === "admin");
  if (!admin) {
    admin = {
      id: nextUserId++,
      username: username.trim(),
      passwordHash: hashPassword(password),
      kind: "local",
      role: "admin",
      disabled: false,
      totp_enabled: false,
      totp_secret: null,
      created_at: nowSec(),
      last_login_at: nowSec(),
      locked_until: 0,
    };
    users.push(admin);
  }
  const token = crypto.randomBytes(32).toString("hex");
  const csrf = crypto.randomBytes(32).toString("hex");
  const session: Session = {
    token,
    id_hash: crypto.createHash("sha256").update(token).digest("hex"),
    user_id: admin.id,
    method: "setup",
    ip: req.ip || "127.0.0.1",
    created_at: nowSec(),
    last_seen: nowSec(),
    expires_at: nowSec() + 86400 * 30,
    reauth_at: nowSec(),
    csrf,
  };
  sessions.set(token, session);
  res.cookie("gogo_session", token, { path: "/", httpOnly: true, sameSite: "strict", maxAge: 86400 * 30 * 1000 });
  res.json({
    user: {
      id: admin.id,
      username: admin.username,
      kind: admin.kind,
      role: admin.role,
      disabled: admin.disabled,
      totp_enabled: admin.totp_enabled,
      created_at: admin.created_at,
      last_login_at: admin.last_login_at,
      locked_until: admin.locked_until,
    },
    csrf,
  });
});

// Login
app.post("/api/v1/auth/login", (req, res) => {
  const { username, password, code } = req.body;
  const user = users.find((u) => u.username.toLowerCase() === (username || "").trim().toLowerCase());
  if (!user || user.disabled) {
    recordAudit("auth.signin_failed", username, req.ip || "127.0.0.1", { reason: "invalid_credentials" });
    return res.status(401).json({ error: "wrong username or password", code: "invalid_credentials" });
  }
  if (user.locked_until > nowSec()) {
    return res.status(429).json({ error: "account temporarily locked", code: "locked", locked_until: user.locked_until });
  }
  if (user.passwordHash !== hashPassword(password)) {
    recordAudit("auth.signin_failed", username, req.ip || "127.0.0.1", { reason: "wrong_password" });
    return res.status(401).json({ error: "wrong username or password", code: "invalid_credentials" });
  }
  if (user.totp_enabled && !code) {
    return res.status(401).json({ error: "sign-in code required", code: "code_required" });
  }

  user.last_login_at = nowSec();
  const token = crypto.randomBytes(32).toString("hex");
  const csrf = crypto.randomBytes(32).toString("hex");
  const session: Session = {
    token,
    id_hash: crypto.createHash("sha256").update(token).digest("hex"),
    user_id: user.id,
    method: "password",
    ip: req.ip || "127.0.0.1",
    created_at: nowSec(),
    last_seen: nowSec(),
    expires_at: nowSec() + 86400 * 30,
    reauth_at: nowSec(),
    csrf,
  };
  sessions.set(token, session);
  res.cookie("gogo_session", token, { path: "/", httpOnly: true, sameSite: "strict", maxAge: 86400 * 30 * 1000 });
  recordAudit("auth.signin", user.username, req.ip || "127.0.0.1", { method: "password" });
  res.json({
    user: {
      id: user.id,
      username: user.username,
      kind: user.kind,
      role: user.role,
      disabled: user.disabled,
      totp_enabled: user.totp_enabled,
      created_at: user.created_at,
      last_login_at: user.last_login_at,
      locked_until: user.locked_until,
    },
    csrf,
  });
});

// Logout
app.post("/api/v1/auth/logout", requireAuth, (req, res) => {
  const { session, user } = (req as any).auth as { session: Session; user: User };
  sessions.delete(session.token);
  res.clearCookie("gogo_session");
  recordAudit("auth.signout", user.username, req.ip || "127.0.0.1", {});
  res.json({ ok: true });
});

// Reauth
app.post("/api/v1/auth/reauth", requireAuth, (req, res) => {
  const { session, user } = (req as any).auth as { session: Session; user: User };
  const { password } = req.body;
  if (user.passwordHash !== hashPassword(password)) {
    return res.status(401).json({ error: "wrong password", code: "invalid_credentials" });
  }
  session.reauth_at = nowSec();
  recordAudit("auth.reauth", user.username, req.ip || "127.0.0.1", {});
  res.json({ ok: true, valid_for_secs: REAUTH_SECS });
});

// Recover
app.post("/api/v1/auth/recover", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username.toLowerCase() === (username || "").trim().toLowerCase());
  if (!user) {
    return res.status(404).json({ error: "user not found", code: "not_found" });
  }
  user.passwordHash = hashPassword(password);
  user.locked_until = 0;
  recordAudit("admin.recovered", user.username, req.ip || "127.0.0.1", {});
  res.json({ ok: true });
});

// Me
app.get("/api/v1/me", requireAuth, (req, res) => {
  const { session, user } = (req as any).auth as { session: Session; user: User };
  const allowedLibs = libraries.filter(
    (l) => user.role === "admin" || l.access.includes("role:user") || l.access.includes(`user:${user.id}`),
  );
  res.json({
    user: {
      id: user.id,
      username: user.username,
      kind: user.kind,
      role: user.role,
      disabled: user.disabled,
      totp_enabled: user.totp_enabled,
      created_at: user.created_at,
      last_login_at: user.last_login_at,
      locked_until: user.locked_until,
    },
    csrf: session.csrf,
    libraries: allowedLibs.map((l) => ({ id: l.id, name: l.name })),
    reauth_valid_for: Math.max(0, REAUTH_SECS - (nowSec() - session.reauth_at)),
    totp_setup_required: false,
    session: {
      method: session.method,
      created_at: session.created_at,
      expires_at: session.expires_at,
    },
    locked_settings: false,
    mode: "linux",
  });
});

// Me - password
app.post("/api/v1/me/password", requireAuth, (req, res) => {
  const { session, user } = (req as any).auth as { session: Session; user: User };
  const { current, new: newPw } = req.body;
  if (user.passwordHash !== hashPassword(current)) {
    return res.status(401).json({ error: "current password incorrect", code: "invalid_credentials" });
  }
  if (!newPw || newPw.length < 12) {
    return res.status(400).json({ error: "password must be at least 12 characters", code: "weak_password" });
  }
  user.passwordHash = hashPassword(newPw);
  // Invalidate other sessions
  for (const [t, s] of sessions.entries()) {
    if (s.user_id === user.id && t !== session.token) {
      sessions.delete(t);
    }
  }
  recordAudit("user.password_changed", user.username, req.ip || "127.0.0.1", { by: "self" });
  res.json({ ok: true });
});

// Me - TOTP
app.post("/api/v1/me/totp/begin", requireAuth, (req, res) => {
  const { user } = (req as any).auth as { user: User };
  const secret = "JBSWY3DPEHPK3PXP";
  user.totp_secret = secret;
  const url = `otpauth://totp/Gogo%20Desktop:${encodeURIComponent(user.username)}?secret=${secret}&issuer=Gogo%20Desktop`;
  res.json({
    secret,
    otpauth_url: url,
    qr: generateSvgQrDataUrl(url),
  });
});

app.post("/api/v1/me/totp/confirm", requireAuth, (req, res) => {
  const { user } = (req as any).auth as { user: User };
  user.totp_enabled = true;
  recordAudit("user.totp_enabled", user.username, req.ip || "127.0.0.1", {});
  res.json({ ok: true });
});

app.post("/api/v1/me/totp/disable", requireAuth, (req, res) => {
  const { auth } = req as any;
  if (!requireRecent(auth)) {
    return res.status(403).json({ error: "confirm it's you first", code: "reauth_required" });
  }
  const { user } = auth as { user: User };
  user.totp_enabled = false;
  user.totp_secret = null;
  recordAudit("user.totp_disabled", user.username, req.ip || "127.0.0.1", {});
  res.json({ ok: true });
});

// Sessions
app.get("/api/v1/me/sessions", requireAuth, (req, res) => {
  const { user, session: currentSession } = (req as any).auth as { user: User; session: Session };
  const userSessions = Array.from(sessions.values()).filter((s) => s.user_id === user.id);
  res.json({
    sessions: userSessions.map((s) => ({
      current: s.id_hash === currentSession.id_hash,
      method: s.method,
      ip: s.ip,
      created_at: s.created_at,
      last_seen: s.last_seen,
      expires_at: s.expires_at,
    })),
  });
});

app.post("/api/v1/me/sessions/end-others", requireAuth, (req, res) => {
  const { user, session: currentSession } = (req as any).auth as { user: User; session: Session };
  let count = 0;
  for (const [t, s] of sessions.entries()) {
    if (s.user_id === user.id && t !== currentSession.token) {
      sessions.delete(t);
      count++;
    }
  }
  recordAudit("user.sessions_ended", user.username, req.ip || "127.0.0.1", { count });
  res.json({ ended: count });
});

// ---------- Search Engine ----------

interface SearchQuery {
  terms: string[];
  phrases: string[];
  negations: string[];
  extensions: string[];
  typeFilter: "file" | "folder" | null;
  minSize: number | null;
  maxSize: number | null;
  pathSubstr: string[];
  libraries: string[];
}

function parseSearchQuery(q: string): SearchQuery {
  const query: SearchQuery = {
    terms: [],
    phrases: [],
    negations: [],
    extensions: [],
    typeFilter: null,
    minSize: null,
    maxSize: null,
    pathSubstr: [],
    libraries: [],
  };

  // Extract quoted phrases
  let remainder = q.replace(/"([^"]+)"/g, (_m, phrase) => {
    query.phrases.push(phrase.toLowerCase().trim());
    return "";
  });

  const tokens = remainder.trim().split(/\s+/).filter(Boolean);
  for (const token of tokens) {
    const lower = token.toLowerCase();
    if (lower.startsWith("ext:")) {
      query.extensions.push(lower.slice(4).replace(/^\./, ""));
    } else if (lower.startsWith("type:")) {
      const val = lower.slice(5);
      if (val === "folder" || val === "dir" || val === "directory") query.typeFilter = "folder";
      if (val === "file") query.typeFilter = "file";
    } else if (lower.startsWith("lib:")) {
      query.libraries.push(lower.slice(4));
    } else if (lower.startsWith("path:")) {
      query.pathSubstr.push(lower.slice(5));
    } else if (lower.startsWith("size:>")) {
      query.minSize = parseSize(lower.slice(6));
    } else if (lower.startsWith("size:<")) {
      query.maxSize = parseSize(lower.slice(6));
    } else if (lower.startsWith("-")) {
      query.negations.push(lower.slice(1));
    } else {
      query.terms.push(lower);
    }
  }
  return query;
}

function parseSize(s: string): number {
  const match = s.match(/^(\d+(?:\.\d+)?)\s*([kmgt])?b?$/i);
  if (!match) return 0;
  const num = parseFloat(match[1]);
  const unit = (match[2] || "").toLowerCase();
  if (unit === "k") return num * 1024;
  if (unit === "m") return num * 1024 * 1024;
  if (unit === "g") return num * 1024 * 1024 * 1024;
  if (unit === "t") return num * 1024 * 1024 * 1024 * 1024;
  return num;
}

app.get("/api/v1/search", requireAuth, (req, res) => {
  const start = performance.now();
  const { user } = (req as any).auth as { user: User };
  const rawQ = String(req.query.q || "").trim();
  const limit = Math.min(200, Math.max(1, parseInt(String(req.query.limit || "50"), 10) || 50));
  const libFilter = String(req.query.lib || "").trim().toLowerCase();

  // Find user accessible libraries
  const allowedLibs = libraries.filter(
    (l) => user.role === "admin" || l.access.includes("role:user") || l.access.includes(`user:${user.id}`),
  );
  const allowedMap = new Map(allowedLibs.map((l) => [l.id, l]));

  if (!rawQ) {
    return res.json({ total: 0, took_ms: 0.1, hits: [] });
  }

  const query = parseSearchQuery(rawQ);

  const matched = fileIndex.filter((item) => {
    const lib = allowedMap.get(item.libraryId);
    if (!lib) return false;
    if (libFilter && lib.name.toLowerCase() !== libFilter) return false;
    if (query.libraries.length && !query.libraries.some((l) => lib.name.toLowerCase().includes(l))) return false;

    // Type filter
    if (query.typeFilter === "folder" && !item.is_dir) return false;
    if (query.typeFilter === "file" && item.is_dir) return false;

    // Extension filter
    if (query.extensions.length) {
      const ext = item.name.includes(".") ? item.name.split(".").pop()?.toLowerCase() : "";
      if (!query.extensions.includes(ext || "")) return false;
    }

    // Size filter
    if (query.minSize !== null && item.size < query.minSize) return false;
    if (query.maxSize !== null && item.size > query.maxSize) return false;

    // Path substring filter
    if (query.pathSubstr.length) {
      const relLower = item.rel_path.toLowerCase();
      if (!query.pathSubstr.every((p) => relLower.includes(p))) return false;
    }

    const nameLower = item.name.toLowerCase();
    const fullLower = `${item.rel_path} ${item.name}`.toLowerCase();

    // Negations
    if (query.negations.some((neg) => fullLower.includes(neg))) return false;

    // Exact phrases
    if (query.phrases.length && !query.phrases.every((ph) => fullLower.includes(ph))) return false;

    // Terms with wildcard support (* and ?)
    if (query.terms.length) {
      const matchAll = query.terms.every((term) => {
        if (term.includes("*") || term.includes("?")) {
          const regex = new RegExp(
            "^" + term.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$",
            "i",
          );
          return regex.test(item.name) || regex.test(item.rel_path);
        }
        return fullLower.includes(term);
      });
      if (!matchAll) return false;
    }

    return true;
  });

  const hits = matched.slice(0, limit).map((item) => {
    const lib = allowedMap.get(item.libraryId)!;
    return {
      id: item.id,
      library: lib.name,
      name: item.name,
      rel_path: item.rel_path,
      path: formatDisplayPath(lib, item.rel_path),
      folder: formatFolderPath(lib, item.rel_path),
      is_dir: item.is_dir,
      size: item.size,
      mtime: item.mtime,
    };
  });

  const took_ms = +(performance.now() - start).toFixed(1);
  res.json({
    total: matched.length,
    took_ms,
    hits,
  });
});

// Status
app.get("/api/v1/status", requireAuth, (req, res) => {
  const { user } = (req as any).auth as { user: User };
  const admin = user.role === "admin";
  const allowedLibs = libraries.filter(
    (l) => admin || l.access.includes("role:user") || l.access.includes(`user:${user.id}`),
  );

  res.json({
    version: "0.1.0",
    mode: "linux",
    profile: "release",
    uptime_secs: Math.floor((Date.now() - startTime) / 1000),
    libraries: allowedLibs.map((l) => ({
      id: l.id,
      name: l.name,
      path: l.path,
      display_prefix: l.display_prefix,
      source: l.source,
      state: l.state,
      method: l.method,
      entries: l.entries,
      last_scan_at: l.last_scan_at,
      last_scan_ms: l.last_scan_ms,
      message: l.message,
    })),
    settings: admin
      ? {
          local_accounts: "all",
          require_totp_for_local_admins: false,
          sso_enabled: false,
          approval: { mandatory: true, pending_max: 50, expiry_days: 30 },
          session_idle_hours: 24,
          session_max_days: 30,
          locked: false,
        }
      : null,
  });
});

// ---------- Admin Routes ----------

// Users
app.get("/api/v1/users", requireAdmin, (_req, res) => {
  res.json({
    users: users.map((u) => ({
      id: u.id,
      username: u.username,
      kind: u.kind,
      role: u.role,
      disabled: u.disabled,
      totp_enabled: u.totp_enabled,
      created_at: u.created_at,
      last_login_at: u.last_login_at,
      locked_until: u.locked_until,
    })),
  });
});

app.post("/api/v1/users", requireAdmin, (req, res) => {
  const { auth } = req as any;
  const { username, password, role } = req.body;
  if (!username || !password || password.length < 12) {
    return res.status(400).json({ error: "Password must be at least 12 characters", code: "weak_password" });
  }
  const cleanUser = username.trim();
  if (users.some((u) => u.username.toLowerCase() === cleanUser.toLowerCase())) {
    return res.status(409).json({ error: "A user with that name already exists", code: "duplicate" });
  }
  const newUser: User = {
    id: nextUserId++,
    username: cleanUser,
    passwordHash: hashPassword(password),
    kind: "local",
    role: role === "admin" ? "admin" : "user",
    disabled: false,
    totp_enabled: false,
    totp_secret: null,
    created_at: nowSec(),
    last_login_at: null,
    locked_until: 0,
  };
  users.push(newUser);
  recordAudit("user.created", auth.user.username, req.ip || "127.0.0.1", { user: newUser.username, role: newUser.role });
  res.json({
    user: {
      id: newUser.id,
      username: newUser.username,
      kind: newUser.kind,
      role: newUser.role,
      disabled: newUser.disabled,
      totp_enabled: newUser.totp_enabled,
      created_at: newUser.created_at,
      last_login_at: newUser.last_login_at,
      locked_until: newUser.locked_until,
    },
  });
});

app.patch("/api/v1/users/:id", requireAdmin, (req, res) => {
  const { auth } = req as any;
  if (!requireRecent(auth)) {
    return res.status(403).json({ error: "confirm it's you first", code: "reauth_required" });
  }
  const id = parseInt(req.params.id, 10);
  const target = users.find((u) => u.id === id);
  if (!target) return res.status(404).json({ error: "user not found", code: "not_found" });

  const { role, disabled } = req.body;
  if (role) {
    target.role = role === "admin" ? "admin" : "user";
    recordAudit("user.role_changed", auth.user.username, req.ip || "127.0.0.1", { user: target.username, role: target.role });
  }
  if (disabled !== undefined) {
    if (disabled && target.id === auth.user.id) {
      return res.status(400).json({ error: "you can't disable your own account", code: "invalid" });
    }
    target.disabled = !!disabled;
    recordAudit(disabled ? "user.disabled" : "user.enabled", auth.user.username, req.ip || "127.0.0.1", { user: target.username });
  }
  res.json({ user: target });
});

app.delete("/api/v1/users/:id", requireAdmin, (req, res) => {
  const { auth } = req as any;
  if (!requireRecent(auth)) {
    return res.status(403).json({ error: "confirm it's you first", code: "reauth_required" });
  }
  const id = parseInt(req.params.id, 10);
  if (id === auth.user.id) {
    return res.status(400).json({ error: "you can't delete your own account", code: "invalid" });
  }
  const idx = users.findIndex((u) => u.id === id);
  if (idx === -1) return res.status(404).json({ error: "user not found", code: "not_found" });
  const [removed] = users.splice(idx, 1);
  recordAudit("user.deleted", auth.user.username, req.ip || "127.0.0.1", { user: removed.username });
  res.json({ ok: true });
});

app.post("/api/v1/users/:id/password", requireAdmin, (req, res) => {
  const { auth } = req as any;
  if (!requireRecent(auth)) {
    return res.status(403).json({ error: "confirm it's you first", code: "reauth_required" });
  }
  const id = parseInt(req.params.id, 10);
  const target = users.find((u) => u.id === id);
  if (!target) return res.status(404).json({ error: "user not found", code: "not_found" });
  const { password } = req.body;
  if (!password || password.length < 12) {
    return res.status(400).json({ error: "password must be at least 12 characters", code: "weak_password" });
  }
  target.passwordHash = hashPassword(password);
  recordAudit("user.password_changed", auth.user.username, req.ip || "127.0.0.1", { user: target.username, by: "admin" });
  res.json({ ok: true });
});

app.post("/api/v1/users/:id/unlock", requireAdmin, (req, res) => {
  const { auth } = req as any;
  const id = parseInt(req.params.id, 10);
  const target = users.find((u) => u.id === id);
  if (!target) return res.status(404).json({ error: "user not found", code: "not_found" });
  target.locked_until = 0;
  recordAudit("user.unlocked", auth.user.username, req.ip || "127.0.0.1", { user: target.username });
  res.json({ ok: true });
});

app.post("/api/v1/users/:id/sessions/end", requireAdmin, (req, res) => {
  const { auth } = req as any;
  const id = parseInt(req.params.id, 10);
  const target = users.find((u) => u.id === id);
  if (!target) return res.status(404).json({ error: "user not found", code: "not_found" });
  let count = 0;
  for (const [t, s] of sessions.entries()) {
    if (s.user_id === id) {
      sessions.delete(t);
      count++;
    }
  }
  recordAudit("user.sessions_ended", auth.user.username, req.ip || "127.0.0.1", { user: target.username, count });
  res.json({ ended: count });
});

// Libraries
app.get("/api/v1/libraries", requireAdmin, (_req, res) => {
  res.json({ libraries, mode: "linux" });
});

app.post("/api/v1/libraries", requireAdmin, (req, res) => {
  const { auth } = req as any;
  if (!requireRecent(auth)) {
    return res.status(403).json({ error: "confirm it's you first", code: "reauth_required" });
  }
  const { name, path: libPath, display_prefix } = req.body;
  if (!name || !libPath) {
    return res.status(400).json({ error: "name and path required", code: "invalid" });
  }
  const newLib: Library = {
    id: nextLibraryId++,
    name: name.trim(),
    path: libPath.trim(),
    display_prefix: display_prefix ? display_prefix.trim() : null,
    source: "admin",
    access: ["role:user"],
    excludes: [],
    entries: 0,
    state: "ready",
    method: "watch",
    last_scan_at: nowSec(),
    last_scan_ms: 100,
  };
  libraries.push(newLib);
  recordAudit("library.added", auth.user.username, req.ip || "127.0.0.1", { library: newLib.name, path: newLib.path });
  res.json({ library: newLib });
});

app.patch("/api/v1/libraries/:id", requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const lib = libraries.find((l) => l.id === id);
  if (!lib) return res.status(404).json({ error: "library not found", code: "not_found" });
  const { display_prefix, excludes } = req.body;
  if (display_prefix !== undefined) {
    lib.display_prefix = display_prefix.trim() || null;
  }
  if (excludes !== undefined && Array.isArray(excludes)) {
    lib.excludes = excludes;
  }
  res.json({ library: lib });
});

app.delete("/api/v1/libraries/:id", requireAdmin, (req, res) => {
  const { auth } = req as any;
  if (!requireRecent(auth)) {
    return res.status(403).json({ error: "confirm it's you first", code: "reauth_required" });
  }
  const id = parseInt(req.params.id, 10);
  const lib = libraries.find((l) => l.id === id);
  if (!lib) return res.status(404).json({ error: "library not found", code: "not_found" });
  const { confirm_name } = req.body;
  if (confirm_name?.trim() !== lib.name) {
    return res.status(400).json({ error: "type the library name exactly to confirm", code: "invalid" });
  }
  const idx = libraries.findIndex((l) => l.id === id);
  libraries.splice(idx, 1);
  recordAudit("library.removed", auth.user.username, req.ip || "127.0.0.1", { library: lib.name });
  res.json({ ok: true });
});

app.put("/api/v1/libraries/:id/access", requireAdmin, (req, res) => {
  const { auth } = req as any;
  if (!requireRecent(auth)) {
    return res.status(403).json({ error: "confirm it's you first", code: "reauth_required" });
  }
  const id = parseInt(req.params.id, 10);
  const lib = libraries.find((l) => l.id === id);
  if (!lib) return res.status(404).json({ error: "library not found", code: "not_found" });
  const { principals } = req.body;
  if (Array.isArray(principals)) {
    lib.access = principals;
  }
  recordAudit("library.access_changed", auth.user.username, req.ip || "127.0.0.1", { library: lib.name, access: lib.access });
  res.json({ library: lib });
});

app.post("/api/v1/libraries/:id/recheck", requireAdmin, (req, res) => {
  const { auth } = req as any;
  const id = parseInt(req.params.id, 10);
  const lib = libraries.find((l) => l.id === id);
  if (!lib) return res.status(404).json({ error: "library not found", code: "not_found" });
  lib.last_scan_at = nowSec();
  lib.last_scan_ms = Math.floor(100 + Math.random() * 200);
  recordAudit("library.recheck", auth.user.username, req.ip || "127.0.0.1", { library: lib.name });
  res.json({ ok: true });
});

// Audit
app.get("/api/v1/audit", requireAdmin, (req, res) => {
  const limit = Math.min(1000, parseInt(String(req.query.limit || "100"), 10) || 100);
  const prefix = String(req.query.prefix || "").trim();
  const records = auditLog.filter((r) => !prefix || r.event.startsWith(prefix)).slice(0, limit);
  res.json({ records });
});

// ---------- Vite Dev & Static Assets Mounting ----------

async function startServer() {
  const isDev = process.env.NODE_ENV !== "production";
  if (isDev) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, "dist")));
    app.get("*", (_req, res) => {
      res.sendFile(path.resolve(__dirname, "dist", "index.html"));
    });
  }

  const PORT = 3000;
  const HOST = "0.0.0.0";
  app.listen(PORT, HOST, () => {
    console.log(`Gogo Desktop is running on http://${HOST}:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start Gogo Desktop server:", err);
  process.exit(1);
});
