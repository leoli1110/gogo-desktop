// API client: JSON, CSRF header, and errors with a machine-readable code.

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public extra: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

let csrf = "";
export function setCsrf(token: string): void {
  csrf = token;
}

// Hook for "confirm it's you": returns true if the user re-authenticated.
let reauthHandler: (() => Promise<boolean>) | null = null;
export function onReauth(fn: () => Promise<boolean>): void {
  reauthHandler = fn;
}

export async function api<T = any>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrf) headers["X-CSRF-Token"] = csrf;
  const resp = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
    signal,
  });
  let data: any = null;
  try {
    data = await resp.json();
  } catch {
    data = null;
  }
  if (!resp.ok) {
    const err = new ApiError(resp.status, data?.code ?? "error", data?.error ?? resp.statusText, data ?? {});
    if (err.code === "reauth_required" && reauthHandler) {
      if (await reauthHandler()) return api<T>(method, path, body, signal);
    }
    throw err;
  }
  return data as T;
}

export interface User {
  id: number;
  username: string;
  kind: "local" | "windows";
  role: "admin" | "user";
  disabled: boolean;
  totp_enabled: boolean;
  created_at: number;
  last_login_at: number | null;
  locked_until: number;
}

export interface Me {
  user: User;
  csrf: string;
  libraries: { id: number; name: string }[];
  totp_setup_required: boolean;
  mode: string;
}

export interface Hit {
  id: string;
  library: string;
  name: string;
  rel_path: string;
  path: string;
  folder: string;
  is_dir: boolean;
  size: number;
  mtime: number;
}

export interface Library {
  id: number;
  name: string;
  path: string;
  display_prefix: string | null;
  excludes: string[];
  source: string;
  access: string[];
}
