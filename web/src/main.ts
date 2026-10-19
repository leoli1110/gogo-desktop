// Gogo Desktop web interface: routing, shell, and sign-in pages.

import "./style.css";
import { api, ApiError, Me, onReauth, setCsrf } from "./api";
import { clear, field, h, input, message } from "./dom";
import { t, toggleLanguage } from "./i18n";
import { searchPage } from "./search";
import { librariesPage, statusPage, usersPage } from "./admin";
import { accountPage } from "./account";

const root = document.getElementById("app")!;
export let me: Me | null = null;

interface Bootstrap {
  setup_required: boolean;
  same_pc_signin: boolean;
  require_totp_for_admins: boolean;
  version: string;
}

export function go(path: string): void {
  history.pushState({}, "", path);
  void route();
}

window.addEventListener("popstate", () => void route());
document.addEventListener("click", (e) => {
  const a = (e.target as HTMLElement).closest("a[data-nav]") as HTMLAnchorElement | null;
  if (a && !e.ctrlKey && !e.metaKey && !e.shiftKey) {
    e.preventDefault();
    go(a.getAttribute("href")!);
  }
});

async function loadMe(): Promise<Me | null> {
  try {
    me = await api<Me>("GET", "/api/v1/me");
    setCsrf(me.csrf);
    return me;
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return null;
    throw e;
  }
}

function shell(active: string, content: HTMLElement): HTMLElement {
  const admin = me?.user.role === "admin";
  const link = (path: string, label: string) =>
    h("a", { href: path, "data-nav": "1", class: active === path ? "active" : "", "aria-current": active === path ? "page" : undefined }, label);
  const nav = h(
    "nav",
    { class: "topnav", "aria-label": "Main" },
    h("a", { href: "/", "data-nav": "1", class: "brand" }, t("appName")),
    link("/", t("search")),
    link("/status", t("status")),
    admin ? link("/users", t("users")) : null,
    admin ? link("/libraries", t("libraries")) : null,
    h("span", { class: "spacer" }),
    link("/account", `${t("account")} (${me?.user.username ?? ""})`),
    h("button", { class: "linklike", type: "button", onclick: () => toggleLanguage() }, t("language")),
    h(
      "button",
      {
        class: "linklike",
        type: "button",
        onclick: async () => {
          await api("POST", "/api/v1/auth/logout", {}).catch(() => undefined);
          me = null;
          go("/login");
        },
      },
      t("signOut"),
    ),
  );
  return h("div", { class: "layout" }, nav, h("main", { id: "main" }, content));
}

function card(title: string, ...children: (Node | null)[]): HTMLElement {
  return h("div", { class: "auth-wrap" }, h("div", { class: "card auth" }, h("h1", {}, title), ...children));
}

function errorText(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  return t("error");
}

function loginPage(boot: Bootstrap): HTMLElement {
  const user = input("username", "text", { autocomplete: "username", required: true, autofocus: true });
  const pass = input("password", "password", { autocomplete: "current-password", required: true });
  const code = input("code", "text", { inputmode: "numeric", autocomplete: "one-time-code", maxlength: 8 });
  const codeField = field(t("code"), code);
  codeField.hidden = true;
  const msg = h("div", {});
  const form = h(
    "form",
    {
      onsubmit: async (e: Event) => {
        e.preventDefault();
        clear(msg);
        try {
          await api("POST", "/api/v1/auth/login", { username: user.value, password: pass.value, code: code.value || null });
          await loadMe();
          go(new URLSearchParams(location.search).get("next")?.startsWith("/") ? new URLSearchParams(location.search).get("next")! : "/");
        } catch (err) {
          if (err instanceof ApiError && err.code === "code_required") {
            codeField.hidden = false;
            code.focus();
            return;
          }
          msg.append(message("error", errorText(err)));
        }
      },
    },
    field(t("username"), user),
    field(t("password"), pass),
    codeField,
    msg,
    h("button", { type: "submit", class: "primary" }, t("signIn")),
  );
  return card(
    t("appName"),
    form,
    boot.same_pc_signin ? h("p", { class: "muted" }, t("sameP")) : null,
    h("p", { class: "muted" }, h("a", { href: "/recover", "data-nav": "1" }, t("forgot"))),
    h("p", { class: "muted small" }, h("button", { class: "linklike", type: "button", onclick: () => toggleLanguage() }, t("language"))),
  );
}

function setupPage(boot: Bootstrap): HTMLElement {
  const code = input("code", "text", { required: true, autofocus: true, placeholder: "XXXX-XXXX-XXXX" });
  const user = input("username", "text", { required: true, autocomplete: "username", value: "admin" });
  const pass = input("password", "password", { required: true, autocomplete: "new-password", minlength: 12 });
  const pass2 = input("password2", "password", { required: true, autocomplete: "new-password" });
  const otp = input("otp", "text", { inputmode: "numeric", autocomplete: "one-time-code", maxlength: 8 });
  const totpBox = h("div", { class: "totp-box" });
  totpBox.hidden = true;
  const msg = h("div", {});
  let totpReady = !boot.require_totp_for_admins;
  const submit = h("button", { type: "submit", class: "primary" }, boot.require_totp_for_admins ? t("next") : t("create"));
  const form = h(
    "form",
    {
      onsubmit: async (e: Event) => {
        e.preventDefault();
        clear(msg);
        if (pass.value !== pass2.value) {
          msg.append(message("error", t("confirmPassword")));
          return;
        }
        try {
          if (!totpReady) {
            const r = await api("POST", "/api/v1/setup/totp", { code: code.value, username: user.value });
            clear(totpBox);
            totpBox.append(
              h("p", {}, t("setupTotpIntro")),
              h("img", { src: r.qr, alt: "QR code", width: 200, height: 200, class: "qr" }),
              h("p", { class: "mono small" }, r.secret),
              field(t("code"), otp),
            );
            totpBox.hidden = false;
            totpReady = true;
            submit.textContent = t("create");
            otp.focus();
            return;
          }
          const r = await api("POST", "/api/v1/setup", {
            code: code.value,
            username: user.value,
            password: pass.value,
            totp_code: otp.value || null,
          });
          setCsrf(r.csrf);
          await loadMe();
          go("/libraries");
        } catch (err) {
          msg.append(message("error", errorText(err)));
        }
      },
    },
    h("p", {}, t("setupIntro")),
    field(t("setupCode"), code),
    field(t("username"), user),
    field(t("password"), pass, t("passwordRules")),
    field(t("confirmPassword"), pass2),
    totpBox,
    msg,
    submit,
  );
  return card(t("setupTitle"), form);
}

function recoverPage(): HTMLElement {
  const code = input("code", "text", { required: true, autofocus: true, placeholder: "XXXX-XXXX-XXXX" });
  const user = input("username", "text", { required: true, autocomplete: "username" });
  const pass = input("password", "password", { required: true, autocomplete: "new-password", minlength: 12 });
  const msg = h("div", {});
  const form = h(
    "form",
    {
      onsubmit: async (e: Event) => {
        e.preventDefault();
        clear(msg);
        try {
          await api("POST", "/api/v1/auth/recover", { code: code.value, username: user.value, password: pass.value });
          msg.append(message("ok", t("recoverDone")));
        } catch (err) {
          msg.append(message("error", errorText(err)));
        }
      },
    },
    field(t("resetCode"), code),
    field(t("username"), user),
    field(t("newPassword"), pass, t("passwordRules")),
    msg,
    h("button", { type: "submit", class: "primary" }, t("save")),
  );
  return card(t("recoverTitle"), form, h("p", {}, h("a", { href: "/login", "data-nav": "1" }, t("signIn"))));
}

async function onetimePage(): Promise<HTMLElement> {
  const token = location.hash.slice(1);
  history.replaceState({}, "", "/signin");
  try {
    if (!token) throw new Error("missing");
    const r = await api("POST", "/api/v1/auth/onetime", { token });
    setCsrf(r.csrf);
    await loadMe();
    go("/");
    return h("div");
  } catch {
    return card(t("appName"), message("error", t("signinFailed")), h("p", {}, h("a", { href: "/login", "data-nav": "1" }, t("signIn"))));
  }
}

// "Confirm it's you" dialog, used when the server asks for re-authentication.
onReauth(
  () =>
    new Promise<boolean>((resolve) => {
      if (me?.user.kind !== "local") {
        resolve(false);
        return;
      }
      const pass = input("password", "password", { autocomplete: "current-password", required: true, autofocus: true });
      const code = input("code", "text", { inputmode: "numeric", autocomplete: "one-time-code", maxlength: 8 });
      const codeField = field(t("code"), code);
      codeField.hidden = !me?.user.totp_enabled;
      const msg = h("div", {});
      const dlg = h("dialog", { class: "card" }) as HTMLDialogElement;
      const done = (ok: boolean) => {
        dlg.close();
        dlg.remove();
        resolve(ok);
      };
      dlg.append(
        h(
          "form",
          {
            onsubmit: async (e: Event) => {
              e.preventDefault();
              clear(msg);
              try {
                await api("POST", "/api/v1/auth/reauth", { password: pass.value, code: code.value || null });
                done(true);
              } catch (err) {
                if (err instanceof ApiError && err.code === "code_required") codeField.hidden = false;
                msg.append(message("error", errorText(err)));
              }
            },
          },
          h("h2", {}, t("reauthTitle")),
          h("p", {}, t("reauthIntro")),
          field(t("password"), pass),
          codeField,
          msg,
          h(
            "div",
            { class: "row" },
            h("button", { type: "submit", class: "primary" }, t("confirm")),
            h("button", { type: "button", onclick: () => done(false) }, t("cancel")),
          ),
        ),
      );
      dlg.addEventListener("cancel", () => done(false));
      document.body.append(dlg);
      dlg.showModal();
    }),
);

async function route(): Promise<void> {
  const path = location.pathname;
  let view: HTMLElement;
  try {
    const boot = await api<Bootstrap>("GET", "/api/v1/bootstrap");
    if (boot.setup_required) {
      if (path !== "/setup") history.replaceState({}, "", "/setup");
      view = setupPage(boot);
    } else if (path === "/signin") {
      view = await onetimePage();
      if (me) return;
    } else if (path === "/recover") {
      view = recoverPage();
    } else if (!(await loadMe())) {
      if (path !== "/login") history.replaceState({}, "", path === "/" ? "/login" : `/login?next=${encodeURIComponent(path)}`);
      view = loginPage(boot);
    } else if (path === "/login" || path === "/setup") {
      history.replaceState({}, "", "/");
      return route();
    } else if (me!.totp_setup_required && path !== "/account") {
      history.replaceState({}, "", "/account");
      return route();
    } else {
      const pages: Record<string, () => HTMLElement> = {
        "/": () => searchPage(me!),
        "/status": () => statusPage(me!),
        "/users": () => usersPage(me!),
        "/libraries": () => librariesPage(me!),
        "/account": () => accountPage(me!, () => void route()),
      };
      const page = pages[path] ?? (() => h("div", { class: "card" }, h("h1", {}, "404")));
      view = shell(path, page());
    }
  } catch (e) {
    view = card(t("appName"), message("error", errorText(e)));
  }
  clear(root);
  root.append(view);
  const focus = root.querySelector<HTMLElement>("[autofocus]");
  focus?.focus();
}

void route();
