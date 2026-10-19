// Account page: password, sign-in code app, sessions.

import { api, ApiError, Me } from "./api";
import { clear, field, formatTime, h, input, message } from "./dom";
import { t } from "./i18n";

function errText(e: unknown): string {
  return e instanceof ApiError ? e.message : t("error");
}

export function accountPage(me: Me, refresh: () => void): HTMLElement {
  const section = h("section", {});
  if (me.totp_setup_required) section.append(message("info", t("totpRequired")));

  // Sign-in code app
  const totpBox = h("div", { class: "card" }, h("h2", {}, t("totpTitle")));
  const totpBody = h("div", {});
  totpBox.append(totpBody);
  const renderTotp = () => {
    clear(totpBody);
    if (me.user.kind !== "local") return;
    if (me.user.totp_enabled) {
      totpBody.append(
        h("p", {}, t("totpOn")),
        h(
          "button",
          {
            type: "button",
            onclick: async () => {
              try {
                await api("POST", "/api/v1/me/totp/disable", {});
                refresh();
              } catch (e) {
                totpBody.append(message("error", errText(e)));
              }
            },
          },
          t("totpDisable"),
        ),
      );
      return;
    }
    totpBody.append(
      h("p", {}, t("totpOff")),
      h(
        "button",
        {
          type: "button",
          class: "primary",
          onclick: async () => {
            try {
              const r = await api("POST", "/api/v1/me/totp/begin", {});
              const code = input("code", "text", { inputmode: "numeric", autocomplete: "one-time-code", maxlength: 8, autofocus: true });
              const msg = h("div", {});
              clear(totpBody);
              totpBody.append(
                h("p", {}, t("totpScan")),
                h("img", { src: r.qr, alt: "QR code", width: 200, height: 200, class: "qr" }),
                h("p", { class: "mono small" }, r.secret),
                h(
                  "form",
                  {
                    onsubmit: async (e: Event) => {
                      e.preventDefault();
                      try {
                        await api("POST", "/api/v1/me/totp/confirm", { code: code.value });
                        refresh();
                      } catch (err) {
                        clear(msg);
                        msg.append(message("error", errText(err)));
                      }
                    },
                  },
                  field(t("code"), code),
                  msg,
                  h("button", { type: "submit", class: "primary" }, t("confirm")),
                ),
              );
              code.focus();
            } catch (e) {
              totpBody.append(message("error", errText(e)));
            }
          },
        },
        t("totpSetup"),
      ),
    );
  };
  renderTotp();

  // Password
  const cur = input("current", "password", { autocomplete: "current-password", required: true });
  const nw = input("new", "password", { autocomplete: "new-password", required: true, minlength: 12 });
  const code = input("code", "text", { inputmode: "numeric", autocomplete: "one-time-code", maxlength: 8 });
  const pwMsg = h("div", {});
  const pwForm = h(
    "form",
    {
      class: "card",
      onsubmit: async (e: Event) => {
        e.preventDefault();
        clear(pwMsg);
        try {
          await api("POST", "/api/v1/me/password", { current: cur.value, new: nw.value, code: code.value || null });
          cur.value = nw.value = code.value = "";
          pwMsg.append(message("ok", t("passwordChanged")));
        } catch (err) {
          pwMsg.append(message("error", errText(err)));
        }
      },
    },
    h("h2", {}, t("password")),
    field(t("currentPassword"), cur),
    field(t("newPassword"), nw, t("passwordRules")),
    me.user.totp_enabled ? field(t("code"), code) : null,
    pwMsg,
    h("button", { type: "submit", class: "primary" }, t("save")),
  );

  // Sessions
  const sessBox = h("div", { class: "card" }, h("h2", {}, t("sessions")));
  const sessList = h("ul", { class: "plain" });
  const loadSessions = async () => {
    const r = await api("GET", "/api/v1/me/sessions");
    clear(sessList);
    for (const s of r.sessions) {
      sessList.append(h("li", {}, `${s.method} · ${s.ip || "-"} · ${formatTime(s.last_seen)}`, s.current ? h("span", { class: "tag" }, t("thisSession")) : null));
    }
  };
  sessBox.append(
    sessList,
    h(
      "button",
      {
        type: "button",
        onclick: async () => {
          await api("POST", "/api/v1/me/sessions/end-others", {});
          void loadSessions();
        },
      },
      t("endOthers"),
    ),
  );
  void loadSessions().catch(() => undefined);

  section.append(
    h("h1", {}, `${t("account")}: ${me.user.username}`),
    h("p", { class: "muted" }, `${me.user.kind === "local" ? t("local") : t("windows")} · ${me.user.role === "admin" ? t("admin") : t("user")}`),
    ...(me.user.kind === "local" ? [totpBox, pwForm] : []),
    sessBox,
  );
  return section;
}
