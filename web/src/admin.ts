// Status, Users and Libraries pages.

import { api, ApiError, Library, Me, User } from "./api";
import { clear, field, formatDuration, formatTime, h, input, message, toast } from "./dom";
import { t } from "./i18n";

function errText(e: unknown): string {
  return e instanceof ApiError ? e.message : t("error");
}

async function act(fn: () => Promise<unknown>, after: () => void, msgBox?: HTMLElement): Promise<void> {
  try {
    await fn();
    after();
  } catch (e) {
    if (msgBox) {
      clear(msgBox);
      msgBox.append(message("error", errText(e)));
    } else {
      toast(errText(e));
    }
  }
}

export function statusPage(me: Me): HTMLElement {
  const box = h("section", { class: "card" }, h("h1", {}, t("status")));
  const body = h("div", {});
  box.append(body);
  const load = async () => {
    try {
      const s = await api("GET", "/api/v1/status");
      clear(body);
      body.append(
        h("p", { class: "muted" }, `${t("version")} ${s.version} · ${s.mode} · ${t("uptime")} ${formatDuration(s.uptime_secs)}`),
        h(
          "table",
          {},
          h(
            "thead",
            {},
            h("tr", {}, ...[t("library"), t("state"), t("method"), t("entries"), t("lastScan"), ""].map((x) => h("th", {}, x))),
          ),
          h(
            "tbody",
            {},
            ...s.libraries.map((l: any) =>
              h(
                "tr",
                {},
                h("td", {}, l.name),
                h("td", {}, h("span", { class: `state state-${l.state}` }, l.state)),
                h("td", {}, l.method),
                h("td", {}, Number(l.entries).toLocaleString()),
                h("td", {}, `${formatTime(l.last_scan_at)} (${(l.last_scan_ms / 1000).toFixed(1)} s)`),
                h(
                  "td",
                  {},
                  me.user.role === "admin"
                    ? h("button", { type: "button", onclick: () => act(() => api("POST", `/api/v1/libraries/${l.id}/recheck`, {}), () => toast(t("recheck"))) }, t("recheck"))
                    : null,
                  l.message ? h("div", { class: "small muted" }, l.message) : null,
                ),
              ),
            ),
          ),
        ),
        ...(s.settings
          ? [h(
              "details",
              { class: "small" },
              h("summary", {}, t("settings")),
              h("pre", { class: "mono" }, JSON.stringify(s.settings, null, 2)),
            )]
          : []),
      );
    } catch (e) {
      clear(body);
      body.append(message("error", errText(e)));
    }
  };
  void load();
  const timer = window.setInterval(() => (document.body.contains(box) ? void load() : window.clearInterval(timer)), 3000);
  return box;
}

export function usersPage(me: Me): HTMLElement {
  const section = h("section", {});
  const tableBox = h("div", { class: "card" }, h("h1", {}, t("users")));
  const list = h("div", {});
  tableBox.append(list);
  const msg = h("div", {});

  const load = async () => {
    const { users } = await api<{ users: User[] }>("GET", "/api/v1/users");
    clear(list);
    const now = Date.now() / 1000;
    list.append(
      msg,
      h(
        "table",
        {},
        h("thead", {}, h("tr", {}, ...[t("username"), t("kind"), t("role"), t("twofa"), t("state"), t("lastLogin"), t("actions")].map((x) => h("th", {}, x)))),
        h(
          "tbody",
          {},
          ...users.map((u) => {
            const self = u.id === me.user.id;
            const state = u.disabled ? t("disabled") : u.locked_until > now ? t("locked") : t("active");
            const btn = (label: string, fn: () => Promise<unknown>) =>
              h("button", { type: "button", onclick: () => act(fn, () => void load(), msg) }, label);
            return h(
              "tr",
              {},
              h("td", {}, u.username, self ? h("span", { class: "tag" }, "you") : null),
              h("td", {}, u.kind === "local" ? t("local") : t("windows")),
              h("td", {}, u.role === "admin" ? t("admin") : t("user")),
              h("td", {}, u.totp_enabled ? "✓" : ""),
              h("td", {}, state),
              h("td", {}, formatTime(u.last_login_at)),
              h(
                "td",
                { class: "actions" },
                btn(u.role === "admin" ? t("makeUser") : t("makeAdmin"), () =>
                  api("PATCH", `/api/v1/users/${u.id}`, { role: u.role === "admin" ? "user" : "admin" }),
                ),
                self ? null : btn(u.disabled ? t("enable") : t("disable"), () => api("PATCH", `/api/v1/users/${u.id}`, { disabled: !u.disabled })),
                u.locked_until > now ? btn(t("unlock"), () => api("POST", `/api/v1/users/${u.id}/unlock`, {})) : null,
                u.kind === "local"
                  ? btn(t("setPassword"), async () => {
                      const pw = prompt(`${t("newPassword")} (${u.username})\n${t("passwordRules")}`);
                      if (pw) await api("POST", `/api/v1/users/${u.id}/password`, { password: pw });
                    })
                  : null,
                btn(t("endSessions"), () => api("POST", `/api/v1/users/${u.id}/sessions/end`, {})),
                self
                  ? null
                  : btn(t("delete"), async () => {
                      if (confirm(`${t("delete")} ${u.username}?`)) await api("DELETE", `/api/v1/users/${u.id}`);
                    }),
              ),
            );
          }),
        ),
      ),
    );
  };

  const uname = input("username", "text", { required: true });
  const pw = input("password", "password", { required: true, autocomplete: "new-password", minlength: 12 });
  const role = h("select", { name: "role" }, h("option", { value: "user" }, t("user")), h("option", { value: "admin" }, t("admin"))) as HTMLSelectElement;
  const addMsg = h("div", {});
  const form = h(
    "form",
    {
      class: "card",
      onsubmit: (e: Event) => {
        e.preventDefault();
        void act(
          () => api("POST", "/api/v1/users", { username: uname.value, password: pw.value, role: role.value }),
          () => {
            uname.value = "";
            pw.value = "";
            clear(addMsg);
            void load();
          },
          addMsg,
        );
      },
    },
    h("h2", {}, t("addUser")),
    h("div", { class: "grid3" }, field(t("username"), uname), field(t("password"), pw, t("passwordRules")), field(t("role"), role)),
    addMsg,
    h("button", { type: "submit", class: "primary" }, t("create")),
  );
  void load().catch((e) => list.append(message("error", errText(e))));
  section.append(tableBox, form);
  return section;
}

export function librariesPage(_me: Me): HTMLElement {
  const section = h("section", {});
  const listBox = h("div", {});
  let users: User[] = [];

  const load = async () => {
    const [{ libraries, mode }, u] = await Promise.all([
      api<{ libraries: Library[]; mode: string }>("GET", "/api/v1/libraries"),
      api<{ users: User[] }>("GET", "/api/v1/users"),
    ]);
    users = u.users.filter((x) => x.role === "user");
    clear(listBox);
    if (libraries.length === 0) {
      listBox.append(
        message("info", mode === "docker" ? "Mount shared folders under /libraries in compose.yaml, then restart the container." : t("addLibrary")),
      );
    }
    for (const lib of libraries) listBox.append(libraryCard(lib));
  };

  function libraryCard(lib: Library): HTMLElement {
    const msg = h("div", {});
    const prefix = input("prefix", "text", { value: lib.display_prefix ?? "", placeholder: lib.path });
    const excludes = h("textarea", { rows: 3, class: "mono" }) as HTMLTextAreaElement;
    excludes.value = lib.excludes.join("\n");
    const allUsers = h("input", { type: "checkbox", checked: lib.access.includes("role:user") }) as HTMLInputElement;
    const userBoxes = users.map((u) => {
      const cb = h("input", { type: "checkbox", value: `user:${u.id}`, checked: lib.access.includes(`user:${u.id}`) }) as HTMLInputElement;
      return { cb, el: h("label", { class: "check" }, cb, u.username) };
    });
    const save = () =>
      act(
        async () => {
          await api("PATCH", `/api/v1/libraries/${lib.id}`, {
            display_prefix: prefix.value,
            excludes: excludes.value.split("\n").map((s) => s.trim()).filter(Boolean),
          });
          const principals = [...(allUsers.checked ? ["role:user"] : []), ...userBoxes.filter((b) => b.cb.checked).map((b) => b.cb.value)];
          await api("PUT", `/api/v1/libraries/${lib.id}/access`, { principals });
        },
        () => {
          toast(t("save"));
          void load();
        },
        msg,
      );
    const removeBtn = h(
      "button",
      {
        type: "button",
        class: "danger",
        onclick: () => {
          const name = prompt(t("typeNameToRemove"));
          if (name !== null) void act(() => api("DELETE", `/api/v1/libraries/${lib.id}`, { confirm_name: name }), () => void load(), msg);
        },
      },
      t("remove"),
    );
    return h(
      "div",
      { class: "card" },
      h("h2", {}, lib.name, h("span", { class: "tag" }, lib.source)),
      h("p", { class: "mono small" }, lib.path),
      field(t("displayPrefix"), prefix),
      field(t("excludes"), excludes),
      h(
        "fieldset",
        {},
        h("legend", {}, t("access")),
        h("label", { class: "check" }, allUsers, t("accessAllUsers")),
        ...userBoxes.map((b) => b.el),
        lib.access.length === 0 ? h("p", { class: "small muted" }, t("accessAdminsOnly")) : null,
      ),
      msg,
      h(
        "div",
        { class: "row" },
        h("button", { type: "button", class: "primary", onclick: () => void save() }, t("save")),
        h("button", { type: "button", onclick: () => act(() => api("POST", `/api/v1/libraries/${lib.id}/recheck`, {}), () => toast(t("recheck"))) }, t("recheck")),
        removeBtn,
      ),
    );
  }

  const name = input("name", "text", { required: true });
  const path = input("path", "text", { required: true, class: "mono" });
  const prefix = input("prefix", "text");
  const addMsg = h("div", {});
  const form = h(
    "form",
    {
      class: "card",
      onsubmit: (e: Event) => {
        e.preventDefault();
        void act(
          () => api("POST", "/api/v1/libraries", { name: name.value, path: path.value, display_prefix: prefix.value || null }),
          () => {
            name.value = path.value = prefix.value = "";
            clear(addMsg);
            void load();
          },
          addMsg,
        );
      },
    },
    h("h2", {}, t("addLibrary")),
    h("div", { class: "grid3" }, field(t("name"), name), field(t("path"), path), field(t("displayPrefix"), prefix)),
    addMsg,
    h("button", { type: "submit", class: "primary" }, t("create")),
  );
  void load().catch((e) => listBox.append(message("error", errText(e))));
  section.append(h("h1", {}, t("libraries")), listBox, form);
  return section;
}
