// Search as you type, with keyboard navigation and copy-path actions.

import { api, ApiError, Hit, Me } from "./api";
import { clear, copyText, formatSize, formatTime, h, message, toast } from "./dom";
import { t } from "./i18n";

interface SearchResponse {
  total: number;
  took_ms: number;
  hits: Hit[];
}

export function searchPage(me: Me): HTMLElement {
  const box = h("input", {
    type: "search",
    class: "searchbox",
    placeholder: t("searchPlaceholder"),
    "aria-label": t("search"),
    autocomplete: "off",
    spellcheck: "false",
    autofocus: true,
  }) as HTMLInputElement;
  const libSelect = h(
    "select",
    { "aria-label": t("library") },
    h("option", { value: "" }, t("allLibraries")),
    ...me.libraries.map((l) => h("option", { value: l.name }, l.name)),
  ) as HTMLSelectElement;
  const info = h("div", { class: "muted small", "aria-live": "polite" });
  const list = h("ol", { class: "results", role: "listbox", "aria-label": t("search") });
  let hits: Hit[] = [];
  let selected = 0;
  let controller: AbortController | null = null;
  let timer: number | undefined;

  const initial = new URLSearchParams(location.search).get("q") ?? "";
  box.value = initial;

  function render(r: SearchResponse | null): void {
    clear(list);
    if (!r) return;
    hits = r.hits;
    selected = 0;
    info.textContent =
      r.total > r.hits.length
        ? `${t("results", { n: r.total, ms: r.took_ms.toFixed(0) })}. ${t("moreResults", { shown: r.hits.length, n: r.total })}`
        : t("results", { n: r.total, ms: r.took_ms.toFixed(0) });
    if (r.hits.length === 0) {
      list.append(h("li", { class: "empty" }, t("noResults")));
      return;
    }
    r.hits.forEach((hit, i) => {
      const li = h(
        "li",
        {
          role: "option",
          id: `hit-${i}`,
          class: "hit",
          "aria-selected": i === 0 ? "true" : "false",
          onclick: () => select(i),
          ondblclick: () => void copy(hit.path),
        },
        h("span", { class: `icon ${hit.is_dir ? "dir" : "file"}`, "aria-hidden": "true" }),
        h(
          "div",
          { class: "hit-main" },
          h("div", { class: "hit-name" }, hit.name),
          h("div", { class: "hit-path mono", title: hit.path }, hit.folder),
        ),
        h(
          "div",
          { class: "hit-meta" },
          h("span", {}, hit.is_dir ? "" : formatSize(hit.size)),
          h("span", {}, formatTime(hit.mtime)),
          h("span", { class: "tag" }, hit.library),
        ),
        h(
          "div",
          { class: "hit-actions" },
          h("button", { type: "button", title: t("copyPath"), onclick: (e: Event) => (e.stopPropagation(), void copy(hit.path)) }, t("copyPath")),
          h("button", { type: "button", title: t("copyFolder"), onclick: (e: Event) => (e.stopPropagation(), void copy(hit.folder)) }, t("folder")),
        ),
      );
      list.append(li);
    });
  }

  function select(i: number): void {
    if (!hits.length) return;
    selected = Math.max(0, Math.min(hits.length - 1, i));
    list.querySelectorAll("li.hit").forEach((el, j) => el.setAttribute("aria-selected", j === selected ? "true" : "false"));
    const el = document.getElementById(`hit-${selected}`);
    el?.scrollIntoView({ block: "nearest" });
    box.setAttribute("aria-activedescendant", `hit-${selected}`);
  }

  async function copy(text: string): Promise<void> {
    toast((await copyText(text)) ? `${t("copied")}: ${text}` : t("error"));
  }

  async function run(): Promise<void> {
    controller?.abort();
    const q = box.value.trim();
    const url = new URL(location.href);
    if (q) url.searchParams.set("q", box.value);
    else url.searchParams.delete("q");
    history.replaceState({}, "", url);
    if (!q) {
      render(null);
      info.textContent = "";
      return;
    }
    controller = new AbortController();
    try {
      const r = await api<SearchResponse>("GET", `/api/v1/search?q=${encodeURIComponent(q)}&limit=100${libSelect.value ? `&lib=${encodeURIComponent(libSelect.value)}` : ""}`, undefined, controller.signal);
      render(r);
    } catch (e) {
      if ((e as Error).name === "AbortError") return;
      clear(list);
      info.textContent = "";
      list.append(h("li", { class: "empty" }, message("error", e instanceof ApiError ? e.message : t("error"))));
    }
  }

  box.addEventListener("input", () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => void run(), 60);
  });
  libSelect.addEventListener("change", () => void run());
  box.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      select(selected + 1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      select(selected - 1);
    } else if (e.key === "Enter" && hits[selected]) {
      e.preventDefault();
      void copy(e.shiftKey ? hits[selected].folder : hits[selected].path);
    } else if (e.key === "Escape") {
      box.value = "";
      void run();
    }
  });
  if (initial) void run();

  const body =
    me.libraries.length === 0
      ? message("info", t("noLibraries"))
      : h("div", {}, info, list);
  return h(
    "section",
    { class: "search" },
    h("div", { class: "searchbar" }, box, me.libraries.length > 1 ? libSelect : null),
    h("details", { class: "help small" }, h("summary", {}, t("searchTips")), h("p", {}, t("searchHelp")), h("p", { class: "muted" }, t("m1Note"))),
    body,
  );
}
