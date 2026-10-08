/* tor-osint — frontend local.
 *
 * Regla de seguridad: todo dato procedente de la API (y por tanto de páginas
 * remotas no confiables) se inserta con textContent a través de h(). Nunca se
 * usa innerHTML, insertAdjacentHTML ni document.write.
 */
"use strict";

const CSRF = document.querySelector('meta[name="csrf-token"]').content;
const IOC_TYPES = ["email", "domain", "url", "ipv4", "hash", "md5", "sha1", "sha256", "cve", "onion"];
const IOC_LABELS = {
  email: "Emails", domain: "Dominios", url: "URLs", ipv4: "IPv4", hash: "Hashes",
  md5: "MD5", sha1: "SHA-1", sha256: "SHA-256", cve: "CVE", onion: "Onion",
};
const PAGE_SIZE = 50;

/* ---------------------------------------------------------------- utilidades */

/** Crea un elemento. Los hijos de tipo string se añaden como nodos de texto. */
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key.startsWith("on") && typeof value === "function") {
      el.addEventListener(key.slice(2), value);
    } else if (key === "class") {
      el.className = value;
    } else if (key === "style") {
      el.style.cssText = value; // CSSOM: permitido por la CSP (setAttribute("style") no)
    } else if (value === true) {
      el.setAttribute(key, "");
    } else {
      el.setAttribute(key, String(value));
    }
  }
  appendAll(el, children);
  return el;
}

function appendAll(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

/** Enlace interno de la SPA (siempre un hash generado por nosotros). */
function link(route, ...children) {
  return h("a", { href: "#" + route }, ...children);
}

function code(text) {
  return h("code", {}, text ?? "");
}

function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString("es-ES");
}

function statusCell(status) {
  if (status === null || status === undefined) return h("span", { class: "muted" }, "—");
  return h("span", { class: "status-" + String(status)[0] }, String(status));
}

function table(headers, rows, emptyText = "Sin datos.") {
  if (!rows.length) return h("p", { class: "empty panel" }, emptyText);
  return h("div", { class: "table-wrap" },
    h("table", {},
      h("thead", {}, h("tr", {}, headers.map((hd) =>
        h("th", { class: [hd.num ? "num" : "", hd.cls || ""].join(" ").trim() || null, scope: "col" }, hd.label ?? hd)))),
      h("tbody", {}, rows)));
}

function toast(message, isError = false) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.className = isError ? "bad" : "";
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.hidden = true; }, isError ? 6000 : 3500);
}

function qs(params) {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") usp.set(k, v);
  const s = usp.toString();
  return s ? "?" + s : "";
}

/* ---------------------------------------------------------------------- API */

async function api(path, { method = "GET", body } = {}) {
  const opts = { method, headers: { Accept: "application/json" }, credentials: "same-origin" };
  if (method !== "GET") {
    opts.headers["Content-Type"] = "application/json";
    opts.headers["X-CSRF-Token"] = CSRF;
    opts.body = JSON.stringify(body ?? {});
  }
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch { /* respuesta vacía */ }
  if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
  return data;
}

/* ------------------------------------------------------------------- router */

const view = document.getElementById("view");

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "") || "panel";
  const [path, query = ""] = raw.split("?");
  const parts = path.split("/").map(decodeURIComponent);
  return { name: parts[0], arg: parts[1], params: new URLSearchParams(query) };
}

const routes = {
  panel: renderPanel,
  sources: renderSources,
  pages: renderPages,
  page: renderPage,
  search: renderSearch,
  iocs: renderIocs,
  related: renderRelated,
  duplicates: renderDuplicates,
  export: renderExport,
};

const navAlias = { page: "pages", related: "iocs" };

async function router() {
  const route = parseHash();
  const render = routes[route.name] || renderNotFound;
  const active = navAlias[route.name] || route.name;
  for (const a of document.querySelectorAll(".tabs a")) {
    if (a.dataset.route === active) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  view.replaceChildren(h("p", { class: "muted" }, "Cargando…"));
  try {
    const content = await render(route);
    view.replaceChildren();
    appendAll(view, [content]); // descarta null/false de secciones opcionales
  } catch (err) {
    view.replaceChildren(h("h1", {}, "Error"), h("p", { class: "error" }, err.message));
  }
  view.focus({ preventScroll: true });
}

window.addEventListener("hashchange", router);

/* -------------------------------------------------------------- estado Tor */

const torPill = document.getElementById("tor-pill");
const crawlPill = document.getElementById("crawl-pill");

async function torCheck(showIp = false) {
  torPill.className = "pill";
  torPill.textContent = "Tor: comprobando…";
  try {
    const r = await api("/api/tor-check", { method: "POST", body: { show_ip: showIp } });
    if (r.error) {
      torPill.className = "pill bad";
      torPill.textContent = "Tor: sin conexión";
      toast(`No se pudo contactar con Tor (${r.error}). ¿Está el servicio activo?`, true);
    } else {
      torPill.className = r.is_tor ? "pill ok" : "pill bad";
      torPill.textContent = r.is_tor ? "Tor: conectado" : "Tor: NO está pasando por Tor";
      if (r.ip) toast(`IP de salida de Tor: ${r.ip}`);
    }
    return r;
  } catch (err) {
    torPill.className = "pill bad";
    torPill.textContent = "Tor: error";
    toast(err.message, true);
    return null;
  }
}

/* ------------------------------------------------------------- crawl (job) */

let crawlTimer = null;
const crawlListeners = new Set();

function updateCrawlPill(job) {
  if (job.state === "running") {
    crawlPill.hidden = false;
    crawlPill.className = "pill warn";
    crawlPill.textContent = `Crawl ${job.current}/${job.total}`;
  } else if (job.state === "done" || job.state === "error") {
    crawlPill.hidden = false;
    crawlPill.className = job.state === "done" && !job.failed.length ? "pill ok" : "pill bad";
    crawlPill.textContent = job.state === "done"
      ? `Crawl: ${job.stored.length} ok · ${job.failed.length} fallo(s)`
      : "Crawl: error";
  } else {
    crawlPill.hidden = true;
  }
}

async function pollCrawl() {
  clearTimeout(crawlTimer);
  try {
    const job = await api("/api/crawl");
    updateCrawlPill(job);
    crawlListeners.forEach((fn) => fn(job));
    if (job.state === "running") crawlTimer = setTimeout(pollCrawl, 1500);
    return job;
  } catch {
    crawlTimer = setTimeout(pollCrawl, 5000);
    return null;
  }
}

async function startCrawl(urls = []) {
  try {
    const job = await api("/api/crawl", { method: "POST", body: { urls } });
    toast(`Crawl iniciado: ${job.total} fuente(s).`);
    updateCrawlPill(job);
    crawlListeners.forEach((fn) => fn(job));
    crawlTimer = setTimeout(pollCrawl, 800);
  } catch (err) {
    toast(err.message, true);
  }
}

function crawlPanel() {
  const box = h("div", { class: "panel" });
  const render = (job) => {
    const pct = job.total ? Math.round((job.current / job.total) * 100) : 0;
    const items = [h("h2", { style: "margin-top:0" }, "Estado del crawl")];
    if (job.state === "idle") {
      items.push(h("p", { class: "muted" }, "Todavía no se ha lanzado ningún crawl en esta sesión."));
    } else {
      items.push(
        h("p", {},
          h("span", { class: "tag" }, { running: "en curso", done: "terminado", error: "error" }[job.state]),
          " ", job.state === "running" ? `${job.current} de ${job.total}` : "",
          job.started_at ? h("span", { class: "muted" }, ` · inicio ${fmtDate(job.started_at)}`) : ""),
      );
      if (job.state === "running") {
        items.push(h("div", { class: "progress", role: "progressbar", "aria-valuenow": pct, "aria-valuemin": 0, "aria-valuemax": 100 },
          h("div", { style: `width:${pct}%` })));
        if (job.current_url) items.push(h("p", { class: "muted" }, "Consultando ", code(job.current_url)));
      }
      if (job.error) items.push(h("p", { class: "error" }, `Error: ${job.error}`));
      if (job.stored.length) {
        items.push(h("p", {}, h("strong", {}, `Guardadas (${job.stored.length})`)),
          h("ul", { class: "plain" }, job.stored.map((u) => h("li", {}, code(u)))));
      }
      if (job.failed.length) {
        items.push(h("p", {}, h("strong", {}, `Fallidas (${job.failed.length})`)),
          h("ul", { class: "plain" }, job.failed.map((f) => h("li", {}, code(f.url), h("br"), h("span", { class: "muted" }, f.reason)))));
      }
      if (job.skipped) items.push(h("p", { class: "notice" }, `${job.skipped} fuente(s) omitidas por el límite de URLs.`));
    }
    box.replaceChildren(...items);
  };
  crawlListeners.clear();
  crawlListeners.add(render);
  render({ state: "idle", failed: [], stored: [] });
  pollCrawl();
  return box;
}

/* -------------------------------------------------------------------- vistas */

async function renderPanel() {
  const s = await api("/api/summary");
  const card = (value, label, route) => {
    const inner = [h("div", { class: "value" }, String(value)), h("div", { class: "label" }, label)];
    return route ? h("a", { class: "card", href: "#" + route }, inner) : h("div", { class: "card" }, inner);
  };
  return [
    h("h1", {}, "Panel"),
    h("p", { class: "lead" }, "Resumen de la base de datos local. ", h("span", { class: "mono" }, s.database)),
    h("div", { class: "cards" },
      card(s.sources, "Fuentes configuradas", "/sources"),
      card(s.pages, "Páginas recopiladas", "/pages"),
      card(s.iocs_distinct, "IOCs distintos", "/iocs"),
      card(s.duplicates, "Grupos duplicados", "/duplicates")),
    s.rejected_sources
      ? h("p", { class: "notice", style: "margin-top:12px" },
        `${s.rejected_sources} línea(s) de sources.txt no son URLs .onion válidas. `, link("/sources", "Revisar"))
      : null,
    h("h2", {}, "Acciones"),
    h("div", { class: "row" },
      h("button", { type: "button", onclick: () => torCheck(false) }, "Comprobar Tor"),
      h("button", { type: "button", class: "secondary", onclick: () => { location.hash = "#/sources"; } }, "Ir a fuentes y crawl"),
      h("span", { class: "muted" }, `Proxy SOCKS: ${s.socks}`)),
    h("div", { class: "grid-2" },
      h("section", {},
        h("h2", {}, "IOCs por tipo"),
        table(
          ["Tipo", { label: "Distintos", num: true }, { label: "Apariciones", num: true }],
          s.ioc_types.map((t) => h("tr", { class: "clickable", onclick: () => { location.hash = "#/iocs?type=" + t.type; } },
            h("td", {}, link("/iocs?type=" + t.type, IOC_LABELS[t.type] || t.type)),
            h("td", { class: "num" }, String(t.distinct)),
            h("td", { class: "num" }, String(t.total)))),
          "Sin IOCs: lanza un crawl para empezar.")),
      h("section", {},
        h("h2", {}, "Códigos HTTP"),
        table(
          ["Código", { label: "Páginas", num: true }],
          s.status_counts.map((c) => h("tr", {}, h("td", {}, statusCell(c.status)), h("td", { class: "num" }, String(c.pages)))),
          "Sin páginas todavía."))),
  ];
}

async function renderSources() {
  const data = await api("/api/sources");
  const selected = new Set();

  const addForm = h("form", { class: "inline" },
    h("input", { type: "text", name: "url", required: true, placeholder: "http://<56 caracteres>.onion/", "aria-label": "URL .onion", autocomplete: "off", spellcheck: "false" }),
    h("button", { type: "submit" }, "Añadir fuente"));
  addForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    await addSource(addForm.url.value);
  });

  const crawlSelectedBtn = h("button", { type: "button", class: "secondary", disabled: true, onclick: () => startCrawl([...selected]) }, "Crawl de seleccionadas");
  const refreshSelected = () => {
    crawlSelectedBtn.disabled = selected.size === 0;
    crawlSelectedBtn.textContent = selected.size ? `Crawl de seleccionadas (${selected.size})` : "Crawl de seleccionadas";
  };

  const validRows = data.valid.map((url) => h("tr", {},
    h("td", {}, h("input", {
      type: "checkbox", "aria-label": "Seleccionar " + url,
      onchange: (ev) => { ev.target.checked ? selected.add(url) : selected.delete(url); refreshSelected(); },
    })),
    h("td", {}, code(url))));

  return [
    h("h1", {}, "Fuentes y crawl"),
    h("p", { class: "lead" },
      "Solo se consultan las fuentes de ", code(data.file),
      ". Cada fuente recibe una única petición: no se siguen enlaces."),
    h("div", { class: "panel" },
      h("h2", { style: "margin-top:0" }, "Añadir fuente"),
      addForm,
      h("p", { class: "muted" }, "Se valida el esquema, el dominio .onion y el checksum v3 antes de añadirla.")),
    h("h2", {}, `Fuentes válidas (${data.valid.length})`),
    table(["", "URL"], validRows, "No hay fuentes: añade una arriba."),
    h("div", { class: "row", style: "margin-top:12px" },
      h("button", { type: "button", disabled: !data.valid.length, onclick: () => startCrawl([]) }, "Crawl de todas las fuentes"),
      crawlSelectedBtn,
      h("button", { type: "button", class: "secondary", onclick: () => torCheck(false) }, "Comprobar Tor")),
    h("div", { style: "margin-top:16px" }, crawlPanel()),
    data.rejected.length
      ? [h("h2", {}, `Líneas rechazadas (${data.rejected.length})`),
        table(["Línea", "Contenido"], data.rejected.map((r) => h("tr", {}, h("td", { class: "num" }, String(r.line)), h("td", {}, code(r.value)))))]
      : null,
    h("h2", {}, `Onion descubiertas (${data.discovered.length})`),
    h("p", { class: "muted" }, "Enlaces .onion vistos en las páginas que no están en tus fuentes. Nunca se visitan automáticamente: decide tú si añadirlos."),
    table(
      ["URL", { label: "Páginas", num: true }, ""],
      data.discovered.map((d) => h("tr", {},
        h("td", {}, code(d.value)),
        h("td", { class: "num" }, String(d.pages)),
        h("td", {}, h("button", { type: "button", class: "small secondary", onclick: () => addSource(d.value) }, "Añadir")))),
      "Ninguna por ahora."),
  ];
}

async function addSource(url) {
  try {
    const r = await api("/api/sources", { method: "POST", body: { url } });
    toast(`Fuente añadida: ${r.added}`);
    router();
  } catch (err) {
    toast(err.message, true);
  }
}

async function renderPages(route) {
  const offset = Math.max(0, parseInt(route.params.get("offset") || "0", 10) || 0);
  const data = await api("/api/pages" + qs({ limit: PAGE_SIZE, offset }));
  const rows = data.items.map((p) => h("tr", { class: "clickable", onclick: () => { location.hash = "#/page/" + p.id; } },
    h("td", { class: "num" }, String(p.id)),
    h("td", {}, link("/page/" + p.id, p.title || "(sin título)")),
    h("td", {}, code(p.url)),
    h("td", {}, statusCell(p.status)),
    h("td", { class: "hide-sm" }, fmtDate(p.fetched_at)),
    h("td", { class: "num" }, String(p.ioc_count))));
  const last = Math.min(offset + PAGE_SIZE, data.total);
  return [
    h("h1", {}, "Páginas"),
    h("p", { class: "lead" }, `${data.total} página(s) almacenadas. El texto ya está redactado: no contiene credenciales.`),
    table(["ID", "Título", "URL", "HTTP", { label: "Fecha", cls: "hide-sm" }, { label: "IOCs", num: true }], rows, "No hay páginas: lanza un crawl desde Fuentes."),
    data.total > PAGE_SIZE
      ? h("div", { class: "pager" },
        h("span", { class: "muted" }, `${offset + 1}–${last} de ${data.total}`),
        h("button", { type: "button", class: "small secondary", disabled: offset === 0, onclick: () => { location.hash = "#/pages?offset=" + Math.max(0, offset - PAGE_SIZE); } }, "Anterior"),
        h("button", { type: "button", class: "small secondary", disabled: last >= data.total, onclick: () => { location.hash = "#/pages?offset=" + (offset + PAGE_SIZE); } }, "Siguiente"))
      : null,
  ];
}

function iocChips(iocs) {
  if (!iocs.length) return h("p", { class: "muted" }, "Sin IOCs.");
  const groups = {};
  for (const i of iocs) (groups[i.type] ||= []).push(i);
  return Object.entries(groups).map(([type, list]) => h("div", { style: "margin-bottom:12px" },
    h("p", { style: "margin:0 0 6px" }, h("span", { class: "tag" }, IOC_LABELS[type] || type), " ", h("span", { class: "muted" }, String(list.length))),
    h("div", { class: "chips" }, list.map((i) =>
      h("button", { type: "button", class: "chip", title: "Ver páginas relacionadas", onclick: () => { location.hash = "#/related" + qs({ value: i.normalized_value }); } }, i.normalized_value)))));
}

async function renderPage(route) {
  const p = await api("/api/pages/" + encodeURIComponent(route.arg || ""));
  return [
    h("p", {}, link("/pages", "← Páginas")),
    h("h1", {}, p.title || "(sin título)"),
    h("div", { class: "panel" },
      h("dl", { class: "meta" },
        h("dt", {}, "URL"), h("dd", {}, code(p.url)),
        h("dt", {}, "Fuente"), h("dd", {}, code(p.source)),
        h("dt", {}, "HTTP"), h("dd", {}, statusCell(p.status)),
        h("dt", {}, "Recopilada"), h("dd", {}, fmtDate(p.fetched_at)),
        h("dt", {}, "SHA-256"), h("dd", {}, code(p.content_hash)))),
    h("div", { class: "grid-2" },
      h("section", {}, h("h2", {}, `IOCs (${p.iocs.length})`), h("div", { class: "panel" }, iocChips(p.iocs))),
      h("section", {}, h("h2", {}, `Enlaces (${p.links.length})`),
        h("div", { class: "panel" }, p.links.length
          ? h("ul", { class: "plain", style: "max-height:360px;overflow:auto" }, p.links.map((l) => h("li", {}, code(l))))
          : h("p", { class: "muted" }, "Sin enlaces."),
        h("p", { class: "muted", style: "margin-bottom:0" }, "Se muestran como texto: no son clicables a propósito.")))),
    h("h2", {}, "Texto"),
    p.text_truncated ? h("p", { class: "notice" }, "Texto truncado a los primeros 100 000 caracteres.") : null,
    h("pre", { class: "text" }, p.text || "(vacío)"),
  ];
}

async function renderSearch(route) {
  const mode = route.params.get("mode") === "regex" ? "regex" : "text";
  const q = route.params.get("q") || "";

  const input = h("input", { type: "search", name: "q", value: q, required: true, "aria-label": "Término de búsqueda",
    placeholder: mode === "regex" ? "CVE-202[0-9]-[0-9]+" : "empresa, alias, producto…", spellcheck: "false" });
  const form = h("form", { class: "inline" }, input, h("button", { type: "submit" }, "Buscar"));
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    location.hash = "#/search" + qs({ q: input.value, mode: mode === "regex" ? "regex" : "" });
  });
  const modeBtn = (value, label) => h("button", {
    type: "button", "aria-pressed": String(mode === value),
    onclick: () => { location.hash = "#/search" + qs({ q: input.value, mode: value === "regex" ? "regex" : "" }); },
  }, label);

  const out = [
    h("h1", {}, "Buscar"),
    h("p", { class: "lead" }, "Búsqueda sobre el contenido local (título y texto). La regex nunca se ejecuta contra datos remotos."),
    h("div", { class: "panel" },
      h("div", { class: "row", style: "margin-bottom:10px" },
        h("div", { class: "segmented", role: "group", "aria-label": "Modo de búsqueda" }, modeBtn("text", "Texto"), modeBtn("regex", "Regex"))),
      form),
  ];
  if (!q) return out;

  if (mode === "text") {
    const r = await api("/api/search" + qs({ q }));
    out.push(h("h2", {}, `${r.items.length} resultado(s)`),
      table(["ID", "Título", "URL", "HTTP", { label: "Fecha", cls: "hide-sm" }], r.items.map((p) => h("tr", { class: "clickable", onclick: () => { location.hash = "#/page/" + p.id; } },
        h("td", { class: "num" }, String(p.id)),
        h("td", {}, link("/page/" + p.id, p.title || "(sin título)")),
        h("td", {}, code(p.url)),
        h("td", {}, statusCell(p.status)),
        h("td", { class: "hide-sm" }, fmtDate(p.fetched_at)))), "Sin resultados."));
  } else {
    const r = await api("/api/regex" + qs({ pattern: q }));
    out.push(h("h2", {}, `${r.items.length} página(s) con coincidencias`),
      r.items.length
        ? r.items.map((hit) => h("div", { class: "panel" },
          h("p", { style: "margin-top:0" }, link("/page/" + hit.page_id, `[${hit.page_id}] ${hit.title || "(sin título)"}`), h("br"), code(hit.url)),
          h("div", { class: "chips" }, hit.matches.map((m) => h("span", { class: "chip" }, m)))))
        : h("p", { class: "empty panel" }, "Sin coincidencias."));
  }
  return out;
}

async function renderIocs(route) {
  const type = route.params.get("type") || "";
  const data = await api("/api/iocs" + qs({ type, limit: 500 }));

  const select = h("select", { "aria-label": "Tipo de IOC", onchange: (ev) => { location.hash = "#/iocs" + qs({ type: ev.target.value }); } },
    h("option", { value: "" }, "Todos los tipos"),
    IOC_TYPES.map((t) => h("option", { value: t, selected: t === type }, IOC_LABELS[t])));

  const relatedInput = h("input", { type: "search", required: true, placeholder: "example.com, CVE-2024-1234, 8.8.8.8…", "aria-label": "Valor de IOC", spellcheck: "false" });
  const relatedForm = h("form", { class: "inline" }, relatedInput, h("button", { type: "submit" }, "Buscar relaciones"));
  relatedForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    location.hash = "#/related" + qs({ value: relatedInput.value });
  });

  return [
    h("h1", {}, "IOCs"),
    h("p", { class: "lead" }, "Indicadores extraídos y normalizados. Pulsa un valor para ver en qué páginas aparece."),
    h("div", { class: "cards", style: "margin-bottom:16px" }, data.types.map((t) =>
      h("a", { class: "card", href: "#/iocs?type=" + t.type },
        h("div", { class: "value" }, String(t.distinct)), h("div", { class: "label" }, IOC_LABELS[t.type] || t.type)))),
    h("div", { class: "grid-2" },
      h("div", { class: "panel" }, h("h2", { style: "margin-top:0" }, "Filtrar"), select),
      h("div", { class: "panel" }, h("h2", { style: "margin-top:0" }, "Correlación"), relatedForm)),
    h("h2", {}, `${data.items.length} valor(es)${type ? " · " + (IOC_LABELS[type] || type) : ""}`),
    table(
      ["Valor", "Tipo", { label: "Páginas", num: true }, { label: "Primera vez", cls: "hide-sm" }, { label: "Última vez", cls: "hide-sm" }],
      data.items.map((i) => h("tr", { class: "clickable", onclick: () => { location.hash = "#/related" + qs({ value: i.value }); } },
        h("td", {}, code(i.value)),
        h("td", {}, h("span", { class: "tag" }, i.type)),
        h("td", { class: "num" }, String(i.pages)),
        h("td", { class: "hide-sm" }, fmtDate(i.first_seen)),
        h("td", { class: "hide-sm" }, fmtDate(i.last_seen)))),
      "Sin IOCs de este tipo."),
  ];
}

async function renderRelated(route) {
  const value = route.params.get("value") || "";
  if (!value) { location.hash = "#/iocs"; return []; }
  const data = await api("/api/related" + qs({ value }));
  const pages = new Set(data.items.map((r) => r.page_id));
  return [
    h("p", {}, link("/iocs", "← IOCs")),
    h("h1", {}, "Relaciones de ", code(value)),
    h("p", { class: "lead" }, `Aparece en ${pages.size} página(s) de la base de datos local. No se hace correlación externa.`),
    table(
      ["Página", "URL", "Tipo", "HTTP", { label: "Visto", cls: "hide-sm" }],
      data.items.map((r) => h("tr", { class: "clickable", onclick: () => { location.hash = "#/page/" + r.page_id; } },
        h("td", {}, link("/page/" + r.page_id, `[${r.page_id}] ${r.title || "(sin título)"}`)),
        h("td", {}, code(r.url)),
        h("td", {}, h("span", { class: "tag" }, r.type)),
        h("td", {}, statusCell(r.status)),
        h("td", { class: "hide-sm" }, `${fmtDate(r.first_seen)} → ${fmtDate(r.last_seen)}`))),
      "Sin coincidencias en la base de datos local."),
  ];
}

async function renderDuplicates() {
  const data = await api("/api/duplicates");
  return [
    h("h1", {}, "Contenido duplicado"),
    h("p", { class: "lead" }, "URLs distintas con exactamente el mismo texto normalizado (mismo SHA-256): mirrors, clones o páginas de error comunes."),
    data.items.length
      ? data.items.map((g) => h("div", { class: "panel" },
        h("p", { style: "margin-top:0" }, h("span", { class: "tag" }, `${g.urls.length} URLs`), " ", code(g.content_hash)),
        h("ul", { class: "plain" }, g.urls.map((u, i) => h("li", {}, code(u), g.titles[i] ? h("span", { class: "muted" }, " · " + g.titles[i]) : null)))))
      : h("p", { class: "empty panel" }, "No hay contenido duplicado."),
  ];
}

async function renderExport() {
  const reportLink = h("a", { class: "button secondary", href: "/report", target: "_blank", rel: "noopener noreferrer", hidden: true }, "Abrir informe");
  const reportStatus = h("p", { class: "muted" }, "El informe se guarda en results/report.html.");
  const generate = async (btn) => {
    btn.disabled = true;
    try {
      const r = await api("/api/report", { method: "POST" });
      reportStatus.textContent = `Informe generado: ${r.path}`;
      reportLink.hidden = false;
      toast("Informe generado.");
    } catch (err) {
      toast(err.message, true);
    } finally {
      btn.disabled = false;
    }
  };
  const dl = (href, label) => h("a", { class: "button secondary", href, download: "" }, label);
  return [
    h("h1", {}, "Exportar e informe"),
    h("p", { class: "lead" }, "Los ficheros se generan en la carpeta results/ y se descargan desde aquí."),
    h("div", { class: "grid-2" },
      h("div", { class: "panel" },
        h("h2", { style: "margin-top:0" }, "Informe HTML"),
        h("p", {}, "Fecha, fuentes, páginas, códigos HTTP, duplicados, IOCs y relación IOC ↔ páginas. Autocontenido y sin scripts."),
        h("div", { class: "row" }, h("button", { type: "button", onclick: (ev) => generate(ev.currentTarget) }, "Generar informe"), reportLink),
        reportStatus),
      h("div", { class: "panel" },
        h("h2", { style: "margin-top:0" }, "Exportar datos"),
        h("p", {}, "JSON con páginas e IOCs, o CSV (protegido frente a inyección de fórmulas)."),
        h("div", { class: "row" },
          dl("/api/export?format=json", "JSON"),
          dl("/api/export?format=csv&table=pages", "CSV páginas"),
          dl("/api/export?format=csv&table=iocs", "CSV IOCs")))),
  ];
}

function renderNotFound() {
  return [h("h1", {}, "No encontrado"), h("p", {}, link("/panel", "Volver al panel"))];
}

/* -------------------------------------------------------------------- inicio */

router();
pollCrawl();
