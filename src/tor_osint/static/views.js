/* Vistas principales: panel, fuentes, páginas, búsqueda, IOCs, relaciones,
 * duplicados y exportación. */

import {
  IOC_LABELS, IOC_TYPES, PAGE_SIZE, annotationsPanel, api, code, fmtDate, go, h, highlighted,
  link, post, qs, rerender, severityBadge, statusCell, table, toast,
} from "./core.js";
import { crawlPanel, setAlertCount, startCrawl, torCheck } from "./status.js";

function card(value, label, route, tone) {
  const inner = [h("div", { class: "value" }, String(value)), h("div", { class: "label" }, label)];
  const cls = "card" + (tone ? " " + tone : "");
  return route ? h("a", { class: cls, href: "#" + route }, inner) : h("div", { class: cls }, inner);
}

function kindsChips(kinds) {
  return h("span", { class: "chips inline-chips" }, kinds.map((k) => h("span", { class: "tag" }, k)));
}

/* ------------------------------------------------------------------- panel */

export async function renderPanel() {
  const s = await api("/api/summary");
  setAlertCount(s.open_alerts);
  return [
    h("h1", {}, "Panel"),
    h("p", { class: "lead" }, "Resumen de la base de datos local. ", h("span", { class: "mono" }, s.database)),
    h("div", { class: "cards" },
      card(s.sources, "Fuentes configuradas", "/sources"),
      card(s.pages, "Páginas recopiladas", "/pages"),
      card(s.iocs_distinct, "IOCs distintos", "/iocs"),
      card(s.open_alerts, "Alertas pendientes", "/watch", s.open_alerts ? "card-alert" : ""),
      card(s.recent_changes.length, "Páginas con cambios", "/changes", s.recent_changes.length ? "card-warn" : ""),
      card(s.duplicates, "Grupos duplicados", "/duplicates")),
    s.rejected_sources
      ? h("p", { class: "notice", style: "margin-top:12px" },
        `${s.rejected_sources} línea(s) de sources.txt no son URLs .onion válidas. `, link("/sources", "Revisar"))
      : null,
    h("h2", {}, "Acciones"),
    h("div", { class: "row" },
      h("button", { type: "button", onclick: () => torCheck(false) }, "Comprobar Tor"),
      h("button", { type: "button", class: "secondary", onclick: () => go("/sources") }, "Ir a fuentes y crawl"),
      h("span", { class: "muted" }, `Proxy SOCKS: ${s.socks}`)),
    s.recent_changes.length
      ? [h("h2", {}, "Cambios recientes"),
        table(["Página", "Cambios", { label: "Fecha", cls: "hide-sm" }],
          s.recent_changes.map((c) => h("tr", { class: "clickable", onclick: () => go(`/diff?page=${c.page_id}`) },
            h("td", {}, link(`/diff?page=${c.page_id}`, `[${c.page_id}] ${c.title || "(sin título)"}`)),
            h("td", {}, kindsChips(c.kinds)),
            h("td", { class: "hide-sm" }, fmtDate(c.fetched_at)))))]
      : null,
    h("div", { class: "grid-2" },
      h("section", {},
        h("h2", {}, "IOCs por tipo"),
        table(
          ["Tipo", { label: "Distintos", num: true }, { label: "Apariciones", num: true }],
          s.ioc_types.map((t) => h("tr", { class: "clickable", onclick: () => go("/iocs?type=" + t.type) },
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

/* ----------------------------------------------------------------- fuentes */

async function addSource(url) {
  if (await post("/api/sources", { url }, (r) => `Fuente añadida: ${r.added}`)) rerender();
}

export async function renderSources() {
  const data = await api("/api/sources");
  const selected = new Set();

  const addForm = h("form", { class: "inline" },
    h("input", { type: "text", name: "url", required: true, placeholder: "http://<56 caracteres>.onion/", "aria-label": "URL .onion", autocomplete: "off", spellcheck: "false" }),
    h("button", { type: "submit" }, "Añadir fuente"));
  addForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    addSource(addForm.url.value);
  });

  const crawlSelectedBtn = h("button", { type: "button", class: "secondary", disabled: true, onclick: () => startCrawl([...selected]) }, "Crawl de seleccionadas");
  const refreshSelected = () => {
    crawlSelectedBtn.disabled = selected.size === 0;
    crawlSelectedBtn.textContent = selected.size ? `Crawl de seleccionadas (${selected.size})` : "Crawl de seleccionadas";
  };

  const validRows = data.valid.map((url) => h("tr", {},
    h("td", {}, h("input", {
      type: "checkbox", "aria-label": "Seleccionar " + url,
      onchange: (ev) => { if (ev.target.checked) selected.add(url); else selected.delete(url); refreshSelected(); },
    })),
    h("td", {}, code(url))));

  return [
    h("h1", {}, "Fuentes y crawl"),
    h("p", { class: "lead" },
      "Solo se consultan las fuentes de ", code(data.file),
      ". Cada fuente recibe una única petición: no se siguen enlaces."),
    h("div", { class: "panel" },
      h("h2", { class: "flush" }, "Añadir fuente"),
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

/* ------------------------------------------------------------------ páginas */

export async function renderPages(route) {
  const offset = Math.max(0, parseInt(route.params.get("offset") || "0", 10) || 0);
  const data = await api("/api/pages" + qs({ limit: PAGE_SIZE, offset }));
  const rows = data.items.map((p) => h("tr", { class: "clickable", onclick: () => go("/page/" + p.id) },
    h("td", { class: "num" }, String(p.id)),
    h("td", {}, link("/page/" + p.id, p.title || "(sin título)")),
    h("td", {}, code(p.url)),
    h("td", {}, statusCell(p.status)),
    h("td", { class: "hide-sm" }, fmtDate(p.fetched_at)),
    h("td", { class: "num hide-sm" }, String(p.snapshot_count)),
    h("td", { class: "num" }, String(p.ioc_count))));
  const last = Math.min(offset + PAGE_SIZE, data.total);
  return [
    h("h1", {}, "Páginas"),
    h("p", { class: "lead" }, `${data.total} página(s) almacenadas. El texto ya está redactado: no contiene credenciales.`),
    table(["ID", "Título", "URL", "HTTP", { label: "Fecha", cls: "hide-sm" }, { label: "Versiones", num: true, cls: "hide-sm" }, { label: "IOCs", num: true }],
      rows, "No hay páginas: lanza un crawl desde Fuentes."),
    data.total > PAGE_SIZE
      ? h("div", { class: "pager" },
        h("span", { class: "muted" }, `${offset + 1}–${last} de ${data.total}`),
        h("button", { type: "button", class: "small secondary", disabled: offset === 0, onclick: () => go("/pages?offset=" + Math.max(0, offset - PAGE_SIZE)) }, "Anterior"),
        h("button", { type: "button", class: "small secondary", disabled: last >= data.total, onclick: () => go("/pages?offset=" + (offset + PAGE_SIZE)) }, "Siguiente"))
      : null,
  ];
}

function iocChips(iocs) {
  if (!iocs.length) return h("p", { class: "muted" }, "Sin IOCs.");
  const groups = {};
  for (const i of iocs) (groups[i.type] ||= []).push(i);
  return Object.entries(groups).map(([type, list]) => h("div", { class: "chip-group" },
    h("p", { class: "chip-title" }, h("span", { class: "tag" }, IOC_LABELS[type] || type), " ", h("span", { class: "muted" }, String(list.length))),
    h("div", { class: "chips" }, list.map((i) =>
      h("button", { type: "button", class: "chip", title: "Ver páginas relacionadas", onclick: () => go("/related" + qs({ value: i.normalized_value })) }, i.normalized_value)))));
}

export async function renderPage(route) {
  const id = encodeURIComponent(route.arg || "");
  const [p, hist] = await Promise.all([api("/api/pages/" + id), api(`/api/pages/${id}/history`)]);
  const snapshots = hist.items;
  return [
    h("p", {}, link("/pages", "← Páginas")),
    h("h1", {}, p.title || "(sin título)"),
    p.tags.length ? h("div", { class: "chips", style: "margin-bottom:12px" }, p.tags.map((t) => h("span", { class: "chip tagchip" }, t))) : null,
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
          ? h("ul", { class: "plain scroll" }, p.links.map((l) => h("li", {}, code(l))))
          : h("p", { class: "muted" }, "Sin enlaces."),
        h("p", { class: "muted flush-bottom" }, "Se muestran como texto: no son clicables a propósito.")))),
    h("h2", {}, `Historial (${snapshots.length} versión/es)`),
    table(
      ["Snapshot", "Fecha", "HTTP", { label: "SHA-256", cls: "hide-sm" }, { label: "IOCs", num: true }, ""],
      snapshots.map((s, i) => {
        const older = snapshots[i + 1];
        const changed = older && older.content_hash !== s.content_hash;
        return h("tr", {},
          h("td", { class: "num" }, String(s.id), s.raw_sha256 ? h("span", { class: "tag", title: "HTML original guardado" }, "raw") : null),
          h("td", {}, fmtDate(s.fetched_at)),
          h("td", {}, statusCell(s.status)),
          h("td", { class: "hide-sm" }, code(s.content_hash.slice(0, 16) + "…")),
          h("td", { class: "num" }, String(s.ioc_count)),
          h("td", {}, older
            ? link(`/diff?page=${p.id}&from=${older.id}&to=${s.id}`, changed ? "Ver cambios" : "Comparar")
            : h("span", { class: "muted" }, "primera")));
      })),
    h("h2", {}, "Notas y etiquetas"),
    annotationsPanel("page", String(p.id), p.notes, p.tags),
    h("h2", {}, "Texto"),
    p.text_truncated ? h("p", { class: "notice" }, "Texto truncado a los primeros 100 000 caracteres.") : null,
    h("pre", { class: "text" }, p.text || "(vacío)"),
  ];
}

/* ------------------------------------------------------------------ búsqueda */

const SEARCH_MODES = { fts: "Texto completo", substring: "Literal", regex: "Regex" };

export async function renderSearch(route) {
  const mode = SEARCH_MODES[route.params.get("mode")] ? route.params.get("mode") : "fts";
  const q = route.params.get("q") || "";
  const placeholders = { fts: "empresa acme (prefijos, sin tildes)", substring: "texto exacto, 100%…", regex: "CVE-202[0-9]-[0-9]+" };

  const input = h("input", { type: "search", name: "q", value: q, required: true, "aria-label": "Término de búsqueda", placeholder: placeholders[mode], spellcheck: "false" });
  const form = h("form", { class: "inline" }, input, h("button", { type: "submit" }, "Buscar"));
  const target = (m) => "/search" + qs({ q: input.value, mode: m === "fts" ? "" : m });
  form.addEventListener("submit", (ev) => { ev.preventDefault(); go(target(mode)); });

  const out = [
    h("h1", {}, "Buscar"),
    h("p", { class: "lead" }, "Búsqueda sobre el contenido local. La regex nunca se ejecuta contra datos remotos."),
    h("div", { class: "panel" },
      h("div", { class: "row", style: "margin-bottom:10px" },
        h("div", { class: "segmented", role: "group", "aria-label": "Modo de búsqueda" },
          Object.entries(SEARCH_MODES).map(([m, label]) =>
            h("button", { type: "button", "aria-pressed": String(mode === m), onclick: () => go(target(m)) }, label)))),
      form),
  ];
  if (!q) return out;

  if (mode === "regex") {
    const r = await api("/api/regex" + qs({ pattern: q }));
    out.push(h("h2", {}, `${r.items.length} página(s) con coincidencias`),
      r.items.length
        ? r.items.map((hit) => h("div", { class: "panel" },
          h("p", { class: "flush" }, link("/page/" + hit.page_id, `[${hit.page_id}] ${hit.title || "(sin título)"}`), h("br"), code(hit.url)),
          h("div", { class: "chips" }, hit.matches.map((m) => h("span", { class: "chip" }, m)))))
        : h("p", { class: "empty panel" }, "Sin coincidencias."));
    return out;
  }
  const r = await api("/api/search" + qs({ q, mode: mode === "substring" ? "substring" : "" }));
  out.push(h("h2", {}, `${r.items.length} resultado(s)`),
    r.items.length
      ? r.items.map((p) => h("div", { class: "panel result" },
        h("p", { class: "flush" }, link("/page/" + p.id, `[${p.id}] ${p.title || "(sin título)"}`), " ", statusCell(p.status)),
        h("p", { class: "muted small" }, code(p.url), " · ", fmtDate(p.fetched_at)),
        p.snippet ? h("p", { class: "snippet" }, "… ", highlighted(p.snippet), " …") : null))
      : h("p", { class: "empty panel" }, "Sin resultados."));
  return out;
}

/* --------------------------------------------------------------------- IOCs */

export async function renderIocs(route) {
  const type = route.params.get("type") || "";
  const data = await api("/api/iocs" + qs({ type, limit: 500 }));
  const showCvss = type === "cve" || data.items.some((i) => i.cvss);

  const select = h("select", { "aria-label": "Tipo de IOC", onchange: (ev) => go("/iocs" + qs({ type: ev.target.value })) },
    h("option", { value: "" }, "Todos los tipos"),
    IOC_TYPES.map((t) => h("option", { value: t, selected: t === type }, IOC_LABELS[t])));

  const relatedInput = h("input", { type: "search", required: true, placeholder: "example.com, CVE-2024-1234, 8.8.8.8…", "aria-label": "Valor de IOC", spellcheck: "false" });
  const relatedForm = h("form", { class: "inline" }, relatedInput, h("button", { type: "submit" }, "Buscar relaciones"));
  relatedForm.addEventListener("submit", (ev) => { ev.preventDefault(); go("/related" + qs({ value: relatedInput.value })); });

  const headers = ["Valor", "Tipo"];
  if (showCvss) headers.push("CVSS");
  headers.push({ label: "Páginas", num: true }, { label: "Primera vez", cls: "hide-sm" }, { label: "Última vez", cls: "hide-sm" });

  return [
    h("h1", {}, "IOCs"),
    h("p", { class: "lead" }, "Indicadores extraídos y normalizados. Pulsa un valor para ver en qué páginas aparece."),
    h("div", { class: "cards", style: "margin-bottom:16px" }, data.types.map((t) =>
      card(t.distinct, IOC_LABELS[t.type] || t.type, "/iocs?type=" + t.type))),
    h("div", { class: "grid-2" },
      h("div", { class: "panel" }, h("h2", { class: "flush" }, "Filtrar"), select),
      h("div", { class: "panel" }, h("h2", { class: "flush" }, "Correlación"), relatedForm)),
    h("h2", {}, `${data.items.length} valor(es)${type ? " · " + (IOC_LABELS[type] || type) : ""}`),
    showCvss && !data.items.some((i) => i.cvss)
      ? h("p", { class: "muted" }, "Sin datos CVSS: importa un JSON de NVD con ", code("tor-osint nvd-import fichero.json"), ".")
      : null,
    table(headers,
      data.items.map((i) => h("tr", { class: "clickable", onclick: () => go("/related" + qs({ value: i.value })) },
        h("td", {}, code(i.value)),
        h("td", {}, h("span", { class: "tag" }, i.type)),
        showCvss ? h("td", {}, severityBadge(i.cvss)) : null,
        h("td", { class: "num" }, String(i.pages)),
        h("td", { class: "hide-sm" }, fmtDate(i.first_seen)),
        h("td", { class: "hide-sm" }, fmtDate(i.last_seen)))),
      "Sin IOCs de este tipo."),
  ];
}

export async function renderRelated(route) {
  const value = route.params.get("value") || "";
  if (!value) { go("/iocs"); return []; }
  const data = await api("/api/related" + qs({ value }));
  const pages = new Set(data.items.map((r) => r.page_id));
  return [
    h("p", {}, link("/iocs", "← IOCs")),
    h("h1", {}, "Relaciones de ", code(data.normalized)),
    h("p", { class: "lead" },
      data.type ? h("span", { class: "tag" }, IOC_LABELS[data.type] || data.type) : null, " ",
      `Aparece en ${pages.size} página(s) de la base de datos local. No se hace correlación externa.`),
    data.cvss
      ? h("div", { class: "panel" },
        h("p", { class: "flush" }, h("strong", {}, "CVSS (NVD): "), severityBadge(data.cvss),
          data.cvss.cvss_version ? h("span", { class: "muted" }, ` · v${data.cvss.cvss_version}`) : null),
        data.cvss.description ? h("p", { class: "flush-bottom" }, data.cvss.description) : null)
      : null,
    table(
      ["Página", "URL", "Tipo", "HTTP", { label: "Visto", cls: "hide-sm" }],
      data.items.map((r) => h("tr", { class: "clickable", onclick: () => go("/page/" + r.page_id) },
        h("td", {}, link("/page/" + r.page_id, `[${r.page_id}] ${r.title || "(sin título)"}`)),
        h("td", {}, code(r.url)),
        h("td", {}, h("span", { class: "tag" }, r.type)),
        h("td", {}, statusCell(r.status)),
        h("td", { class: "hide-sm" }, `${fmtDate(r.first_seen)} → ${fmtDate(r.last_seen)}`))),
      "Sin coincidencias en la base de datos local."),
    h("h2", {}, "Notas y etiquetas"),
    annotationsPanel("ioc", data.normalized, data.notes, data.tags),
  ];
}

/* --------------------------------------------------------------- duplicados */

export async function renderDuplicates(route) {
  const near = route.params.get("mode") === "near";
  const toggle = h("div", { class: "segmented", role: "group", "aria-label": "Tipo de duplicado" },
    h("button", { type: "button", "aria-pressed": String(!near), onclick: () => go("/duplicates") }, "Idénticos (SHA-256)"),
    h("button", { type: "button", "aria-pressed": String(near), onclick: () => go("/duplicates?mode=near") }, "Casi duplicados (SimHash)"));
  if (near) {
    const data = await api("/api/near-duplicates" + qs({ distance: route.params.get("distance") }));
    return [
      h("h1", {}, "Contenido duplicado"), toggle,
      h("p", { class: "lead" }, `Páginas con texto muy parecido (≤ ${data.distance} bits de diferencia en SimHash): mirrors con pequeños cambios. Poco fiable con páginas de menos de ~50 palabras.`),
      data.items.length
        ? data.items.map((g) => h("div", { class: "panel" },
          h("p", { class: "flush" }, h("span", { class: "tag" }, `${g.pages.length} páginas`), " ", h("span", { class: "muted" }, `hasta ${g.max_distance} bits`)),
          h("ul", { class: "plain" }, g.pages.map((p) => h("li", {}, link("/page/" + p.id, `[${p.id}] ${p.title || "(sin título)"}`), " ", code(p.url))))))
        : h("p", { class: "empty panel" }, "No hay casi duplicados."),
    ];
  }
  const data = await api("/api/duplicates");
  return [
    h("h1", {}, "Contenido duplicado"), toggle,
    h("p", { class: "lead" }, "URLs distintas con exactamente el mismo texto normalizado (mismo SHA-256): mirrors, clones o páginas de error comunes."),
    data.items.length
      ? data.items.map((g) => h("div", { class: "panel" },
        h("p", { class: "flush" }, h("span", { class: "tag" }, `${g.urls.length} URLs`), " ", code(g.content_hash)),
        h("ul", { class: "plain" }, g.urls.map((u, i) => h("li", {}, code(u), g.titles[i] ? h("span", { class: "muted" }, " · " + g.titles[i]) : null)))))
      : h("p", { class: "empty panel" }, "No hay contenido duplicado."),
  ];
}

/* ---------------------------------------------------------------- exportar */

export async function renderExport() {
  const reportLink = h("a", { class: "button secondary", href: "/report", target: "_blank", rel: "noopener noreferrer", hidden: true }, "Abrir informe");
  const reportStatus = h("p", { class: "muted" }, "El informe se guarda en results/report.html.");
  const verifyBox = h("div", {});
  const generate = async (btn) => {
    btn.disabled = true;
    const r = await post("/api/report", {}, "Informe generado.");
    if (r) {
      reportStatus.replaceChildren("Generado: ", code(r.path), h("br"), "SHA-256: ", code(r.sha256));
      reportLink.hidden = false;
    }
    btn.disabled = false;
  };
  const verify = async () => {
    try {
      const r = await api("/api/verify", { method: "POST" });
      verifyBox.replaceChildren(
        h("p", { class: r.passed ? "ok-box" : "error" }, r.passed ? "Verificación correcta: ningún fichero alterado." : "Verificación FALLIDA."),
        table(["Fichero", "Estado"], [
          ...r.ok.map((f) => h("tr", {}, h("td", {}, code(f)), h("td", { class: "status-2" }, "ok"))),
          ...r.modified.map((f) => h("tr", {}, h("td", {}, code(f)), h("td", { class: "status-5" }, "MODIFICADO"))),
          ...r.missing.map((f) => h("tr", {}, h("td", {}, code(f)), h("td", { class: "status-4" }, "FALTA"))),
        ], "El manifiesto está vacío."));
    } catch (err) {
      toast(err.message, true);
    }
  };
  const dl = (href, label) => h("a", { class: "button secondary", href, download: "" }, label);
  return [
    h("h1", {}, "Exportar e informe"),
    h("p", { class: "lead" }, "Los ficheros se generan en results/ y se registran con su SHA-256 en results/manifest.json (cadena de custodia)."),
    h("div", { class: "grid-2" },
      h("div", { class: "panel" },
        h("h2", { class: "flush" }, "Informe HTML"),
        h("p", {}, "Resumen, códigos HTTP, duplicados, IOCs con CVSS, cambios, alertas, notas y relación IOC ↔ páginas. Autocontenido y sin scripts."),
        h("div", { class: "row" }, h("button", { type: "button", onclick: (ev) => generate(ev.currentTarget) }, "Generar informe"), reportLink),
        reportStatus),
      h("div", { class: "panel" },
        h("h2", { class: "flush" }, "Exportar datos"),
        h("p", {}, "JSON y CSV (anti CSV injection), o formatos de intercambio de inteligencia de amenazas."),
        h("div", { class: "row" },
          dl("/api/export?format=json", "JSON"),
          dl("/api/export?format=csv&table=pages", "CSV páginas"),
          dl("/api/export?format=csv&table=iocs", "CSV IOCs"),
          dl("/api/export?format=stix", "STIX 2.1"),
          dl("/api/export?format=misp", "MISP")))),
    h("div", { class: "panel" },
      h("h2", { class: "flush" }, "Verificar evidencias"),
      h("p", {}, "Recalcula el SHA-256 de cada fichero del manifiesto para detectar modificaciones o borrados."),
      h("div", { class: "row" },
        h("button", { type: "button", class: "secondary", onclick: verify }, "Verificar integridad"),
        link("/audit", "Ver registro de auditoría")),
      verifyBox),
  ];
}

export function renderNotFound() {
  return [h("h1", {}, "No encontrado"), h("p", {}, link("/panel", "Volver al panel"))];
}
