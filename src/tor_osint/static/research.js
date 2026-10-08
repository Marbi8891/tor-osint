/* Vistas de investigación: cambios, diff, watchlist y alertas, grafo y auditoría. */

import {
  IOC_LABELS, api, appendAll, code, fmtDate, go, h, link, post, qs, rerender, statusCell, svg, table,
} from "./core.js";
import { setAlertCount } from "./status.js";

/* ----------------------------------------------------------------- cambios */

function iocDelta(added, removed) {
  const rows = [];
  for (const [type, values] of Object.entries(added || {})) {
    for (const v of values) rows.push(h("li", { class: "delta-add" }, h("span", { class: "delta-sign", "aria-label": "añadido" }, "+"), " ", h("span", { class: "tag" }, IOC_LABELS[type] || type), " ", code(v)));
  }
  for (const [type, values] of Object.entries(removed || {})) {
    for (const v of values) rows.push(h("li", { class: "delta-del" }, h("span", { class: "delta-sign", "aria-label": "eliminado" }, "−"), " ", h("span", { class: "tag" }, IOC_LABELS[type] || type), " ", code(v)));
  }
  return rows.length ? h("ul", { class: "plain delta" }, rows) : h("p", { class: "muted" }, "Sin cambios de IOCs.");
}

export async function renderChanges() {
  const data = await api("/api/changes" + qs({ limit: 200 }));
  return [
    h("h1", {}, "Cambios"),
    h("p", { class: "lead" }, "Páginas cuyo último crawl difiere del anterior: código HTTP, título, contenido o IOCs."),
    data.items.length
      ? data.items.map((c) => h("div", { class: "panel" },
        h("div", { class: "row spread" },
          h("p", { class: "flush" }, link(`/page/${c.page_id}`, `[${c.page_id}] ${c.title || "(sin título)"}`), h("br"), code(c.url)),
          h("a", { class: "button secondary small", href: `#/diff?page=${c.page_id}&from=${c.old_snapshot}&to=${c.new_snapshot}` }, "Ver diff")),
        h("p", {}, c.kinds.map((k) => h("span", { class: "tag tag-space" }, k)), h("span", { class: "muted" }, fmtDate(c.fetched_at))),
        iocDelta(c.iocs_added, c.iocs_removed)))
      : h("p", { class: "empty panel" }, "Ninguna página ha cambiado en su último crawl. Repite el crawl para detectar cambios."),
  ];
}

export async function renderDiff(route) {
  const page = route.params.get("page");
  const from = route.params.get("from");
  const to = route.params.get("to");
  const [data, hist] = await Promise.all([
    api("/api/diff" + qs({ page, from, to })),
    api(`/api/pages/${encodeURIComponent(page || "")}/history`),
  ]);
  const head = [h("p", {}, link(`/page/${page}`, "← Página"), " · ", link("/changes", "Cambios")), h("h1", {}, `Diferencias de la página ${page}`)];
  const snaps = hist.items;
  if (snaps.length > 1) {
    const pick = (name, current) => h("select", { "aria-label": name === "from" ? "Versión antigua" : "Versión nueva", onchange: (ev) => {
      const params = { page, from: data.diff?.old_id, to: data.diff?.new_id, [name]: ev.target.value };
      go("/diff" + qs(params));
    } }, snaps.map((s) => h("option", { value: s.id, selected: String(s.id) === String(current) }, `#${s.id} · ${fmtDate(s.fetched_at)}`)));
    head.push(h("div", { class: "panel row" }, h("span", {}, "Comparar"), pick("from", data.diff?.old_id), h("span", {}, "con"), pick("to", data.diff?.new_id)));
  }
  const d = data.diff;
  if (!d) return [...head, h("p", { class: "empty panel" }, "La página solo tiene una versión: no hay nada que comparar.")];
  const pct = Math.round(d.similarity * 100);
  return [
    ...head,
    h("div", { class: "panel" },
      h("dl", { class: "meta" },
        h("dt", {}, "Antigua"), h("dd", {}, `#${d.old_id} · ${fmtDate(d.old_fetched_at)}`),
        h("dt", {}, "Nueva"), h("dd", {}, `#${d.new_id} · ${fmtDate(d.new_fetched_at)}`),
        h("dt", {}, "Cambios"), h("dd", {}, d.kinds.length ? d.kinds.map((k) => h("span", { class: "tag tag-space" }, k)) : "ninguno"),
        d.status ? [h("dt", {}, "HTTP"), h("dd", {}, statusCell(d.status[0]), " → ", statusCell(d.status[1]))] : null,
        d.title ? [h("dt", {}, "Título"), h("dd", {}, h("del", {}, d.title[0] || "(vacío)"), " → ", h("ins", {}, d.title[1] || "(vacío)"))] : null,
        d.content_changed ? [h("dt", {}, "Similitud"), h("dd", {},
          h("div", { class: "progress", role: "img", "aria-label": `Similitud ${pct}%` }, h("div", { style: `width:${pct}%` })), `${pct} % del texto se mantiene`)] : null)),
    d.content_changed
      ? h("div", { class: "grid-2" },
        h("section", {}, h("h2", {}, `Eliminado (${d.removed.length})`),
          d.removed.length ? h("ul", { class: "plain" }, d.removed.map((f) => h("li", {}, h("del", {}, f)))) : h("p", { class: "muted" }, "Nada.")),
        h("section", {}, h("h2", {}, `Añadido (${d.added.length})`),
          d.added.length ? h("ul", { class: "plain" }, d.added.map((f) => h("li", {}, h("ins", {}, f)))) : h("p", { class: "muted" }, "Nada.")))
      : null,
    d.truncated ? h("p", { class: "notice" }, "Diff calculado sobre las primeras 20 000 palabras de cada versión.") : null,
    h("h2", {}, "IOCs"),
    h("div", { class: "panel" }, iocDelta(d.iocs_added, d.iocs_removed)),
  ];
}

/* --------------------------------------------------------- watchlist y alertas */

export async function renderWatch(route) {
  const showAll = route.params.get("all") === "1";
  const [watch, alerts] = await Promise.all([api("/api/watchlist"), api("/api/alerts" + qs({ all: showAll ? "1" : "" }))]);
  setAlertCount(alerts.open);

  const kind = h("select", { "aria-label": "Tipo de vigilancia" },
    h("option", { value: "term" }, "Término (texto)"), h("option", { value: "ioc" }, "IOC (dominio, IP, CVE…)"));
  const value = h("input", { type: "text", required: true, maxlength: 500, placeholder: "acme, CVE-2024-1234, 203.0.113.7…", "aria-label": "Valor a vigilar", spellcheck: "false" });
  const label = h("input", { type: "text", maxlength: 100, placeholder: "descripción (opcional)", "aria-label": "Descripción" });
  const form = h("form", { class: "inline" }, kind, value, label, h("button", { type: "submit" }, "Vigilar"));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const r = await post("/api/watch", { kind: kind.value, value: value.value, label: label.value },
      (res) => `Vigilancia añadida · ${res.alerts} coincidencia(s) en los datos actuales`);
    if (r) rerender();
  });

  return [
    h("h1", {}, "Watchlist y alertas"),
    h("p", { class: "lead" }, "Términos e IOCs que te interesan. Tras cada crawl se comparan con las páginas guardadas; la alerta solo se repite si la página cambia."),
    h("div", { class: "panel" }, h("h2", { class: "flush" }, "Nueva vigilancia"), form,
      h("p", { class: "muted flush-bottom" }, "Los términos ignoran mayúsculas y tildes. Los IOCs se normalizan (cve-2024-1234 = CVE-2024-1234).")),
    h("div", { class: "row spread" },
      h("h2", {}, `Vigilancias (${watch.items.length})`),
      h("button", { type: "button", class: "secondary small", onclick: async () => { if (await post("/api/watch/scan", {}, (r) => `${r.alerts} alerta(s) nuevas`)) rerender(); } }, "Reevaluar toda la BD")),
    table(["Tipo", "Valor", "Descripción", { label: "Pendientes", num: true }, { label: "Total", num: true }, ""],
      watch.items.map((w) => h("tr", {},
        h("td", {}, h("span", { class: "tag" }, w.kind === "term" ? "término" : "ioc")),
        h("td", {}, code(w.value)),
        h("td", {}, w.label || h("span", { class: "muted" }, "—")),
        h("td", { class: "num" }, String(w.open_alerts)),
        h("td", { class: "num" }, String(w.alerts)),
        h("td", {}, h("button", { type: "button", class: "small secondary", onclick: async () => { if (await post("/api/watch/delete", { id: w.id }, "Vigilancia eliminada")) rerender(); } }, "Eliminar")))),
      "Todavía no vigilas nada."),
    h("div", { class: "row spread" },
      h("h2", {}, showAll ? `Todas las alertas (${alerts.items.length})` : `Alertas pendientes (${alerts.open})`),
      h("div", { class: "row" },
        h("a", { class: "button secondary small", href: showAll ? "#/watch" : "#/watch?all=1" }, showAll ? "Solo pendientes" : "Ver todas"),
        alerts.open ? h("button", { type: "button", class: "small", onclick: async () => { if (await post("/api/alerts/ack", {}, "Alertas marcadas como revisadas")) rerender(); } }, "Marcar todas como revisadas") : null)),
    table(["", "Fecha", "Vigilancia", "Página", ""],
      alerts.items.map((a) => h("tr", {},
        h("td", {}, a.acknowledged ? h("span", { class: "muted", title: "revisada" }, "✓") : h("span", { class: "alert-dot", title: "pendiente" }, "●")),
        h("td", {}, fmtDate(a.created_at)),
        h("td", {}, h("span", { class: "tag" }, a.kind), " ", code(a.value)),
        h("td", {}, link("/page/" + a.page_id, `[${a.page_id}] ${a.title || "(sin título)"}`), h("br"), code(a.url)),
        h("td", {}, a.acknowledged ? null : h("button", { type: "button", class: "small secondary", onclick: async () => { if (await post("/api/alerts/ack", { ids: [a.id] }, "Alerta revisada")) rerender(); } }, "Revisada")))),
      showAll ? "No hay alertas." : "No hay alertas pendientes."),
  ];
}

/* --------------------------------------------------------------- auditoría */

export async function renderAudit() {
  const data = await api("/api/audit" + qs({ limit: 300 }));
  return [
    h("p", {}, link("/export", "← Exportar e informe")),
    h("h1", {}, "Registro de auditoría"),
    h("p", { class: "lead" }, "Acciones del investigador (crawls, exportaciones, vigilancias, notas…) con fecha y usuario del sistema. Forma parte de la cadena de custodia."),
    table(["Fecha", "Usuario", "Acción", "Detalles"],
      data.items.map((e) => h("tr", {},
        h("td", {}, fmtDate(e.at)),
        h("td", {}, e.actor),
        h("td", {}, code(e.action)),
        h("td", { class: "small" }, Object.entries(e.details).map(([k, v]) => h("span", { class: "kv" }, h("span", { class: "muted" }, k + "="), String(v)))))),
      "Sin entradas."),
  ];
}

/* ------------------------------------------------------------------- grafo */

// Categorías del grafo: 3 tonos validados (todos los pares, ambos modos) + gris "otros".
const CATEGORY = {
  email: "net", domain: "net", url: "net", ipv4: "net", onion: "net",
  md5: "file", sha1: "file", sha256: "file",
  cve: "vuln", attack: "vuln",
  btc: "other", eth: "other", pgp: "other",
};
const CATEGORY_LABEL = { page: "Página", net: "Red (email, dominio, URL, IP, onion)", file: "Fichero (hash)", vuln: "Vulnerabilidad / ATT&CK", other: "Otros (cripto, PGP)" };

function mulberry32(seed) {
  return () => {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Fruchterman–Reingold con semilla fija: el mismo grafo produce el mismo dibujo. */
function forceLayout(nodes, edges, width, height) {
  const n = nodes.length;
  const rand = mulberry32(42);
  const pos = nodes.map(() => [rand() * width, rand() * height]);
  const index = new Map(nodes.map((nd, i) => [nd.id, i]));
  const links = edges.map(([a, b]) => [index.get(a), index.get(b)]).filter(([a, b]) => a !== undefined && b !== undefined);
  const k = 0.9 * Math.sqrt((width * height) / Math.max(n, 1));
  let temp = width / 8;
  for (let it = 0; it < 220; it++) {
    const disp = pos.map(() => [0, 0]);
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const dx = pos[i][0] - pos[j][0];
        const dy = pos[i][1] - pos[j][1];
        const d = Math.max(0.01, Math.hypot(dx, dy));
        const f = (k * k) / d;
        disp[i][0] += (dx / d) * f; disp[i][1] += (dy / d) * f;
        disp[j][0] -= (dx / d) * f; disp[j][1] -= (dy / d) * f;
      }
    }
    for (const [a, b] of links) {
      const dx = pos[a][0] - pos[b][0];
      const dy = pos[a][1] - pos[b][1];
      const d = Math.max(0.01, Math.hypot(dx, dy));
      const f = (d * d) / k;
      disp[a][0] -= (dx / d) * f; disp[a][1] -= (dy / d) * f;
      disp[b][0] += (dx / d) * f; disp[b][1] += (dy / d) * f;
    }
    for (let i = 0; i < n; i++) {
      disp[i][0] += (width / 2 - pos[i][0]) * 0.05 * k / 10; // gravedad suave: evita islas lejanas
      disp[i][1] += (height / 2 - pos[i][1]) * 0.05 * k / 10;
      const len = Math.max(0.01, Math.hypot(disp[i][0], disp[i][1]));
      pos[i][0] += (disp[i][0] / len) * Math.min(len, temp);
      pos[i][1] += (disp[i][1] / len) * Math.min(len, temp);
    }
    temp *= 0.975;
  }
  // Ajuste al lienzo con margen.
  const pad = 40;
  const xs = pos.map((p) => p[0]); const ys = pos.map((p) => p[1]);
  const [minX, maxX, minY, maxY] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)];
  const sx = (width - 2 * pad) / Math.max(1, maxX - minX);
  const sy = (height - 2 * pad) / Math.max(1, maxY - minY);
  return pos.map(([x, y]) => [pad + (x - minX) * sx, pad + (y - minY) * sy]);
}

function legendItem(category) {
  const mark = category === "page"
    ? svg("svg", { width: 14, height: 14, "aria-hidden": "true" }, svg("rect", { x: 2, y: 2, width: 10, height: 10, rx: 2, class: "g-node g-page" }))
    : svg("svg", { width: 14, height: 14, "aria-hidden": "true" }, svg("circle", { cx: 7, cy: 7, r: 5, class: `g-node g-${category}` }));
  return h("span", { class: "legend-item" }, mark, CATEGORY_LABEL[category]);
}

export async function renderGraph(route) {
  const minPages = route.params.get("min_pages") || "2";
  const type = route.params.get("type") || "";
  const data = await api("/api/graph" + qs({ min_pages: minPages, type }));
  const tableMode = route.params.get("view") === "table";

  const filters = h("div", { class: "row filters" },
    h("label", {}, "IOCs presentes en al menos ",
      h("select", { onchange: (ev) => go("/graph" + qs({ min_pages: ev.target.value, type, view: route.params.get("view") })) },
        ["1", "2", "3", "5"].map((v) => h("option", { value: v, selected: v === minPages }, v))), " página(s)"),
    h("label", {}, "Tipo ",
      h("select", { onchange: (ev) => go("/graph" + qs({ min_pages: minPages, type: ev.target.value, view: route.params.get("view") })) },
        h("option", { value: "" }, "Todos"),
        Object.keys(CATEGORY).map((t) => h("option", { value: t, selected: t === type }, IOC_LABELS[t] || t)))),
    h("div", { class: "segmented", role: "group", "aria-label": "Vista" },
      h("button", { type: "button", "aria-pressed": String(!tableMode), onclick: () => go("/graph" + qs({ min_pages: minPages, type })) }, "Grafo"),
      h("button", { type: "button", "aria-pressed": String(tableMode), onclick: () => go("/graph" + qs({ min_pages: minPages, type, view: "table" })) }, "Tabla")));

  const intro = [
    h("h1", {}, "Grafo de correlación"),
    h("p", { class: "lead" }, "Páginas e indicadores que comparten. Un IOC conectado a varias páginas relaciona fuentes entre sí. Solo datos locales."),
    filters,
  ];
  const iocNodes = data.nodes.filter((n) => n.kind === "ioc");
  if (!iocNodes.length) {
    return [...intro, h("p", { class: "empty panel" }, `Ningún IOC aparece en ${minPages} o más páginas. Baja el umbral o recopila más fuentes.`)];
  }

  const pagesById = new Map(data.nodes.filter((n) => n.kind === "page").map((n) => [n.id, n]));
  const pagesOf = new Map(iocNodes.map((n) => [n.id, []]));
  for (const [p, i] of data.edges) pagesOf.get(i)?.push(pagesById.get(p));

  if (tableMode) {
    return [...intro,
      table(["IOC", "Categoría", { label: "Páginas", num: true }, "Aparece en"],
        iocNodes.map((n) => h("tr", {},
          h("td", {}, link("/related" + qs({ value: n.label }), n.label)),
          h("td", {}, h("span", { class: "tag" }, IOC_LABELS[n.type] || n.type)),
          h("td", { class: "num" }, String(n.pages)),
          h("td", {}, (pagesOf.get(n.id) || []).filter(Boolean).map((p) => h("span", { class: "kv" }, link("/page/" + p.page_id, `#${p.page_id}`))))))),
      data.truncated ? h("p", { class: "muted" }, "Mostrando los 150 IOCs más compartidos.") : null];
  }

  const W = 960; const H = 600;
  const pos = forceLayout(data.nodes, data.edges, W, H);
  const at = new Map(data.nodes.map((n, i) => [n.id, pos[i]]));
  const neighbors = new Map(data.nodes.map((n) => [n.id, new Set([n.id])]));
  for (const [a, b] of data.edges) { neighbors.get(a)?.add(b); neighbors.get(b)?.add(a); }

  const tooltip = h("div", { class: "g-tooltip", role: "status", hidden: true });
  const wrap = h("div", { class: "graph-wrap" });
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "graph", role: "group", "aria-label": `Grafo con ${data.nodes.length} nodos y ${data.edges.length} relaciones` });

  const edgeEls = data.edges.map(([a, b]) => {
    const [x1, y1] = at.get(a); const [x2, y2] = at.get(b);
    return svg("line", { x1, y1, x2, y2, class: "g-edge", "data-a": a, "data-b": b });
  });
  root.append(svg("g", {}, edgeEls));

  // Etiquetas directas solo en los IOCs más conectados (selectivas, nunca en todos).
  const labelled = new Set([...iocNodes].sort((x, y) => y.pages - x.pages).slice(0, 8).map((n) => n.id));
  const nodeLayer = svg("g", {});
  const labelLayer = svg("g", { "aria-hidden": "true" });
  const nodeEls = new Map();

  const showTip = (node, x, y) => {
    tooltip.hidden = false;
    tooltip.replaceChildren();
    appendAll(tooltip, [ // appendAll descarta null (replaceChildren lo pintaría como texto)
      h("strong", {}, node.kind === "page" ? (node.label || "(sin título)") : node.label),
      h("div", { class: "muted" }, node.kind === "page" ? `Página #${node.page_id}` : `${IOC_LABELS[node.type] || node.type} · ${node.pages} página(s)`),
      node.kind === "page" ? h("div", { class: "mono small" }, node.url) : null]);
    const box = wrap.getBoundingClientRect();
    const sx = box.width / W;
    tooltip.style.left = `${Math.min(box.width - 260, Math.max(0, x * sx + 12))}px`;
    tooltip.style.top = `${y * sx + 12}px`;
  };
  const highlight = (id) => {
    const keep = neighbors.get(id);
    root.classList.add("is-focus");
    for (const [nid, el] of nodeEls) el.classList.toggle("is-hi", keep.has(nid));
    for (const el of edgeEls) el.classList.toggle("is-hi", el.dataset.a === id || el.dataset.b === id);
  };
  const clear = () => {
    root.classList.remove("is-focus");
    tooltip.hidden = true;
  };

  for (const node of data.nodes) {
    const [x, y] = at.get(node.id);
    const category = node.kind === "page" ? "page" : CATEGORY[node.type] || "other";
    const r = node.kind === "page" ? 6 : Math.min(12, 4 + Math.sqrt(node.pages) * 1.8);
    const target = node.kind === "page" ? "/page/" + node.page_id : "/related" + qs({ value: node.label });
    const name = node.kind === "page" ? `Página ${node.page_id}: ${node.label || "sin título"}` : `${IOC_LABELS[node.type] || node.type} ${node.label}, en ${node.pages} páginas`;
    const mark = node.kind === "page"
      ? svg("rect", { x: x - r, y: y - r, width: 2 * r, height: 2 * r, rx: 2, class: "g-node g-page" })
      : svg("circle", { cx: x, cy: y, r, class: `g-node g-${category}` });
    const g = svg("g", {
      class: "g-item", tabindex: 0, role: "link", "aria-label": name,
      onpointerenter: () => { highlight(node.id); showTip(node, x, y); },
      onpointerleave: clear,
      onfocus: () => { highlight(node.id); showTip(node, x, y); },
      onblur: clear,
      onclick: () => go(target),
      onkeydown: (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); go(target); } },
    }, svg("circle", { cx: x, cy: y, r: Math.max(r + 6, 12), class: "g-hit" }), mark);
    nodeEls.set(node.id, g);
    nodeLayer.append(g);
    if (labelled.has(node.id)) {
      const text = node.label.length > 28 ? node.label.slice(0, 27) + "…" : node.label;
      const leftSide = x > W - 200; // cerca del borde derecho: etiqueta a la izquierda del nodo
      labelLayer.append(svg("text", {
        x: leftSide ? x - r - 4 : x + r + 4, y: y + 4, class: "g-label", "text-anchor": leftSide ? "end" : "start",
      }, text));
    }
  }
  root.append(nodeLayer, labelLayer);
  wrap.append(root, tooltip);

  return [
    ...intro,
    h("div", { class: "legend", role: "list", "aria-label": "Leyenda" },
      ["page", "net", "file", "vuln", "other"].map((c) => h("span", { role: "listitem" }, legendItem(c)))),
    h("div", { class: "panel graph-panel" }, wrap),
    h("p", { class: "muted small" },
      `${pagesById.size} páginas · ${iocNodes.length} IOCs · ${data.edges.length} relaciones. `,
      "Pasa el ratón o usa Tab para resaltar las conexiones; Intro abre el detalle. En pantallas estrechas, desliza el grafo o usa la vista Tabla. ",
      data.truncated ? "Mostrando los 150 IOCs más compartidos." : ""),
  ];
}
