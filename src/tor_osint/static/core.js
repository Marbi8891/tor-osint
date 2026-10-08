/* tor-osint — utilidades compartidas del frontend.
 *
 * Regla de seguridad: todo dato procedente de la API (y por tanto de páginas
 * remotas no confiables) se inserta con textContent a través de h(). Nunca se
 * usa innerHTML, insertAdjacentHTML ni document.write.
 */

const CSRF = document.querySelector('meta[name="csrf-token"]').content;

export const IOC_TYPES = [
  "email", "domain", "url", "ipv4", "hash", "md5", "sha1", "sha256", "cve", "onion",
  "crypto", "btc", "eth", "attack", "pgp",
];
export const IOC_LABELS = {
  email: "Emails", domain: "Dominios", url: "URLs", ipv4: "IPv4", hash: "Hashes",
  md5: "MD5", sha1: "SHA-1", sha256: "SHA-256", cve: "CVE", onion: "Onion",
  crypto: "Criptomonedas", btc: "Bitcoin", eth: "Ethereum", attack: "ATT&CK", pgp: "PGP",
};
export const PAGE_SIZE = 50;

/* ---------------------------------------------------------------- DOM */

/** Crea un elemento. Los hijos de tipo string se añaden como nodos de texto. */
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  setAttrs(el, attrs);
  appendAll(el, children);
  return el;
}

/** Igual que h() pero en el espacio de nombres SVG. */
export function svg(tag, attrs = {}, ...children) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  setAttrs(el, attrs);
  appendAll(el, children);
  return el;
}

function setAttrs(el, attrs) {
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key.startsWith("on") && typeof value === "function") {
      el.addEventListener(key.slice(2), value);
    } else if (key === "class") {
      el.setAttribute("class", value);
    } else if (key === "style") {
      el.style.cssText = value; // CSSOM: permitido por la CSP (setAttribute("style") no)
    } else if (value === true) {
      el.setAttribute(key, "");
    } else {
      el.setAttribute(key, String(value));
    }
  }
}

export function appendAll(el, children) {
  for (const child of [children].flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

/** Enlace interno de la SPA (siempre un hash generado por nosotros). */
export function link(route, ...children) {
  return h("a", { href: "#" + route }, ...children);
}

export function go(route) {
  location.hash = "#" + route;
}

export function code(text) {
  return h("code", {}, text ?? "");
}

export function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString("es-ES");
}

export function statusCell(status) {
  if (status === null || status === undefined) return h("span", { class: "muted" }, "—");
  return h("span", { class: "status-" + String(status)[0] }, String(status));
}

export function severityBadge(cvss) {
  if (!cvss) return h("span", { class: "muted" }, "—");
  const sev = (cvss.severity || "").toUpperCase();
  const score = cvss.cvss_score !== null && cvss.cvss_score !== undefined ? cvss.cvss_score.toFixed(1) : "";
  return h("span", { class: "sev sev-" + (/^[A-Z]+$/.test(sev) ? sev : "NONE"), title: cvss.description || "" },
    `${score} ${sev}`.trim() || "—");
}

/** Convierte un snippet FTS con marcadores \x02…\x03 en nodos de texto y <mark>. */
export function highlighted(snippet) {
  const out = [];
  let marked = false;
  for (const part of String(snippet || "").split(/([\x02\x03])/)) {
    if (part === "\x02") marked = true;
    else if (part === "\x03") marked = false;
    else if (part) out.push(marked ? h("mark", {}, part) : part);
  }
  return out;
}

export function table(headers, rows, emptyText = "Sin datos.") {
  if (!rows.length) return h("p", { class: "empty panel" }, emptyText);
  return h("div", { class: "table-wrap" },
    h("table", {},
      h("thead", {}, h("tr", {}, headers.map((hd) =>
        h("th", { class: [hd.num ? "num" : "", hd.cls || ""].join(" ").trim() || null, scope: "col" }, hd.label ?? hd)))),
      h("tbody", {}, rows)));
}

export function toast(message, isError = false) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.className = isError ? "bad" : "";
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.hidden = true; }, isError ? 6000 : 3500);
}

export function qs(params) {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") usp.set(k, v);
  const s = usp.toString();
  return s ? "?" + s : "";
}

/* ---------------------------------------------------------------- API */

export async function api(path, { method = "GET", body } = {}) {
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

/** Ejecuta una acción POST mostrando el resultado; devuelve la respuesta o null. */
export async function post(path, body, okMessage) {
  try {
    const res = await api(path, { method: "POST", body });
    if (okMessage) toast(typeof okMessage === "function" ? okMessage(res) : okMessage);
    return res;
  } catch (err) {
    toast(err.message, true);
    return null;
  }
}

/* ------------------------------------------------- notas y etiquetas (widget) */

/**
 * Panel de notas y etiquetas para una página o un IOC. `onChange` se llama
 * tras cada modificación para refrescar la vista.
 */
export function annotationsPanel(targetType, target, notes, tags, onChange = rerender) {
  const tagInput = h("input", { type: "text", required: true, maxlength: 40, placeholder: "etiqueta (p. ej. phishing)", "aria-label": "Nueva etiqueta", spellcheck: "false" });
  const tagForm = h("form", { class: "inline" }, tagInput, h("button", { type: "submit", class: "secondary" }, "Etiquetar"));
  tagForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (await post("/api/tags", { target_type: targetType, target, tag: tagInput.value }, "Etiqueta añadida")) onChange();
  });

  const noteInput = h("textarea", { required: true, maxlength: 10000, rows: 3, placeholder: "Nota del investigador…", "aria-label": "Nueva nota" });
  const noteForm = h("form", { class: "stack" }, noteInput, h("div", {}, h("button", { type: "submit" }, "Añadir nota")));
  noteForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (await post("/api/notes", { target_type: targetType, target, body: noteInput.value }, "Nota añadida")) onChange();
  });

  return h("div", { class: "panel" },
    h("h2", { class: "flush" }, "Etiquetas"),
    tags.length
      ? h("div", { class: "chips", style: "margin-bottom:10px" }, tags.map((t) =>
        h("span", { class: "chip tagchip" }, t,
          h("button", {
            type: "button", class: "chip-x", "aria-label": `Quitar etiqueta ${t}`,
            onclick: async () => { if (await post("/api/tags/delete", { target_type: targetType, target, tag: t }, "Etiqueta quitada")) onChange(); },
          }, "×"))))
      : h("p", { class: "muted" }, "Sin etiquetas."),
    tagForm,
    h("h2", {}, `Notas (${notes.length})`),
    notes.length
      ? h("ul", { class: "plain" }, notes.map((n) => h("li", {},
        h("div", { class: "note-meta" }, h("span", { class: "muted" }, fmtDate(n.created_at)),
          h("button", {
            type: "button", class: "small secondary",
            onclick: async () => { if (await post("/api/notes/delete", { id: n.id }, "Nota eliminada")) onChange(); },
          }, "Eliminar")),
        h("p", { class: "note-body" }, n.body))))
      : h("p", { class: "muted" }, "Sin notas."),
    noteForm);
}

/** Vuelve a pintar la vista actual (el router escucha "hashchange"). */
export function rerender() {
  window.dispatchEvent(new HashChangeEvent("hashchange"));
}
