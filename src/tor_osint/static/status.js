/* Estado de Tor y del crawl en segundo plano (indicadores de la cabecera). */

import { api, code, fmtDate, h, link, toast } from "./core.js";

const torPill = document.getElementById("tor-pill");
const crawlPill = document.getElementById("crawl-pill");
const alertPill = document.getElementById("alert-pill");

export async function torCheck(showIp = false) {
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

/** Actualiza el indicador de alertas pendientes de la cabecera. */
export function setAlertCount(count) {
  alertPill.hidden = !count;
  alertPill.textContent = `${count} alerta(s)`;
}

export async function refreshAlertCount() {
  try {
    setAlertCount((await api("/api/alerts")).open);
  } catch { /* indicador opcional */ }
}

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

export async function pollCrawl() {
  clearTimeout(crawlTimer);
  try {
    const job = await api("/api/crawl");
    updateCrawlPill(job);
    crawlListeners.forEach((fn) => fn(job));
    if (job.state === "running") crawlTimer = setTimeout(pollCrawl, 1500);
    else if (job.state === "done") refreshAlertCount();
    return job;
  } catch {
    crawlTimer = setTimeout(pollCrawl, 5000);
    return null;
  }
}

export async function startCrawl(urls = []) {
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

export function crawlPanel() {
  const box = h("div", { class: "panel" });
  const render = (job) => {
    const pct = job.total ? Math.round((job.current / job.total) * 100) : 0;
    const items = [h("h2", { class: "flush" }, "Estado del crawl")];
    if (job.state === "idle") {
      items.push(h("p", { class: "muted" }, "Todavía no se ha lanzado ningún crawl en esta sesión."));
    } else {
      items.push(h("p", {},
        h("span", { class: "tag" }, { running: "en curso", done: "terminado", error: "error" }[job.state]),
        " ", job.state === "running" ? `${job.current} de ${job.total}` : "",
        job.started_at ? h("span", { class: "muted" }, ` · inicio ${fmtDate(job.started_at)}`) : ""));
      if (job.state === "running") {
        items.push(h("div", { class: "progress", role: "progressbar", "aria-valuenow": pct, "aria-valuemin": 0, "aria-valuemax": 100 },
          h("div", { style: `width:${pct}%` })));
        if (job.current_url) items.push(h("p", { class: "muted" }, "Consultando ", code(job.current_url)));
      }
      if (job.state === "done") {
        items.push(h("div", { class: "row" },
          h("span", { class: "pill" }, `${job.new} nueva(s)`),
          h("span", { class: job.changed ? "pill warn" : "pill" }, `${job.changed} con cambios`),
          h("span", { class: job.alerts ? "pill bad" : "pill" }, `${job.alerts} alerta(s)`),
          job.changed ? link("/changes", "Ver cambios") : null,
          job.alerts ? link("/watch", "Ver alertas") : null));
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
