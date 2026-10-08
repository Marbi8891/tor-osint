/* tor-osint — punto de entrada del frontend: router por hash. */

import { appendAll, h } from "./core.js";
import {
  renderAudit, renderChanges, renderDiff, renderGraph, renderWatch,
} from "./research.js";
import { pollCrawl, refreshAlertCount } from "./status.js";
import {
  renderDuplicates, renderExport, renderIocs, renderNotFound, renderPage, renderPages,
  renderPanel, renderRelated, renderSearch, renderSources,
} from "./views.js";

const view = document.getElementById("view");

const routes = {
  panel: renderPanel,
  sources: renderSources,
  changes: renderChanges,
  diff: renderDiff,
  pages: renderPages,
  page: renderPage,
  search: renderSearch,
  iocs: renderIocs,
  related: renderRelated,
  graph: renderGraph,
  watch: renderWatch,
  duplicates: renderDuplicates,
  export: renderExport,
  audit: renderAudit,
};

// Vistas de detalle que resaltan la pestaña de su sección.
const navAlias = { page: "pages", related: "iocs", diff: "changes", audit: "export" };

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "") || "panel";
  const [path, query = ""] = raw.split("?");
  const parts = path.split("/").map(decodeURIComponent);
  return { name: parts[0], arg: parts[1], params: new URLSearchParams(query) };
}

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
router();
pollCrawl();
refreshAlertCount();
