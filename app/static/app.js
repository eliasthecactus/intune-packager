"use strict";

const $ = (id) => document.getElementById(id);
const sections = ["login", "new-job", "progress", "result", "failed"];
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* ignore */ } },
  del(k) { try { localStorage.removeItem(k); } catch { /* ignore */ } },
};

let cfg = null;
let files = []; // {file, path}
let pollTimer = null;
let eventCount = 0;
let allEvents = [];

function show(id) {
  sections.forEach((s) => { $(s).hidden = s !== id; });
}

function fmtSize(n) {
  const u = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${i ? n.toFixed(1) : n} ${u[i]}`;
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function api(path, opts = {}) {
  const res = await fetch(path, { credentials: "same-origin", ...opts });
  if (res.status === 401) { show("login"); throw new Error("auth"); }
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { msg = (await res.json()).detail || msg; } catch { /* ignore */ }
    throw new Error(msg);
  }
  return res.json();
}

// ------------------------------------------------------------------ boot
async function boot() {
  cfg = await (await fetch("/api/config", { credentials: "same-origin" })).json();
  $("provider").textContent = cfg.provider;
  $("provider").hidden = false;
  $("logout").hidden = !cfg.auth_required || !cfg.authenticated;
  $("limit-hint").textContent = `Max. upload ${fmtSize(cfg.max_upload_mb * 1024 * 1024)}`;
  if (!cfg.configured) {
    $("config-error").hidden = false;
    $("config-error").textContent = "AI provider not configured: " + cfg.config_errors.join("; ");
  }
  if (cfg.auth_required && !cfg.authenticated) { show("login"); $("login-key").focus(); return; }
  const jobId = store.get("jobId");
  if (jobId) { startPolling(jobId); return; }
  show("new-job");
}

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("login-error").hidden = true;
  try {
    const res = await fetch("/api/login", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: $("login-key").value }),
    });
    if (!res.ok) {
      let msg = "Wrong access key";
      try { msg = (await res.json()).detail || msg; } catch { /* ignore */ }
      throw new Error(msg);
    }
    $("login-key").value = "";
    await boot();
  } catch (err) {
    $("login-error").textContent = err.message;
    $("login-error").hidden = false;
  }
});

$("logout").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST", credentials: "same-origin" });
  location.reload();
});

// ----------------------------------------------------------------- files
function addFiles(list) {
  for (const { file, path } of list) {
    if (/(^|\/)(\.DS_Store|Thumbs\.db|desktop\.ini)$/.test(path) || path.startsWith("__MACOSX/")) continue;
    if (!files.some((f) => f.path === path)) files.push({ file, path });
  }
  renderFiles();
}

function renderFiles() {
  const ul = $("file-list");
  ul.innerHTML = "";
  files.slice(0, 500).forEach((f, i) => {
    const li = document.createElement("li");
    li.innerHTML = `<span class="name">${esc(f.path)}</span><span><span class="size">${fmtSize(f.file.size)}</span> <button type="button" aria-label="Remove">✕</button></span>`;
    li.querySelector("button").addEventListener("click", () => { files.splice(i, 1); renderFiles(); });
    ul.appendChild(li);
  });
  const total = files.reduce((s, f) => s + f.file.size, 0);
  $("file-summary").textContent = `${files.length} file(s), ${fmtSize(total)}` + (files.length > 500 ? " (showing first 500)" : "");
  $("file-list-wrap").hidden = files.length === 0;
}

$("pick-files").addEventListener("click", () => $("file-input").click());
$("pick-folder").addEventListener("click", () => $("folder-input").click());
$("file-input").addEventListener("change", (e) => { addFiles([...e.target.files].map((f) => ({ file: f, path: f.name }))); e.target.value = ""; });
$("folder-input").addEventListener("change", (e) => { addFiles([...e.target.files].map((f) => ({ file: f, path: f.webkitRelativePath || f.name }))); e.target.value = ""; });
$("clear-files").addEventListener("click", () => { files = []; renderFiles(); });

const dz = $("dropzone");
["dragenter", "dragover"].forEach((t) => dz.addEventListener(t, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
["dragleave", "drop"].forEach((t) => dz.addEventListener(t, (e) => { e.preventDefault(); dz.classList.remove("drag"); }));
dz.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("file-input").click(); } });
dz.addEventListener("drop", async (e) => {
  const items = [...(e.dataTransfer.items || [])];
  const entries = items.map((it) => it.webkitGetAsEntry && it.webkitGetAsEntry()).filter(Boolean);
  if (!entries.length) { addFiles([...e.dataTransfer.files].map((f) => ({ file: f, path: f.name }))); return; }
  const out = [];
  await Promise.all(entries.map((en) => walk(en, "", out)));
  addFiles(out);
});

function walk(entry, prefix, out) {
  return new Promise((resolve) => {
    if (entry.isFile) {
      entry.file((f) => { out.push({ file: f, path: prefix + f.name }); resolve(); }, () => resolve());
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      const all = [];
      const read = () => reader.readEntries(async (batch) => {
        if (!batch.length) {
          await Promise.all(all.map((c) => walk(c, `${prefix}${entry.name}/`, out)));
          resolve();
        } else { all.push(...batch); read(); }
      }, () => resolve());
      read();
    } else resolve();
  });
}

// ---------------------------------------------------------------- submit
$("job-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const description = $("description").value.trim();
  $("form-error").hidden = true;
  if (!description && !files.length) {
    $("form-error").textContent = "Upload files or describe what you need (or both).";
    $("form-error").hidden = false;
    return;
  }
  const fd = new FormData();
  fd.append("description", description);
  fd.append("paths", JSON.stringify(files.map((f) => f.path)));
  files.forEach((f) => fd.append("files", f.file, f.file.name));

  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/api/jobs");
  xhr.withCredentials = true;
  $("submit").disabled = true;
  $("upload-progress").hidden = !files.length;
  xhr.upload.addEventListener("progress", (ev) => {
    if (ev.lengthComputable) $("upload-progress").firstElementChild.style.width = `${(ev.loaded / ev.total) * 100}%`;
  });
  xhr.onload = () => {
    $("submit").disabled = false;
    $("upload-progress").hidden = true;
    let data = {};
    try { data = JSON.parse(xhr.responseText); } catch { /* ignore */ }
    if (xhr.status === 401) { show("login"); return; }
    if (xhr.status >= 400 || !data.id) {
      $("form-error").textContent = data.detail || `Upload failed (HTTP ${xhr.status})`;
      $("form-error").hidden = false;
      return;
    }
    store.set("jobId", data.id);
    startPolling(data.id);
  };
  xhr.onerror = () => {
    $("submit").disabled = false;
    $("upload-progress").hidden = true;
    $("form-error").textContent = "Upload failed (network error or upload too large for a proxy in front of the app).";
    $("form-error").hidden = false;
  };
  xhr.send(fd);
});

// --------------------------------------------------------------- polling
function startPolling(jobId) {
  eventCount = 0;
  allEvents = [];
  $("events").innerHTML = "";
  show("progress");
  clearTimeout(pollTimer);
  poll(jobId);
}

async function poll(jobId) {
  let data;
  try {
    data = await api(`/api/jobs/${jobId}?since=${eventCount}`);
  } catch (err) {
    if (err.message === "auth") return;
    if (/not found/i.test(err.message)) { store.del("jobId"); show("new-job"); return; }
    pollTimer = setTimeout(() => poll(jobId), 4000);
    return;
  }
  data.events.forEach((ev) => { allEvents.push(ev); appendEvent($("events"), ev); });
  eventCount = data.next;
  $("elapsed").textContent = fmtTime(data.elapsed);
  if (data.status === "done") { renderResult(jobId, data); return; }
  if (data.status === "failed") { renderFailed(data); return; }
  pollTimer = setTimeout(() => poll(jobId), 1500);
}

function fmtTime(s) { return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`; }

function appendEvent(list, ev) {
  const li = document.createElement("li");
  li.className = ev.type;
  li.innerHTML = `<span class="t">${fmtTime(Math.round(ev.t))}</span><span class="msg">${esc(ev.msg)}</span>`;
  list.appendChild(li);
  if (list.id === "events") li.scrollIntoView({ block: "nearest" });
}

function copyButton(text) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "link copy";
  b.textContent = "Copy";
  b.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(text); b.textContent = "Copied"; setTimeout(() => { b.textContent = "Copy"; }, 1500); } catch { /* ignore */ }
  });
  return b;
}

function quickItem(label, value) {
  const div = document.createElement("div");
  div.className = "item";
  div.innerHTML = `<div class="k"><span>${esc(label)}</span></div><div class="v">${esc(value)}</div>`;
  div.querySelector(".k").appendChild(copyButton(value));
  return div;
}

function detectionText(rule) {
  switch (rule.type) {
    case "msi": return `MSI ${rule.msi_product_code}` + (rule.msi_product_version ? ` (version ${rule.msi_version_operator || "greaterThanOrEqual"} ${rule.msi_product_version})` : "");
    case "file": return `File: ${rule.path}\\${rule.file_or_folder} · ${rule.file_method}` + (rule.value ? ` ${rule.operator} ${rule.value}` : "");
    case "registry": return `Registry: ${rule.key_path}` + (rule.value_name ? ` · ${rule.value_name}` : "") + ` · ${rule.registry_method}` + (rule.value ? ` ${rule.operator} ${rule.value}` : "");
    case "script": return "Custom script (detection/detect.ps1 in the zip)";
    default: return JSON.stringify(rule);
  }
}

function renderResult(jobId, data) {
  store.del("jobId");
  const ui = data.result;
  const r = ui.result || {};
  const app = r.app || {};
  $("result-title").textContent = app.name || "Result";
  $("result-sub").textContent = [app.publisher, app.version].filter(Boolean).join(" · ");
  const st = $("result-status");
  st.textContent = ui.feasible ? "Ready to upload" : "Not possible as requested";
  st.className = `status ${ui.feasible ? "ok" : "no"}`;
  const logo = $("result-logo");
  if (ui.logo) { logo.src = `/api/jobs/${jobId}/logo`; logo.hidden = false; } else logo.hidden = true;

  const quick = $("quick");
  quick.innerHTML = "";
  if (ui.feasible) {
    quick.appendChild(quickItem("Install command", r.install_command || ""));
    quick.appendChild(quickItem("Uninstall command", r.uninstall_command || ""));
    (r.detection_rules || []).forEach((rule, i) => quick.appendChild(quickItem(`Detection rule ${i + 1}`, detectionText(rule))));
  }
  $("download").href = `/api/jobs/${jobId}/download`;
  $("download").setAttribute("download", ui.zip_name);
  const u = data.usage;
  $("usage").textContent = u ? `${u.requests} AI requests · ${(u.input_tokens / 1000).toFixed(0)}k input / ${(u.output_tokens / 1000).toFixed(0)}k output tokens` + (u.cost_usd ? ` · ~$${u.cost_usd.toFixed(2)}` : "") + ` · ${fmtTime(data.elapsed)} min` : "";
  $("readme").innerHTML = renderMarkdown(ui.readme || "");
  const fin = $("events-final");
  fin.innerHTML = "";
  allEvents.forEach((ev) => appendEvent(fin, ev));
  show("result");
}

function renderFailed(data) {
  store.del("jobId");
  $("failed-msg").textContent = data.error || "Unknown error";
  const list = $("events-failed");
  list.innerHTML = "";
  allEvents.forEach((ev) => appendEvent(list, ev));
  show("failed");
}

function restart() {
  files = [];
  renderFiles();
  $("description").value = "";
  show("new-job");
}
$("restart").addEventListener("click", restart);
$("restart-failed").addEventListener("click", () => show("new-job"));

// ------------------------------------------------------- tiny markdown
function inline(text) {
  let s = esc(text);
  s = s.replace(/``(.+?)``|`([^`]+)`/g, (_, a, b) => `<code>${a ?? b}</code>`);
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  return s;
}

function renderMarkdown(md) {
  const lines = md.split("\n");
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^#{1,3} /.test(line)) {
      const level = line.match(/^#+/)[0].length;
      out.push(`<h${level}>${inline(line.slice(level + 1))}</h${level}>`);
      i++;
    } else if (line.startsWith("|")) {
      const rows = [];
      while (i < lines.length && lines[i].startsWith("|")) { rows.push(lines[i]); i++; }
      const cells = (r) => r.replace(/^\||\|$/g, "").split(/(?<!\\)\|/).map((c) => inline(c.trim().replace(/\\\|/g, "|")));
      const body = rows.filter((r) => !/^\|(\s*:?-+:?\s*\|)+$/.test(r));
      const head = cells(body.shift() || "");
      const headHtml = head.some((c) => c) ? `<thead><tr>${head.map((c) => `<th>${c}</th>`).join("")}</tr></thead>` : "";
      out.push(`<table>${headHtml}<tbody>${body.map((r) => `<tr>${cells(r).map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>`);
    } else if (/^- /.test(line)) {
      const items = [];
      while (i < lines.length && /^- /.test(lines[i])) { items.push(`<li>${inline(lines[i].slice(2))}</li>`); i++; }
      out.push(`<ul>${items.join("")}</ul>`);
    } else if (line.startsWith("> ")) {
      out.push(`<blockquote>${inline(line.slice(2))}</blockquote>`);
      i++;
    } else if (line.trim()) {
      out.push(`<p>${inline(line)}</p>`);
      i++;
    } else i++;
  }
  return out.join("\n");
}

boot().catch((err) => { if (err.message !== "auth") { show("new-job"); } });
