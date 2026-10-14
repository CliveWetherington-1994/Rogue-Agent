// Rogue Agent desktop front end. No framework: one module, plain DOM.

const $ = (id) => document.getElementById(id);

const token = new URLSearchParams(location.hash.slice(1)).get("token") ?? "";
history.replaceState(null, "", location.pathname);

const native = typeof window.ipc?.postMessage === "function";
const pendingNative = new Map();
let nativeRequest = 0;

const ui = {
  server: null,
  functions: [],
  functionByAddress: new Map(),
  functionByName: new Map(),
  strings: null,
  imports: null,
  list: "functions",
  rows: [],
  filter: "",
  regex: false,
  selected: null,
  view: "code",
  current: null,
  history: [],
  historyIndex: -1,
  requestSerial: 0,
  environment: null,
};

// ---------------------------------------------------------------- utilities

class ApiError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    method: options.body === undefined ? "GET" : "POST",
    headers: {
      "x-rogue-token": token,
      ...(options.body === undefined
        ? {}
        : { "content-type": "application/json" }),
    },
    ...(options.body === undefined
      ? {}
      : { body: JSON.stringify(options.body) }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok)
    throw new ApiError(
      payload.error?.code ?? String(response.status),
      payload.error?.message ?? response.statusText,
    );
  return payload;
}

const escapeHtml = (value) =>
  value.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );

let toastTimer;
function toast(message) {
  const element = $("toast");
  element.textContent = message;
  element.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.add("hidden"), 4000);
}

function setStatus(message) {
  $("status-text").textContent = message;
}

function setProgress(percent) {
  const bar = $("progress");
  if (percent === undefined) {
    bar.classList.add("hidden");
    return;
  }
  bar.classList.remove("hidden");
  bar.classList.toggle("indeterminate", percent === null);
  $("progress-bar").style.width =
    percent === null ? "30%" : `${Math.max(2, percent)}%`;
}

const formatMs = (ms) =>
  ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;

// ------------------------------------------------------ native window bridge

window.__rogueIpcReply = (message) => {
  const resolve = pendingNative.get(message.requestId);
  if (resolve === undefined) return;
  pendingNative.delete(message.requestId);
  resolve(message.path ?? null);
};

window.__rogueOpenPath = (path) => {
  if (typeof path === "string" && path.length > 0) void openPath(path);
};

async function pickFile(mode, suggested) {
  if (native) {
    const requestId = ++nativeRequest;
    return new Promise((resolve) => {
      pendingNative.set(requestId, resolve);
      window.ipc.postMessage(
        JSON.stringify({ type: "pick", mode, requestId, suggested }),
      );
    });
  }
  const { path } = await api("/api/pick-file", {
    body: { mode, ...(suggested ? { suggested } : {}) },
  });
  return path;
}

// ------------------------------------------------------------- state render

function renderServerState(state) {
  const previousPhase = ui.server?.phase;
  ui.server = state;
  const pill = $("status-pill");
  const labels = {
    idle: "Idle",
    opening: "Opening",
    analyzing: "Analyzing",
    ready: "Ready",
    error: "Error",
  };
  pill.textContent = labels[state.phase] ?? state.phase;
  pill.className = `pill ${
    state.phase === "ready"
      ? "pill-ready"
      : state.phase === "error"
        ? "pill-error"
        : state.phase === "idle"
          ? "pill-idle"
          : "pill-busy"
  }`;
  const path = state.target?.path;
  if (path === undefined) $("target").textContent = "No file open";
  else {
    const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
    $("target").innerHTML =
      `<strong>${escapeHtml(path.slice(cut + 1))}</strong> <span class="muted">${escapeHtml(cut > 0 ? path.slice(0, cut) : "")}</span>`;
  }
  $("target").title = state.target
    ? `${state.target.path}\nsha256 ${state.target.sha256}\n${state.target.format} ${state.target.architecture ?? ""}`
    : "";
  const busy = state.phase === "opening" || state.phase === "analyzing";
  $("export-button").disabled = state.phase !== "ready";
  $("workspace").classList.toggle(
    "hidden",
    state.phase === "idle" ||
      (state.phase === "error" && state.target === null),
  );
  $("welcome").classList.toggle(
    "hidden",
    !$("workspace").classList.contains("hidden"),
  );
  if (busy) {
    setStatus(
      state.progress?.message ??
        (state.phase === "opening" ? "Opening…" : "Analyzing…"),
    );
    setProgress(state.progress?.percent ?? null);
    if (ui.selected === null)
      showPlaceholder(
        state.phase === "analyzing"
          ? "Ghidra is importing and auto-analyzing the binary. Large programs can take a few minutes the first time."
          : "Opening…",
      );
  } else setProgress(undefined);
  if (state.phase === "error") {
    setStatus(`Error: ${state.error?.message ?? "unknown"}`);
    if (state.target === null) renderWelcome();
    else showPlaceholder(state.error?.message ?? "Analysis failed");
    toast(state.error?.message ?? "Analysis failed");
  }
  if (state.phase === "ready" && previousPhase !== "ready") void onReady();
  if (state.phase === "idle") renderWelcome();
}

async function onReady() {
  const timing = ui.server.timings.analysisMs;
  setStatus(
    `${ui.server.functionCount ?? 0} functions · analysis ${timing === null ? "" : formatMs(timing)}`,
  );
  const { functions } = await api("/api/functions");
  ui.functions = functions;
  ui.functionByAddress = new Map(functions.map((f) => [f.address, f]));
  ui.functionByName = new Map();
  for (const f of functions) {
    ui.functionByName.set(f.name, f);
    const short = f.name.split("::").pop();
    if (!ui.functionByName.has(short)) ui.functionByName.set(short, f);
  }
  ui.strings = null;
  ui.imports = null;
  $("count-functions").textContent = String(functions.length);
  $("count-strings").textContent = "";
  $("count-imports").textContent = "";
  selectList("functions");
  const entry =
    functions.find((f) =>
      /^(main|wmain|WinMain|wWinMain|_main|DllMain)$/.test(
        f.name.split("::").pop(),
      ),
    ) ??
    functions.find((f) => /^entry$/i.test(f.name)) ??
    functions.find((f) => !f.external);
  if (entry && ui.selected === null) void navigate(entry.address);
}

// ------------------------------------------------------------ list (left)

const ROW = 26;

function selectList(kind) {
  ui.list = kind;
  for (const tab of document.querySelectorAll(".sidebar .tab"))
    tab.classList.toggle("active", tab.dataset.list === kind);
  $("filter").placeholder =
    kind === "functions"
      ? "Filter functions (Ctrl+F)"
      : kind === "strings"
        ? "Filter strings"
        : "Filter imports";
  void loadList(kind);
}

async function loadList(kind) {
  try {
    if (kind === "strings" && ui.strings === null) {
      setStatus("Loading strings…");
      ui.strings = (await api("/api/strings")).strings;
      $("count-strings").textContent = String(ui.strings.length);
      setStatus(`${ui.strings.length} strings`);
    }
    if (kind === "imports" && ui.imports === null) {
      setStatus("Loading imports…");
      ui.imports = (await api("/api/imports")).imports;
      $("count-imports").textContent = String(ui.imports.length);
      setStatus(`${ui.imports.length} imports`);
    }
  } catch (error) {
    toast(error.message);
  }
  applyFilter();
}

function sourceRows() {
  if (ui.list === "strings")
    return (ui.strings ?? []).map((s) => ({
      address: s.address,
      label: s.value,
      kind: "string",
    }));
  if (ui.list === "imports")
    return (ui.imports ?? []).map((s) => ({
      address: s.address,
      label: s.name,
      kind: "import",
    }));
  return ui.functions.map((f) => ({
    address: f.address,
    label: f.name,
    kind: "function",
    external: f.external,
    thunk: f.thunk,
  }));
}

function applyFilter() {
  const all = sourceRows();
  const query = ui.filter.trim();
  let match = () => true;
  if (query !== "") {
    if (ui.regex) {
      try {
        const pattern = new RegExp(query, "i");
        match = (row) => pattern.test(row.label) || pattern.test(row.address);
      } catch {
        match = () => false;
      }
    } else {
      const needle = query.toLowerCase();
      match = (row) =>
        row.label.toLowerCase().includes(needle) ||
        row.address.toLowerCase().includes(needle);
    }
  }
  ui.rows = all.filter(match);
  $("list-spacer").style.height = `${ui.rows.length * ROW}px`;
  $("list").scrollTop = 0;
  renderRows();
}

function renderRows() {
  const list = $("list");
  const first = Math.max(0, Math.floor(list.scrollTop / ROW) - 10);
  const count = Math.ceil(list.clientHeight / ROW) + 20;
  const slice = ui.rows.slice(first, first + count);
  const container = $("list-rows");
  container.style.transform = `translateY(${first * ROW}px)`;
  container.innerHTML = slice
    .map((row) => {
      const tags = row.external
        ? '<span class="tag">ext</span>'
        : row.thunk
          ? '<span class="tag">thunk</span>'
          : "";
      const selected =
        row.kind === "function" && row.address === ui.selected
          ? " selected"
          : "";
      return `<div class="row-item${selected}" data-address="${escapeHtml(row.address)}" data-kind="${row.kind}" title="${escapeHtml(row.label)}">
        <span class="name">${escapeHtml(row.label)}</span>${tags}<span class="addr">${escapeHtml(row.address)}</span></div>`;
    })
    .join("");
}

$("list").addEventListener("scroll", () => requestAnimationFrame(renderRows), {
  passive: true,
});
$("list-rows").addEventListener("click", (event) => {
  const row = event.target.closest(".row-item");
  if (row === null) return;
  if (row.dataset.kind === "function") void navigate(row.dataset.address);
  else void showUsages(row.dataset.address, row.title);
});
$("list").addEventListener("keydown", (event) => {
  if (
    ui.list !== "functions" ||
    (event.key !== "ArrowDown" && event.key !== "ArrowUp")
  )
    return;
  event.preventDefault();
  const index = ui.rows.findIndex((row) => row.address === ui.selected);
  const next =
    ui.rows[
      Math.min(
        ui.rows.length - 1,
        Math.max(0, index + (event.key === "ArrowDown" ? 1 : -1)),
      )
    ];
  if (next) {
    void navigate(next.address);
    const top = ui.rows.indexOf(next) * ROW;
    const list = $("list");
    if (top < list.scrollTop) list.scrollTop = top;
    else if (top + ROW > list.scrollTop + list.clientHeight)
      list.scrollTop = top + ROW - list.clientHeight;
  }
});

let filterTimer;
$("filter").addEventListener("input", (event) => {
  ui.filter = event.target.value;
  clearTimeout(filterTimer);
  filterTimer = setTimeout(applyFilter, 80);
});
$("filter-regex").addEventListener("change", (event) => {
  ui.regex = event.target.checked;
  applyFilter();
});
for (const tab of document.querySelectorAll(".sidebar .tab"))
  tab.addEventListener("click", () => selectList(tab.dataset.list));

// ---------------------------------------------------- code highlighting

const C_KEYWORDS = new Set(
  "if else while for do return break continue switch case default goto sizeof struct union enum typedef const volatile static extern register inline true false NULL".split(
    " ",
  ),
);
const C_TYPES = new Set(
  "void char short int long float double signed unsigned bool byte ushort uint ulong uchar longlong ulonglong undefined undefined1 undefined2 undefined4 undefined8 code size_t wchar_t wchar16 string float10 dword word qword BOOL DWORD WORD BYTE HANDLE LPVOID LPCSTR LPSTR LPCWSTR LPWSTR HMODULE HINSTANCE UINT ULONG LONG int8_t int16_t int32_t int64_t uint8_t uint16_t uint32_t uint64_t".split(
    " ",
  ),
);
const TOKEN =
  /(\/\*[\s\S]*?\*\/|\/\/[^\n]*)|("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')|(\b0x[0-9a-fA-F]+\b|\b\d+(?:\.\d+)?[uUlLfF]*\b)|([A-Za-z_$][\w$]*(?:::[A-Za-z_$][\w$]*)*)/g;

function highlight(source, mode) {
  let html = "";
  let last = 0;
  for (const match of source.matchAll(TOKEN)) {
    html += escapeHtml(source.slice(last, match.index));
    last = match.index + match[0].length;
    const [text, comment, string, number, identifier] = match;
    if (comment !== undefined)
      html += `<span class="co">${escapeHtml(text)}</span>`;
    else if (string !== undefined)
      html += `<span class="st">${escapeHtml(text)}</span>`;
    else if (number !== undefined)
      html +=
        mode === "c" ? `<span class="nu">${text}</span>` : escapeHtml(text);
    else if (identifier !== undefined) {
      const target = ui.functionByName.get(identifier);
      if (target !== undefined && target.address !== ui.selected)
        html += `<a class="fn" data-address="${escapeHtml(target.address)}">${escapeHtml(text)}</a>`;
      else if (mode === "c" && C_KEYWORDS.has(identifier))
        html += `<span class="kw">${text}</span>`;
      else if (mode === "c" && C_TYPES.has(identifier))
        html += `<span class="ty">${text}</span>`;
      else html += escapeHtml(text);
    }
  }
  return html + escapeHtml(source.slice(last));
}

$("code").addEventListener("click", (event) => {
  const link = event.target.closest("a.fn");
  if (link !== null) void navigate(link.dataset.address);
});

// ------------------------------------------------------------- viewer

function showPlaceholder(message) {
  $("code").innerHTML =
    `<span class="placeholder">${escapeHtml(message)}</span>`;
  $("copy-button").disabled = true;
}

function renderInfo(info) {
  const lines = [];
  const add = (label, value) => {
    if (value !== undefined && value !== null && value !== "")
      lines.push(`${label.padEnd(18)} ${value}`);
  };
  add("Name", info.name);
  add("Entry", info.entrypoint ?? info.address);
  add("Signature", info.signature);
  add("Length", info.length === undefined ? undefined : `${info.length} bytes`);
  add("Basic blocks", info.basicblock_count);
  if (info.classification)
    add(
      "Classification",
      Object.entries(info.classification)
        .filter(([, v]) => v === true)
        .map(([k]) => k)
        .join(", ") || "internal",
    );
  if (Array.isArray(info.locals) && info.locals.length > 0) {
    lines.push("", "Locals");
    for (const local of info.locals)
      lines.push(
        `  ${String(local.name ?? "").padEnd(24)} ${local.type ?? ""} ${local.storage ?? ""}`,
      );
  }
  return lines.join("\n");
}

async function renderView() {
  const current = ui.current;
  if (current === null) return;
  const serial = ui.requestSerial;
  const code = $("code");
  try {
    if (ui.view === "code") {
      if (current.pseudocode === undefined) return;
      code.innerHTML =
        current.pseudocode === null
          ? '<span class="placeholder">No body to decompile (external or imported function).</span>'
          : highlight(current.pseudocode, "c");
      $("copy-button").disabled = current.pseudocode === null;
      return;
    }
    if (ui.view === "asm") {
      if (current.asm === undefined) {
        showPlaceholder("Loading assembly…");
        current.asm = (
          await api(
            `/api/disassembly?fn=${encodeURIComponent(current.address)}`,
          )
        ).text;
        if (serial !== ui.requestSerial || ui.view !== "asm") return;
      }
      code.innerHTML = highlight(current.asm, "asm");
      $("copy-button").disabled = false;
      return;
    }
    if (current.info === undefined) {
      showPlaceholder("Loading…");
      current.info = (
        await api(`/api/info?fn=${encodeURIComponent(current.address)}`)
      ).info;
      if (serial !== ui.requestSerial || ui.view !== "info") return;
    }
    code.textContent = renderInfo(current.info);
    $("copy-button").disabled = false;
  } catch (error) {
    if (serial === ui.requestSerial) showPlaceholder(error.message);
  }
}

for (const tab of document.querySelectorAll(".viewer .tab"))
  tab.addEventListener("click", () => {
    ui.view = tab.dataset.view;
    for (const other of document.querySelectorAll(".viewer .tab"))
      other.classList.toggle("active", other === tab);
    void renderView();
  });

$("copy-button").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("code").textContent ?? "");
  toast("Copied");
});

function renderLinks(listId, countId, items) {
  $(countId).textContent = items.length === 0 ? "" : String(items.length);
  $(listId).innerHTML =
    items.length === 0
      ? '<li class="external">—</li>'
      : items
          .map(
            (item) =>
              `<li class="${item.external ? "external" : ""}" data-address="${escapeHtml(item.address)}" title="${escapeHtml(`${item.name} @ ${item.address}`)}">${escapeHtml(item.name)}</li>`,
          )
          .join("");
}

for (const id of ["callers", "callees"])
  $(id).addEventListener("click", (event) => {
    const item = event.target.closest("li[data-address]");
    if (item !== null && !item.classList.contains("external"))
      void navigate(item.dataset.address);
  });

async function showUsages(address, label) {
  setStatus(`Finding references to ${label}…`);
  $("callers").innerHTML = '<li class="external">Searching…</li>';
  try {
    const { usages } = await api(
      `/api/usages?addr=${encodeURIComponent(address)}`,
    );
    renderLinks("callers", "count-callers", usages);
    setStatus(
      `${usages.length} functions reference ${label.length > 60 ? `${label.slice(0, 60)}…` : label}`,
    );
  } catch (error) {
    renderLinks("callers", "count-callers", []);
    setStatus(error.message);
  }
}

async function navigate(address, { push = true } = {}) {
  if (ui.server?.phase !== "ready") return;
  const serial = ++ui.requestSerial;
  ui.selected = address;
  if (push) {
    ui.history = ui.history.slice(0, ui.historyIndex + 1);
    if (ui.history[ui.history.length - 1] !== address) ui.history.push(address);
    ui.historyIndex = ui.history.length - 1;
  }
  $("back-button").disabled = ui.historyIndex <= 0;
  $("forward-button").disabled = ui.historyIndex >= ui.history.length - 1;
  const row = ui.functionByAddress.get(address);
  $("function-name").textContent = row?.name ?? address;
  $("function-address").textContent = address;
  ui.current = { address };
  renderRows();
  showPlaceholder("Decompiling…");
  setStatus(`Decompiling ${row?.name ?? address}…`);
  const references = api(
    `/api/references?fn=${encodeURIComponent(address)}`,
  ).catch(() => ({ callers: [], callees: [] }));
  try {
    const result = await api(
      `/api/decompile?fn=${encodeURIComponent(address)}`,
    );
    if (serial !== ui.requestSerial) return;
    ui.current.pseudocode = result.pseudocode;
    setStatus(
      `${row?.name ?? address} · decompiled in ${formatMs(result.elapsedMs)}`,
    );
    void renderView();
  } catch (error) {
    if (serial !== ui.requestSerial) return;
    ui.current.pseudocode = undefined;
    showPlaceholder(error.message);
    setStatus(error.message);
  }
  const { callers, callees } = await references;
  if (serial !== ui.requestSerial) return;
  renderLinks("callers", "count-callers", callers);
  renderLinks("callees", "count-callees", callees);
}

function step(delta) {
  const index = ui.historyIndex + delta;
  if (index < 0 || index >= ui.history.length) return;
  ui.historyIndex = index;
  void navigate(ui.history[index], { push: false });
}
$("back-button").addEventListener("click", () => step(-1));
$("forward-button").addEventListener("click", () => step(1));

// ------------------------------------------------------------- opening

async function openPath(path) {
  ui.selected = null;
  ui.current = null;
  ui.history = [];
  ui.historyIndex = -1;
  ui.functions = [];
  ui.rows = [];
  renderRows();
  renderLinks("callers", "count-callers", []);
  renderLinks("callees", "count-callees", []);
  $("function-name").textContent = "Select a function";
  $("function-address").textContent = "";
  try {
    await api("/api/open", { body: { path } });
  } catch (error) {
    toast(error.message);
    setStatus(error.message);
  }
}

async function chooseAndOpen() {
  try {
    const path = await pickFile("open");
    if (path) await openPath(path);
  } catch (error) {
    toast(error.message);
  }
}

$("open-button").addEventListener("click", chooseAndOpen);
$("welcome-open").addEventListener("click", chooseAndOpen);
$("path-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const path = $("path-input").value.trim();
  if (path) void openPath(path);
});

const dropZone = $("drop-zone");
for (const name of ["dragenter", "dragover"])
  document.addEventListener(name, (event) => {
    event.preventDefault();
    dropZone.classList.add("dragging");
  });
for (const name of ["dragleave", "drop"])
  document.addEventListener(name, (event) => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
  });
document.addEventListener("drop", (event) => {
  // The native window delivers dropped paths through __rogueOpenPath; a plain
  // browser does not expose them, so ask for the path instead.
  if (!native) toast("Paste the file's full path below, or use Open…");
  void event;
});

$("export-button").addEventListener("click", async () => {
  const target = ui.server?.target?.path ?? "program";
  const suggested = `${target.replace(/\.[^.\\/]+$/, "")}.decompiled.c`;
  try {
    const path = await pickFile("save", suggested);
    if (!path) return;
    await api("/api/export", { body: { path } });
    setStatus("Exporting…");
  } catch (error) {
    toast(error.message);
  }
});

// ------------------------------------------------------- welcome & setup

/**
 * Remember a found installation; the bundled one is used without saving its
 * path, so moving or reinstalling the app never leaves it stale.
 */
function rememberFoundTools(settings, ghidra, java) {
  if (
    ghidra.path &&
    settings.ghidraInstallDir === null &&
    !ghidra.entry?.bundled
  )
    void api("/api/settings", {
      body: { ghidraInstallDir: ghidra.path },
    }).catch(() => undefined);
  if (java.path && settings.javaHome === null && !java.entry?.bundled)
    void api("/api/settings", { body: { javaHome: java.path } }).catch(
      () => undefined,
    );
}

/** Setup checks for the Ghidra provider; remembers found (not bundled) tools. */
function ghidraSetupChecks({ settings, ghidra, java }) {
  const ghidraPath = settings.ghidraInstallDir ?? ghidra[0]?.path ?? null;
  const ghidraEntry = ghidra.find((g) => g.path === ghidraPath);
  const javaPath = settings.javaHome ?? java[0]?.path ?? null;
  const javaEntry = java.find((j) => j.path === javaPath);
  const where = (entry, path) =>
    `<span class="muted">${entry?.bundled ? "bundled" : escapeHtml(path)}</span>`;
  const unsupported =
    ghidraEntry && !ghidraEntry.supported
      ? ' <span class="bad">(12.1.x recommended)</span>'
      : "";
  rememberFoundTools(
    settings,
    { path: ghidraPath, entry: ghidraEntry },
    { path: javaPath, entry: javaEntry },
  );
  return [
    ghidraPath
      ? `<div class="check"><span class="ok">✓</span><span>Ghidra ${escapeHtml(ghidraEntry?.version ?? "")} ${where(ghidraEntry, ghidraPath)}${unsupported}</span></div>`
      : '<div class="check"><span class="bad">✗</span><span>Ghidra 12.1 not found. <a href="https://github.com/NationalSecurityAgency/ghidra/releases" target="_blank" rel="noreferrer">Download it</a>, unzip it, then pick the folder in Settings.</span></div>',
    javaPath
      ? `<div class="check"><span class="ok">✓</span><span>JDK ${escapeHtml(javaEntry?.version ?? "")} ${where(javaEntry, javaPath)}</span></div>`
      : '<div class="check"><span class="bad">✗</span><span>JDK 21+ not found. Install <a href="https://adoptium.net/" target="_blank" rel="noreferrer">Temurin 21</a> or set its folder in Settings.</span></div>',
  ];
}

async function renderWelcome() {
  try {
    ui.environment = await api("/api/environment");
  } catch (error) {
    $("setup").innerHTML = `<p class="error">${escapeHtml(error.message)}</p>`;
    return;
  }
  const { settings } = ui.environment;
  $("engine").textContent = `v${ui.environment.version}`;
  const checks =
    settings.provider === "ghidra"
      ? ghidraSetupChecks(ui.environment)
      : [
          `<div class="check"><span class="${settings.idaMcpConfigPath ? "ok" : "bad"}">${settings.idaMcpConfigPath ? "✓" : "✗"}</span><span>IDA via ida-pro-mcp ${escapeHtml(settings.idaMcpConfigPath ?? "— set the configuration file in Settings")}</span></div>`,
        ];
  $("setup").innerHTML = checks.join("");
  $("recent").innerHTML =
    settings.recentFiles.length === 0
      ? ""
      : `<h3>Recent</h3><ul class="link-list">${settings.recentFiles.map((path) => `<li data-path="${escapeHtml(path)}" title="${escapeHtml(path)}">${escapeHtml(path)}</li>`).join("")}</ul>`;
}

$("recent").addEventListener("click", (event) => {
  const item = event.target.closest("li[data-path]");
  if (item !== null) void openPath(item.dataset.path);
});

// ------------------------------------------------------------- settings

async function openSettings() {
  const environment = ui.environment ?? (await api("/api/environment"));
  ui.environment = environment;
  const form = $("settings-form");
  const { settings } = environment;
  form.provider.value = settings.provider;
  // With a bundled tool, an empty field means "use the bundled one".
  const bundledGhidra = environment.ghidra.find((g) => g.bundled);
  const bundledJava = environment.java.find((j) => j.bundled);
  const ghidraChoices = environment.ghidra.filter((g) => !g.bundled);
  const javaChoices = environment.java.filter((j) => !j.bundled);
  form.ghidraInstallDir.value =
    settings.ghidraInstallDir ??
    (bundledGhidra ? "" : (environment.ghidra[0]?.path ?? ""));
  form.ghidraInstallDir.placeholder = bundledGhidra
    ? `Bundled Ghidra ${bundledGhidra.version}`
    : "";
  form.javaHome.value =
    settings.javaHome ?? (bundledJava ? "" : (environment.java[0]?.path ?? ""));
  form.javaHome.placeholder = bundledJava
    ? `Bundled JDK ${bundledJava.version}`
    : "";
  form.idaMcpConfigPath.value = settings.idaMcpConfigPath ?? "";
  form.decompileTimeoutSeconds.value = String(settings.decompileTimeoutSeconds);
  form.prefetchCallees.checked = settings.prefetchCallees;
  form.analysisCache.checked = settings.analysisCache;
  void renderCacheSummary();
  $("ghidra-options").innerHTML = ghidraChoices
    .map(
      (g) =>
        `<option value="${escapeHtml(g.path)}">${escapeHtml(g.version)}</option>`,
    )
    .join("");
  $("java-options").innerHTML = javaChoices
    .map(
      (j) =>
        `<option value="${escapeHtml(j.path)}">${escapeHtml(j.version)}</option>`,
    )
    .join("");
  const hint = (bundled, choices, label, none) =>
    [
      bundled
        ? `Leave empty to use the bundled ${label} ${bundled.version}.`
        : "",
      choices.length === 0
        ? bundled
          ? ""
          : none
        : `Also found ${choices.map((c) => c.version).join(", ")}.`,
    ]
      .filter(Boolean)
      .join(" ");
  $("ghidra-hint").textContent = hint(
    bundledGhidra,
    ghidraChoices,
    "Ghidra",
    "No Ghidra release found automatically.",
  );
  $("java-hint").textContent = hint(
    bundledJava,
    javaChoices,
    "JDK",
    "No JDK 21+ found automatically.",
  );
  $("settings-error").classList.add("hidden");
  $("settings-dialog").showModal();
}

const formatBytes = (bytes) =>
  bytes < 1024 ** 2
    ? `${Math.round(bytes / 1024)} KB`
    : bytes < 1024 ** 3
      ? `${(bytes / 1024 ** 2).toFixed(0)} MB`
      : `${(bytes / 1024 ** 3).toFixed(1)} GB`;

async function renderCacheSummary(cache) {
  try {
    const report = cache ?? (await api("/api/cache")).cache;
    $("cache-summary").textContent =
      `${report.entries} stored ${report.entries === 1 ? "analysis" : "analyses"}, ${formatBytes(report.bytes)}`;
    $("cache-summary").title = report.directory;
  } catch (error) {
    $("cache-summary").textContent = error.message;
  }
}

$("cache-clear").addEventListener("click", async () => {
  try {
    await renderCacheSummary(
      (await api("/api/cache/clear", { body: {} })).cache,
    );
    toast("Stored analyses cleared");
  } catch (error) {
    toast(error.message);
  }
});

$("settings-button").addEventListener(
  "click",
  () => void openSettings().catch((error) => toast(error.message)),
);
$("settings-form").addEventListener("submit", async (event) => {
  if (event.submitter?.value !== "save") return;
  event.preventDefault();
  const form = event.target;
  const optional = (value) => (value.trim() === "" ? null : value.trim());
  try {
    await api("/api/settings", {
      body: {
        provider: form.provider.value,
        ghidraInstallDir: optional(form.ghidraInstallDir.value),
        javaHome: optional(form.javaHome.value),
        idaMcpConfigPath: optional(form.idaMcpConfigPath.value),
        decompileTimeoutSeconds: Number(
          form.decompileTimeoutSeconds.value || 0,
        ),
        prefetchCallees: form.prefetchCallees.checked,
        analysisCache: form.analysisCache.checked,
      },
    });
    $("settings-dialog").close();
    ui.environment = null;
    toast("Settings saved. They apply to the next file you open.");
    if (ui.server?.phase === "idle") void renderWelcome();
  } catch (error) {
    $("settings-error").textContent = error.message;
    $("settings-error").classList.remove("hidden");
  }
});

// ------------------------------------------------------------- keyboard

document.addEventListener("keydown", (event) => {
  const ctrl = event.ctrlKey || event.metaKey;
  if (ctrl && event.key.toLowerCase() === "o") {
    event.preventDefault();
    void chooseAndOpen();
  } else if (
    ctrl &&
    event.key.toLowerCase() === "f" &&
    ui.server?.phase === "ready"
  ) {
    event.preventDefault();
    $("filter").focus();
    $("filter").select();
  } else if (ctrl && event.shiftKey && event.key.toLowerCase() === "e") {
    event.preventDefault();
    $("export-button").click();
  } else if (event.altKey && event.key === "ArrowLeft") {
    event.preventDefault();
    step(-1);
  } else if (event.altKey && event.key === "ArrowRight") {
    event.preventDefault();
    step(1);
  }
});

// ---------------------------------------------------------------- start

void api("/api/environment")
  .then((environment) => {
    ui.environment ??= environment;
    $("engine").textContent = `v${environment.version}`;
    if (native)
      window.ipc.postMessage(
        JSON.stringify({ type: "loaded", version: environment.version }),
      );
  })
  .catch(() => undefined);

const events = new EventSource(
  `/api/events?token=${encodeURIComponent(token)}`,
);
events.addEventListener("state", (event) =>
  renderServerState(JSON.parse(event.data)),
);
events.addEventListener("export", (event) => {
  const progress = JSON.parse(event.data);
  if (progress.running) {
    setProgress(
      progress.total === 0
        ? null
        : Math.round((100 * progress.completed) / progress.total),
    );
    setStatus(`Exporting ${progress.completed}/${progress.total} functions…`);
  } else {
    setProgress(undefined);
    if (progress.error) toast(`Export failed: ${progress.error}`);
    else if (progress.path) {
      setStatus(`Exported ${progress.total} functions to ${progress.path}`);
      toast(`Saved ${progress.path}`);
    }
  }
});
events.addEventListener("error", () =>
  setStatus("Connection to the analysis engine was lost."),
);
