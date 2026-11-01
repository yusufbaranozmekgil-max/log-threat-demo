"use strict";

const PY_FILES = [
  "logdetect/__init__.py", "logdetect/models.py", "logdetect/parsers.py",
  "logdetect/rules.py", "logdetect/engine.py", "logdetect/reports.py",
  "rules/ssh.yml", "rules/web.yml", "demo.py",
];
const SAMPLE_YEAR = 2026;
const MAX_LINES = 200000;
const SWEEP_MS = 1500;

const $ = (id) => document.getElementById(id);
const els = {
  form: $("controls"), run: $("run"), status: $("status"), paste: $("paste"), own: $("own-log"),
  canvas: $("drum"), range: $("drum-range"), scale: $("drum-scale"), tally: $("tally"),
  ledger: $("ledger"), rev: $("rev"),
};
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const state = { pyodide: null, result: null, selected: -1, sweep: 1, samples: {} };

function setStatus(html, isError = false) {
  els.status.innerHTML = html;
  els.status.classList.toggle("error", isError);
}

function source() {
  return els.form.elements.source.value;
}

/* Runtime */

async function boot() {
  try {
    const [pyodide] = await Promise.all([
      loadPyodide({ indexURL: "https://cdn.jsdelivr.net/pyodide/v0.27.2/full/" }),
      fetch("py/SOURCE_REV").then((r) => (r.ok ? r.text() : "")).then((t) => { els.rev.textContent = t.trim() || "unknown"; }),
    ]);
    await pyodide.loadPackage("pyyaml");
    pyodide.FS.mkdirTree("/demo/logdetect");
    pyodide.FS.mkdirTree("/demo/rules");
    const files = await Promise.all(PY_FILES.map(async (path) => {
      const response = await fetch(`py/${path}`);
      if (!response.ok) throw new Error(`could not load ${path}`);
      return [path, await response.text()];
    }));
    for (const [path, text] of files) pyodide.FS.writeFile(`/demo/${path}`, text);
    pyodide.runPython("import sys; sys.path.insert(0, '/demo'); import demo");
    state.pyodide = pyodide;
    els.run.disabled = false;
    await scan();
  } catch (error) {
    setStatus(`The Python runtime could not load (${escapeText(error.message)}). Check your connection and reload the page.`, true);
  }
}

async function sampleText(name) {
  if (!state.samples[name]) {
    const response = await fetch(`samples/${name}.log`);
    if (!response.ok) throw new Error(`sample ${name} is missing`);
    state.samples[name] = await response.text();
  }
  return state.samples[name];
}

async function scan() {
  if (!state.pyodide) return;
  const which = source();
  let text;
  let year = SAMPLE_YEAR;
  if (which === "own") {
    text = els.own.value;
    year = new Date().getFullYear();
    if (!text.trim()) {
      setStatus("Paste some log lines first, then run the scan.");
      els.own.focus();
      return;
    }
  } else {
    text = await sampleText(which);
  }
  const lines = text.split("\n");
  if (lines.length > MAX_LINES) {
    text = lines.slice(0, MAX_LINES).join("\n");
  }
  els.run.disabled = true;
  setStatus("Scanning in your browser…");
  await new Promise(requestAnimationFrame);
  try {
    const started = performance.now();
    const run = state.pyodide.globals.get("demo").run;
    state.result = JSON.parse(run(text, year));
    const seconds = (performance.now() - started) / 1000;
    const s = state.result.stats;
    const cut = lines.length > MAX_LINES ? ` First ${MAX_LINES.toLocaleString("en")} lines only.` : "";
    setStatus(
      `Scanned <strong>${s.lines.toLocaleString("en")}</strong> lines in ${seconds.toFixed(2)} s with ${state.result.rules} rules, inside this tab. ` +
      `${s.events.toLocaleString("en")} events, ${s.ignored.toLocaleString("en")} ignored, ${s.malformed.toLocaleString("en")} malformed.${cut} Nothing left your browser.`,
    );
    state.selected = -1;
    renderLedger();
    record();
  } catch (error) {
    setStatus(`The scan failed: ${escapeText(String(error.message).split("\n").filter(Boolean).pop())}`, true);
  } finally {
    els.run.disabled = false;
  }
}

/* Drum */

function clock(seconds) {
  return new Date(seconds * 1000).toISOString().slice(11, 19);
}

function day(seconds) {
  return new Date(seconds * 1000).toISOString().slice(0, 10);
}

function seeded(n) {
  const x = Math.sin(n * 12.9898) * 43758.5453;
  return x - Math.floor(x);
}

// Group findings that start at the same spot so they share one label. Lanes count upward from
// the trace. Labels that fit to the right of their mark are placed right to left, so a dropline
// only ever passes labels that start to its right. Labels squeezed against the right edge end at
// their mark instead, and take the lanes above everything else so no dropline runs through them.
function layoutBrackets(findings, xOf, right, measure) {
  const order = findings.map((f, i) => i).sort((a, b) => findings[a].first - findings[b].first);
  const groups = [];
  for (const i of order) {
    const x1 = xOf(findings[i].first);
    const last = groups[groups.length - 1];
    if (last && Math.abs(last.x1 - x1) <= 4) last.members.push(i);
    else groups.push({ x1, members: [i] });
  }
  for (const g of groups) {
    g.label = [...new Set(g.members.map((i) => findings[i].attack))].join(" · ");
    const w = measure(g.label);
    g.squeezed = g.x1 + 4 + w > right;
    g.labelX = g.squeezed ? Math.max(g.x1 + 1 - w, 0) : g.x1 + 4;
    g.start = Math.min(g.x1, g.labelX) - 6;
    g.end = g.labelX + w + 6;
  }
  const placedGroups = [];
  const clashes = (g, lane) => placedGroups.some((o) =>
    (o.lane === lane && g.start < o.end && g.end > o.start) ||
    (o.lane > lane && o.x1 > g.start && o.x1 < g.end) ||
    (o.lane < lane && g.x1 > o.start && g.x1 < o.end));
  const place = (g, from) => {
    let lane = from;
    while (lane < from + 12 && clashes(g, lane)) lane++;
    g.lane = lane;
    placedGroups.push(g);
  };
  for (const g of [...groups].reverse().filter((g) => !g.squeezed)) place(g, 0);
  const top = placedGroups.reduce((m, g) => Math.max(m, g.lane + 1), 0);
  for (const g of groups.filter((g) => g.squeezed)) place(g, top);
  const placed = new Array(findings.length);
  for (const g of groups) {
    for (const i of g.members) {
      placed[i] = { x1: g.x1, x2: Math.max(xOf(findings[i].last), g.x1 + 8), lane: g.lane, group: g };
    }
  }
  return { placed, groups };
}

const grainCache = { key: "", canvas: null };

// Soot on drum paper: fine grain plus faint streaks where the drum turned under the stylus.
function sootGrain(width, height, dpr) {
  const key = `${width}x${height}@${dpr}`;
  if (grainCache.key === key) return grainCache.canvas;
  const canvas = document.createElement("canvas");
  canvas.width = Math.round(width * dpr);
  canvas.height = Math.round(height * dpr);
  const ctx = canvas.getContext("2d");
  const image = ctx.createImageData(canvas.width, canvas.height);
  const data = image.data;
  const streak = new Float32Array(canvas.height);
  for (let y = 0; y < canvas.height; y++) streak[y] = (seeded(y * 0.37 + 11) - 0.5) * 7;
  for (let y = 0; y < canvas.height; y++) {
    for (let x = 0; x < canvas.width; x++) {
      const n = (seeded(x * 1.7 + y * 913.1) - 0.5) * 16 + streak[y];
      const speck = seeded(x * 3.1 + y * 77.7) > 0.9975 ? 26 : 0;
      const o = (y * canvas.width + x) * 4;
      data[o] = 22 + n + speck;
      data[o + 1] = 20 + n + speck;
      data[o + 2] = 16 + n * 0.8 + speck;
      data[o + 3] = 255;
    }
  }
  ctx.putImageData(image, 0, 0);
  grainCache.key = key;
  grainCache.canvas = canvas;
  return canvas;
}

function draw() {
  const canvas = els.canvas;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  if (canvas.width !== Math.round(width * dpr) || canvas.height !== Math.round(height * dpr)) {
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
  }
  const ctx = canvas.getContext("2d");
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.drawImage(sootGrain(width, height, dpr), 0, 0);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  const css = getComputedStyle(document.documentElement);
  const color = (name) => css.getPropertyValue(name).trim();
  const mono = color("--mono");
  const result = state.result;
  const trace = result && result.trace;
  const pad = 14;
  const laneHeight = 22;
  const bracketsTop = 22;
  const axisLane = 26;

  const findings = result ? result.findings : [];
  const start = trace ? trace.start : 0;
  const end = trace ? trace.end : 1;
  const span = Math.max(end - start, 1);
  const xOf = (t) => pad + ((t - start) / span) * (width - 2 * pad);
  ctx.font = `650 11.5px ${mono}`;
  const layout = trace
    ? layoutBrackets(findings, xOf, width - pad, (text) => ctx.measureText(text).width)
    : { placed: [], groups: [] };
  const { placed, groups } = layout;
  const lanes = groups.reduce((m, g) => Math.max(m, g.lane + 1), 0);
  const plotTop = bracketsTop + lanes * laneHeight + 14;
  const laneY = (lane) => bracketsTop + (lanes - 1 - lane) * laneHeight;
  const plotBottom = height - axisLane;
  const baseline = Math.round((plotTop + plotBottom) / 2) + 0.5;
  const amplitude = (plotBottom - plotTop) / 2 - 4;
  const clampY = (y) => Math.max(plotTop + 2, Math.min(plotBottom - 2, y));

  // Time is carried by the record itself: faint ticks along the baseline, minutes along the edge.
  const columns = Math.max(4, Math.round(width / 110));
  ctx.font = `500 10.5px ${mono}`;
  for (let i = 0; i <= columns * 4; i++) {
    const x = Math.round(pad + ((width - 2 * pad) / (columns * 4)) * i) + 0.5;
    const major = i % 4 === 0;
    ctx.strokeStyle = major ? color("--grid-strong") : color("--grid");
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(x, baseline - (major ? 5 : 2));
    ctx.lineTo(x, baseline + (major ? 5 : 2));
    ctx.moveTo(x, plotBottom + 2);
    ctx.lineTo(x, plotBottom + (major ? 8 : 4));
    ctx.stroke();
    if (trace && major && i < columns * 4) {
      ctx.fillStyle = color("--ink-faint");
      ctx.fillText(clock(start + (span / columns) * (i / 4)).slice(0, 5), x + 3, height - 6);
    }
  }

  if (!trace) {
    ctx.strokeStyle = color("--grid-strong");
    ctx.lineWidth = 1.25;
    ctx.beginPath(); ctx.moveTo(pad, baseline); ctx.lineTo(width - pad, baseline); ctx.stroke();
    return;
  }

  const counts = trace.counts;
  const peak = Math.max(...counts, 1);
  const sweepX = pad + (width - 2 * pad) * state.sweep;
  const sel = state.selected >= 0 ? placed[state.selected] : null;
  const steps = Math.floor(width - 2 * pad);
  const points = [];
  for (let i = 0; i <= steps; i++) {
    const bucket = Math.min(counts.length - 1, Math.floor((i / steps) * counts.length));
    // Near-linear scale: routine traffic stays a low murmur, bursts tear the trace.
    const level = Math.pow(counts[bucket] / peak, 1.35);
    const wobble = (seeded(i) - 0.5) * 2;
    points.push([pad + i, clampY(baseline - wobble * (1.2 + level * amplitude) * (i % 2 === 0 ? 1 : -0.85))]);
  }

  // The stylus lifts soot unevenly, so every segment gets its own width and brightness.
  const scratch = (alpha, from = pad, to = sweepX) => {
    ctx.lineCap = "round";
    for (let i = 1; i < points.length; i++) {
      const [x, y] = points[i];
      if (x > to) break;
      if (x < from) continue;
      const [px, py] = points[i - 1];
      ctx.globalAlpha = alpha * (0.62 + seeded(i * 5.3 + 2) * 0.38);
      ctx.lineWidth = 0.7 + seeded(i * 2.9 + 7) * 0.9;
      ctx.beginPath(); ctx.moveTo(px, py); ctx.lineTo(x, y); ctx.stroke();
    }
    ctx.globalAlpha = 1;
  };

  ctx.strokeStyle = color("--trace");
  scratch(sel ? 0.22 : 1);

  if (sel) {
    ctx.fillStyle = "rgba(224, 86, 59, 0.09)";
    ctx.fillRect(sel.x1 - 3, plotTop, sel.x2 - sel.x1 + 6, plotBottom - plotTop);
    ctx.strokeStyle = color("--trace");
    scratch(1, sel.x1 - 3, Math.min(sel.x2 + 3, sweepX));
  }

  // Stylus head while recording.
  if (state.sweep < 1) {
    ctx.strokeStyle = color("--brass");
    ctx.lineWidth = 2;
    ctx.beginPath(); ctx.moveTo(sweepX, plotTop - 6); ctx.lineTo(sweepX, plotBottom); ctx.stroke();
  }

  // Readings inked onto the drum: a ruled bracket, a dropline into the trace, and the window
  // underlined on the paper itself.
  placed.forEach((p, i) => {
    if (p.x1 > sweepX) return;
    const y = laneY(p.lane) + 8;
    const dim = sel && sel !== p;
    ctx.globalAlpha = dim ? 0.28 : 1;
    ctx.strokeStyle = color("--vermilion");
    ctx.lineWidth = sel === p ? 2 : 1.4;
    ctx.beginPath();
    ctx.moveTo(p.x1, y + 6); ctx.lineTo(p.x1, y); ctx.lineTo(p.x2, y); ctx.lineTo(p.x2, y + 6);
    ctx.stroke();
    ctx.setLineDash([2, 3]);
    ctx.lineWidth = 1;
    ctx.globalAlpha = dim ? 0.18 : 0.7;
    ctx.beginPath(); ctx.moveTo(p.x1 + 0.5, y + 6); ctx.lineTo(p.x1 + 0.5, plotBottom - 6); ctx.stroke();
    ctx.setLineDash([]);
    ctx.globalAlpha = dim ? 0.28 : 1;
    ctx.lineWidth = sel === p ? 3 : 2;
    ctx.beginPath(); ctx.moveTo(p.x1, plotBottom - 4); ctx.lineTo(p.x2, plotBottom - 4); ctx.stroke();
    ctx.globalAlpha = 1;
  });

  ctx.font = `650 11.5px ${mono}`;
  for (const g of groups) {
    if (g.x1 > sweepX) continue;
    const selected = sel && sel.group === g;
    ctx.globalAlpha = sel && !selected ? 0.32 : 1;
    ctx.fillStyle = color("--vermilion-soft");
    ctx.fillText(g.label, g.labelX, laneY(g.lane) + 3);
    ctx.globalAlpha = 1;
  }
}

function record() {
  const result = state.result;
  const trace = result.trace;
  els.range.textContent = trace ? `${day(trace.start)}  ${clock(trace.start)} to ${clock(trace.end)} UTC` : "No events recognised";
  els.scale.textContent = trace ? `peak ${Math.max(...trace.counts).toLocaleString("en")} events per interval` : "";
  const label = trace
    ? `Recording from ${clock(trace.start)} to ${clock(trace.end)} UTC with ${result.findings.length} findings marked.`
    : "No events recognised in this log.";
  els.canvas.setAttribute("aria-label", label);

  if (reduceMotion.matches || !trace) {
    state.sweep = 1;
    draw();
    return;
  }
  const begun = performance.now();
  const step = (now) => {
    const t = Math.min((now - begun) / SWEEP_MS, 1);
    state.sweep = 1 - Math.pow(1 - t, 3);
    draw();
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

/* Ledger */

function escapeText(value) {
  const span = document.createElement("span");
  span.textContent = value;
  return span.innerHTML;
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function attackUrl(id) {
  return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}

function renderLedger() {
  const { findings, stats } = state.result;
  els.ledger.replaceChildren();
  const bySeverity = findings.reduce((m, f) => ({ ...m, [f.severity]: (m[f.severity] || 0) + 1 }), {});
  const parts = ["critical", "high", "medium", "low"].filter((s) => bySeverity[s]).map((s) => `${bySeverity[s]} ${s}`);
  els.tally.textContent = findings.length
    ? `${findings.length} findings: ${parts.join(", ")}.`
    : stats.events ? "No findings in this log." : "No lines matched a supported log format.";

  if (!findings.length) {
    els.ledger.append(el("li", "empty", stats.events
      ? "The recording stayed quiet: no rule fired on these lines."
      : "Nothing was recognised. Supported formats are OpenSSH auth.log lines and nginx or Apache combined access log lines."));
    return;
  }

  findings.forEach((f, i) => {
    const item = el("li");
    const button = el("button", "reading");
    button.type = "button";
    button.setAttribute("aria-expanded", "false");
    const panelId = `evidence-${i}`;
    button.setAttribute("aria-controls", panelId);

    const sameDay = day(f.first) === day(f.last);
    button.append(
      el("span", "when", f.first === f.last ? clock(f.first) : `${clock(f.first)}–${sameDay ? clock(f.last) : day(f.last)}`),
      el("span", `sev sev-${f.severity}`, f.severity.toUpperCase()),
    );
    const what = el("span", "what", f.title);
    what.append(el("small", null, f.rule));
    button.append(what, el("span", "tech", f.attack), el("span", "key", f.key));

    const panel = el("div", "evidence");
    panel.id = panelId;
    panel.hidden = true;
    panel.append(el("pre", null, f.evidence.join("\n")));
    const more = f.suppressed ? ` ${f.suppressed} more matching events followed inside the window and are counted, not shown.` : "";
    const note = el("p");
    note.append(document.createTextNode(`Evidence lines as logged.${more} `));
    const link = el("a", null, `About ${f.attack} on MITRE ATT&CK`);
    link.href = attackUrl(f.attack);
    link.rel = "noopener";
    link.target = "_blank";
    note.append(link);
    panel.append(note);

    button.addEventListener("click", () => {
      const open = button.getAttribute("aria-expanded") === "true";
      els.ledger.querySelectorAll(".reading").forEach((b) => b.setAttribute("aria-expanded", "false"));
      els.ledger.querySelectorAll(".evidence").forEach((p) => { p.hidden = true; });
      button.setAttribute("aria-expanded", String(!open));
      panel.hidden = open;
      state.selected = open ? -1 : i;
      draw();
    });

    item.append(button, panel);
    els.ledger.append(item);
  });
}

/* Wiring */

els.form.addEventListener("submit", (event) => {
  event.preventDefault();
  scan();
});

els.form.addEventListener("change", () => {
  const own = source() === "own";
  els.paste.hidden = !own;
  if (own) els.own.focus();
  else scan();
});

let resizeFrame = 0;
window.addEventListener("resize", () => {
  cancelAnimationFrame(resizeFrame);
  resizeFrame = requestAnimationFrame(draw);
});

document.fonts.ready.then(draw);
draw();
boot();
