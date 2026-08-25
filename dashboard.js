const statusBar = document.getElementById("statusBar");
const progressEl = document.getElementById("progress");
const resultsEl = document.getElementById("results");
const headerResults = document.getElementById("headerResults");
const scoreEl = document.getElementById("score");
const scanBtn = document.getElementById("scanBtn");
const clearBtn = document.getElementById("clearBtn");
const exportBtn = document.getElementById("exportBtn");
const deleteHistoryBtn = document.getElementById("deleteHistoryBtn");
const historyList = document.getElementById("historyList");
const targetHost = document.getElementById("targetHost");
const targetFav = document.getElementById("targetFav");
const toggleHeadersBtn = document.getElementById("toggleHeaders");
const tabSelect = document.getElementById("tabSelect");
const refreshTabsBtn = document.getElementById("refreshTabsBtn");
let selectedTabId = null;

let currentFindings = [];
let currentFilter = "all";
let lastScanData = null;
let scanning = false;

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function setProgress(msg) {
  if (!msg) {
    progressEl.style.display = "none";
    progressEl.textContent = "";
  } else {
    progressEl.style.display = "block";
    progressEl.textContent = "// " + msg;
  }
}

function setStatus(msg) {
  statusBar.textContent = msg;
}

function showTarget(url, favIconUrl) {
  try {
    const u = new URL(url);
    targetHost.textContent = u.hostname + (u.pathname !== "/" ? u.pathname.slice(0, 60) : "");
    if (favIconUrl) {
      targetFav.src = favIconUrl;
      targetFav.style.display = "block";
    } else if (targetFav.src && targetFav.src.indexOf("chrome-extension") === -1 && targetFav.src.indexOf("google.com/s2") === -1) {
      // keep existing non-google icon if any
    } else {
      targetFav.removeAttribute("src");
      targetFav.style.display = "none";
    }
  } catch (e) {
    targetHost.textContent = url || "No tab selected";
  }
}

function clearResults() {
  lastScanData = null;
  currentFindings = [];
  resultsEl.innerHTML = '<div class="empty-hint">No findings yet</div>';
  headerResults.innerHTML = '<div class="empty-hint">Run a scan to analyze headers</div>';
  scoreEl.textContent = "—";
  scoreEl.className = "stat-value score";
  ["sumHigh", "sumMed", "sumLow", "sumInfo"].forEach(function (id) {
    document.getElementById(id).textContent = "0";
  });
  setProgress(null);
  setStatus("// results cleared — open a site tab and hit Scan");
}

function analyzeHeaders(headerList) {
  const map = {};
  (headerList || []).forEach(function (h) {
    map[h.name.toLowerCase()] = h.value;
  });

  const checks = [
    {
      name: "Content-Security-Policy",
      key: "content-security-policy",
      test: function (v) {
        if (!v) return { status: "missing", note: "Missing" };
        if (v.indexOf("unsafe-inline") !== -1 || v.indexOf("unsafe-eval") !== -1)
          return { status: "weak", note: "unsafe-inline/eval" };
        return { status: "ok", note: "Present" };
      }
    },
    {
      name: "Strict-Transport-Security",
      key: "strict-transport-security",
      test: function (v) {
        if (!v) return { status: "missing", note: "Missing" };
        return { status: "ok", note: "Present" };
      }
    },
    {
      name: "X-Frame-Options",
      key: "x-frame-options",
      test: function (v) {
        if (!v) return { status: "missing", note: "Missing" };
        return { status: "ok", note: v };
      }
    },
    {
      name: "X-Content-Type-Options",
      key: "x-content-type-options",
      test: function (v) {
        if (!v) return { status: "missing", note: "Missing" };
        return { status: "ok", note: v };
      }
    },
    {
      name: "Referrer-Policy",
      key: "referrer-policy",
      test: function (v) {
        if (!v) return { status: "missing", note: "Missing" };
        return { status: "ok", note: v };
      }
    },
    {
      name: "Permissions-Policy",
      key: "permissions-policy",
      test: function (v) {
        if (!v) return { status: "missing", note: "Missing" };
        return { status: "ok", note: "Present" };
      }
    }
  ];

  let html = "";
  checks.forEach(function (c) {
    const result = c.test(map[c.key]);
    html += '<div class="header-item"><span class="name">' + c.name +
      '</span><span class="status ' + result.status + '">' + escapeHtml(result.note) + '</span></div>';
  });

  const setCookies = [];
  (headerList || []).forEach(function (h) {
    if (h.name.toLowerCase() === "set-cookie") setCookies.push(h.value);
  });
  if (setCookies.length) {
    html += '<div style="margin-top:14px;color:#00e896;font-family:JetBrains Mono,monospace;font-size:11px;">// COOKIES</div>';
    setCookies.forEach(function (c) {
      const name = c.split("=")[0];
      const hasSecure = /;\s*secure/i.test(c);
      const hasHttpOnly = /;\s*httponly/i.test(c);
      const hasSameSite = /;\s*samesite=/i.test(c);
      const flags = [];
      if (!hasSecure) flags.push("no Secure");
      if (!hasHttpOnly) flags.push("no HttpOnly");
      if (!hasSameSite) flags.push("no SameSite");
      const status = flags.length === 0 ? "ok" : (flags.length >= 2 ? "missing" : "weak");
      const note = flags.length ? flags.join(", ") : "Secure + HttpOnly + SameSite";
      html += '<div class="header-item"><span class="name">' + escapeHtml(name) +
        '</span><span class="status ' + status + '">' + escapeHtml(note) + '</span></div>';
    });
  }

  headerResults.innerHTML = html || '<div class="empty-hint">No headers captured</div>';
}

async function runActiveChecks(pageUrl) {
  const extra = [];
  const canary = "vxscan" + Date.now().toString(36);
  let u;
  try { u = new URL(pageUrl); } catch (e) { return extra; }
  const origin = u.origin;

  // reflected params (still useful as a clue)
  const reflectParams = ["q", "search", "s", "id", "page", "name", "query", "keyword", "term"];
  for (let i = 0; i < reflectParams.length; i++) {
    const param = reflectParams[i];
    try {
      const testUrl = new URL(pageUrl);
      testUrl.searchParams.set(param, canary);
      const resp = await fetch(testUrl.toString(), { credentials: "omit", redirect: "manual" });
      const textBody = await resp.text();
      if (textBody.indexOf(canary) !== -1) {
        extra.push({
          severity: "medium",
          type: "Reflected input",
          detail: 'Parameter "' + param + '" reflects in response (reflects in page, check manually)'
        });
        break;
      }
    } catch (e) {}
  }

  // soft-404 baseline then path probes
  const commonPaths = [
    "/admin", "/admin/", "/login", "/wp-admin", "/wp-login.php", "/dashboard", "/panel",
    "/.env", "/.git/HEAD", "/.git/config", "/robots.txt", "/sitemap.xml", "/phpinfo.php",
    "/api", "/api/v1", "/graphql", "/swagger", "/actuator", "/actuator/health",
    "/server-status", "/config", "/backup", "/debug", "/console", "/manager"
  ];

  let baselineStatus = null;
  let baselineLen = -1;
  try {
    const randPath = "/vxscan-not-a-real-path-" + Date.now();
    const baseResp = await fetch(origin + randPath, { credentials: "omit", redirect: "manual" });
    baselineStatus = baseResp.status;
    const baseText = await baseResp.text();
    baselineLen = baseText.length;
  } catch (e) {}

  const foundPaths = [];

  async function probe(path) {
    const ctrl = new AbortController();
    const t = setTimeout(function () { ctrl.abort(); }, 2200);
    try {
      const resp = await fetch(origin + path, {
        method: "GET",
        credentials: "omit",
        redirect: "manual",
        signal: ctrl.signal
      });
      clearTimeout(t);
      if (!resp.status || resp.status === 0) return;
      // skip soft-404: same status as random path (and similar size when 200)
      if (baselineStatus && resp.status === baselineStatus) {
        if (resp.status === 200 || resp.status === 403 || resp.status === 404) {
          try {
            const body = await resp.clone().text();
            if (baselineLen >= 0 && Math.abs(body.length - baselineLen) < 80) return;
          } catch (e) {}
          // if baseline was 403/404 and probe matches, treat as non-existent
          if (baselineStatus === 403 || baselineStatus === 404) return;
        }
      }
      if (resp.status === 404 || resp.status === 410) return;
      foundPaths.push(path + " (" + resp.status + ")");
    } catch (e) {
      clearTimeout(t);
    }
  }

  for (let i = 0; i < commonPaths.length; i += 5) {
    const batch = commonPaths.slice(i, i + 5);
    await Promise.all(batch.map(probe));
    setProgress("path discovery " + Math.min(i + 5, commonPaths.length) + "/" + commonPaths.length);
  }

  if (foundPaths.length) {
    extra.push({
      severity: "info",
      type: "Interesting paths found",
      detail: foundPaths.join(", ")
    });
  }

  // robots / sitemap
  try {
    const robotsResp = await fetch(origin + "/robots.txt", { credentials: "omit" });
    if (robotsResp.ok) {
      const robotsText = await robotsResp.text();
      const sitemapMatch = robotsText.match(/Sitemap:\s*(\S+)/i);
      if (sitemapMatch) {
        extra.push({ severity: "info", type: "Sitemap declared", detail: sitemapMatch[1] });
      }
    }
  } catch (e) {}

  // open-redirect: check webRequest redirect cache for cross-host redirects from probe URLs
  try {
    const redir = await new Promise(function (resolve) {
      chrome.runtime.sendMessage({ type: "get_redirects" }, function (resp) {
        resolve((resp && resp.redirects) || {});
      });
    });
    const hits = [];
    Object.keys(redir).forEach(function (fromUrl) {
      if (fromUrl.indexOf(origin) === 0) {
        hits.push(fromUrl + " → " + redir[fromUrl].to);
      }
    });
    if (hits.length) {
      extra.push({
        severity: "medium",
        type: "Cross-origin redirect",
        detail: hits.slice(0, 5).join(" | ")
      });
    }
  } catch (e) {}

  return extra;
}


function renderFindings(data) {
  if (!data) {
    clearResults();
    return;
  }
  lastScanData = data;
  currentFindings = data.findings || [];
  showTarget(data.url || "");

  const sum = data.summary || {};
  document.getElementById("sumHigh").textContent = sum.high || 0;
  document.getElementById("sumMed").textContent = sum.medium || 0;
  document.getElementById("sumLow").textContent = sum.low || 0;
  document.getElementById("sumInfo").textContent = sum.info || 0;

  let risk = data.risk || "info";
  if ((sum.high || 0) > 0) risk = "high";
  else if ((sum.medium || 0) > 0) risk = "medium";
  else if ((sum.low || 0) > 0) risk = "low";
  const riskLabel = { high: "HIGH", medium: "MED", low: "LOW", info: "OK" };
  scoreEl.textContent = riskLabel[risk] || "OK";
  scoreEl.className = "stat-value score " + (risk === "info" || risk === "low" ? "good" : risk === "medium" ? "mid" : "bad");

  applyFilter();
}

function applyFilter() {
  let list = currentFindings;
  if (currentFilter !== "all") {
    list = currentFindings.filter(function (f) { return f.severity === currentFilter; });
  }
  if (!list.length) {
    resultsEl.innerHTML = '<div class="empty-hint">' +
      (currentFindings.length ? "No findings in this filter" : "No findings yet") + "</div>";
    return;
  }
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  list = list.slice().sort(function (a, b) {
    return (order[a.severity] || 9) - (order[b.severity] || 9);
  });

  resultsEl.innerHTML = list.map(function (f, idx) {
    const long = f.detail && f.detail.length > 140;
    return '<div class="finding ' + f.severity + '">' +
      '<div class="type">' +
        '<span class="severity ' + f.severity + '">' + f.severity + '</span>' +
        escapeHtml(f.type) +
        '<button class="copy-btn" data-idx="' + idx + '">copy</button>' +
      '</div>' +
      '<div class="detail' + (long ? ' collapsed' : '') + '">' + escapeHtml(f.detail) + '</div>' +
      (long ? '<div class="detail-toggle">expand</div>' : '') +
    '</div>';
  }).join("");

  resultsEl.querySelectorAll(".copy-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const i = parseInt(btn.getAttribute("data-idx"), 10);
      const item = list[i];
      const text = item.type + ": " + item.detail;
      navigator.clipboard.writeText(text).then(function () {
        btn.textContent = "copied";
        setTimeout(function () { btn.textContent = "copy"; }, 1000);
      });
    });
  });
  resultsEl.querySelectorAll(".detail-toggle").forEach(function (tog) {
    tog.addEventListener("click", function () {
      const detail = tog.previousElementSibling;
      const open = !detail.classList.contains("collapsed");
      detail.classList.toggle("collapsed");
      tog.textContent = open ? "expand" : "collapse";
    });
  });
}

function saveToHistory(scan) {
  if (!scan || !scan.url) return;
  chrome.storage.local.get("scanHistory", function (data) {
    let hist = data.scanHistory || [];
    hist.unshift({
      url: scan.url,
      risk: scan.risk || "info",
      timestamp: scan.timestamp || Date.now(),
      summary: scan.summary || {},
      findingsCount: (scan.findings || []).length
    });
    chrome.storage.local.set({ scanHistory: hist.slice(0, 12) });
  });
}

function loadHistory() {
  chrome.storage.local.get("scanHistory", function (data) {
    const hist = data.scanHistory || [];
    if (!hist.length) {
      historyList.innerHTML = '<div class="empty-hint">No history yet</div>';
      return;
    }
    historyList.innerHTML = hist.map(function (h) {
      return '<div class="hist-item">' +
        '<div class="hist-url">' + escapeHtml(h.url) + '</div>' +
        '<div class="hist-meta">' + (h.risk || h.score || '') + ' · ' + h.findingsCount + ' findings · ' +
        new Date(h.timestamp).toLocaleString() + '</div></div>';
    }).join("");
  });
}


function loadTabs() {
  return new Promise(function (resolve) {
    chrome.runtime.sendMessage({ type: "list_tabs" }, function (resp) {
      const tabs = (resp && resp.tabs) || [];
      if (!tabSelect) { resolve(tabs); return; }

      if (!tabs.length) {
        tabSelect.innerHTML = '<option value="">No scannable tabs open</option>';
        selectedTabId = null;
        resolve(tabs);
        return;
      }

      // preserve selection if possible
      const prev = selectedTabId;
      tabSelect.innerHTML = tabs.map(function (t) {
        let label = t.title || t.url;
        if (label.length > 70) label = label.slice(0, 67) + "...";
        try {
          const host = new URL(t.url).hostname;
          label = host + " — " + label;
        } catch (e) {}
        return '<option value="' + t.id + '">' + escapeHtml(label) + "</option>";
      }).join("");

      // prefer previous selection, else active tab, else first
      let pick = tabs.find(function (t) { return t.id === prev; });
      if (!pick) pick = tabs.find(function (t) { return t.active; }) || tabs[0];
      selectedTabId = pick.id;
      tabSelect.value = String(pick.id);
      showTarget(pick.url, pick.favIconUrl || "");
      resolve(tabs);
    });
  });
}

function getSelectedTab() {
  return new Promise(function (resolve) {
    const id = selectedTabId || (tabSelect && tabSelect.value ? parseInt(tabSelect.value, 10) : null);
    if (!id) {
      resolve(null);
      return;
    }
    chrome.runtime.sendMessage({ type: "get_tab", tabId: id }, function (resp) {
      resolve((resp && resp.tab) || null);
    });
  });
}

async function getTargetTab() {
  return new Promise(function (resolve) {
    chrome.runtime.sendMessage({ type: "get_active_tab" }, function (resp) {
      resolve((resp && resp.tab) || null);
    });
  });
}

async function runScan() {
  if (scanning) return;
  scanning = true;
  scanBtn.disabled = true;
  setStatus("// scanning...");
  setProgress("resolving active tab...");

  try {
    // refresh list then use selection
    await loadTabs();
    const tab = await getSelectedTab();
    if (!tab || !tab.id || !tab.url) {
      setStatus("// no scannable tab selected — open a website and refresh the list");
      setProgress(null);
      scanning = false;
      scanBtn.disabled = false;
      return;
    }
    if (tab.url.startsWith("chrome://") || tab.url.startsWith("chrome-extension://") || tab.url.startsWith("edge://")) {
      setStatus("// cannot scan browser internal pages");
      setProgress(null);
      scanning = false;
      scanBtn.disabled = false;
      return;
    }

    showTarget(tab.url);
    setProgress("passive scan...");

    // headers
    chrome.runtime.sendMessage({ type: "get_headers", tabId: tab.id }, function (resp) {
      if (resp && resp.headers) analyzeHeaders(resp.headers);
    });

    // inject content script
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["content.js"]
    });

    // wait briefly for content script results
    await new Promise(function (r) { setTimeout(r, 800); });

    const stored = await new Promise(function (resolve) {
      chrome.storage.local.get("lastScan", function (data) { resolve(data.lastScan || null); });
    });

    let scan = stored && stored.url === tab.url ? stored : {
      url: tab.url,
      findings: [],
      score: 100,
      summary: { high: 0, medium: 0, low: 0, info: 0 },
      timestamp: Date.now()
    };

    setProgress("active probes + paths...");
    let activeFindings = [];
    try {
      activeFindings = await runActiveChecks(tab.url);
    } catch (e) {
      console.log(e);
    }

    if (activeFindings.length) {
      scan.findings = (scan.findings || []).concat(activeFindings);
      scan.summary = scan.summary || { high: 0, medium: 0, low: 0, info: 0 };
      activeFindings.forEach(function (f) {
        scan.summary[f.severity] = (scan.summary[f.severity] || 0) + 1;
      });
      if ((scan.summary.high || 0) > 0) scan.risk = "high";
      else if ((scan.summary.medium || 0) > 0) scan.risk = "medium";
      else if ((scan.summary.low || 0) > 0) scan.risk = "low";
      else scan.risk = "info";
    }

    scan.timestamp = Date.now();
    chrome.storage.local.set({ lastScan: scan });
    saveToHistory(scan);
    renderFindings(scan);
    setProgress(null);
    setStatus("// scan complete — " + (scan.findings || []).length + " finding(s)");
  } catch (err) {
    setProgress(null);
    setStatus("// error: " + err.message);
  }

  scanning = false;
  scanBtn.disabled = false;
}

// nav
document.querySelectorAll(".nav-btn").forEach(function (btn) {
  btn.addEventListener("click", function () {
    document.querySelectorAll(".nav-btn").forEach(function (b) { b.classList.remove("active"); });
    document.querySelectorAll(".view").forEach(function (v) { v.classList.remove("active"); });
    btn.classList.add("active");
    const view = document.getElementById("view-" + btn.getAttribute("data-view"));
    if (view) view.classList.add("active");
    if (btn.getAttribute("data-view") === "history") loadHistory();
  });
});

// filters
document.querySelectorAll(".filter").forEach(function (btn) {
  btn.addEventListener("click", function () {
    document.querySelectorAll(".filter").forEach(function (b) { b.classList.remove("active"); });
    btn.classList.add("active");
    currentFilter = btn.getAttribute("data-sev");
    applyFilter();
  });
});

scanBtn.addEventListener("click", runScan);
clearBtn.addEventListener("click", clearResults);

exportBtn.addEventListener("click", function () {
  if (!lastScanData) {
    setStatus("// nothing to export");
    return;
  }
  const findings = (lastScanData.findings || []).map(function (f) {
    return { severity: f.severity, type: f.type, detail: f.exportDetail || f.detail };
  });
  let md = "# VulnScan Report\n\n";
  md += "**URL:** " + lastScanData.url + "\n\n";
  md += "**Risk:** " + (lastScanData.risk || "n/a") + "\n\n";
  md += "**Time:** " + new Date(lastScanData.timestamp || Date.now()).toISOString() + "\n\n";
  md += "## Findings\n\n";
  findings.forEach(function (f) {
    md += "- **[" + f.severity.toUpperCase() + "]** " + f.type + " — " + f.detail + "\n";
  });
  const blob = new Blob([md], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "vuln-scan-" + Date.now() + ".md";
  a.click();
  URL.revokeObjectURL(url);
});

exportBtn.addEventListener("contextmenu", function (e) {
  e.preventDefault();
  if (!lastScanData) return;
  const exportData = {
    url: lastScanData.url,
    timestamp: lastScanData.timestamp,
    score: lastScanData.score,
    summary: lastScanData.summary,
    findings: (lastScanData.findings || []).map(function (f) {
      return { severity: f.severity, type: f.type, detail: f.exportDetail || f.detail };
    })
  };
  const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "vuln-scan-" + Date.now() + ".json";
  a.click();
  URL.revokeObjectURL(url);
});

if (deleteHistoryBtn) {
  deleteHistoryBtn.addEventListener("click", function () {
    chrome.storage.local.set({ scanHistory: [] }, function () {
      historyList.innerHTML = '<div class="empty-hint">History deleted</div>';
    });
  });
}

if (toggleHeadersBtn) {
  toggleHeadersBtn.addEventListener("click", function () {
    const hidden = headerResults.style.display === "none";
    headerResults.style.display = hidden ? "block" : "none";
    toggleHeadersBtn.textContent = hidden ? "hide" : "show";
  });
}

document.addEventListener("keydown", function (e) {
  if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
  const k = e.key.toLowerCase();
  if (k === "s") { e.preventDefault(); runScan(); }
  if (k === "c") { e.preventDefault(); clearResults(); }
  if (k === "e") { e.preventDefault(); exportBtn.click(); }
});

// restore last scan on load
chrome.storage.local.get("lastScan", function (data) {
  if (data.lastScan) renderFindings(data.lastScan);
});



if (tabSelect) {
  tabSelect.addEventListener("change", function () {
    selectedTabId = parseInt(tabSelect.value, 10) || null;
    const opt = tabSelect.options[tabSelect.selectedIndex];
    // fetch full tab for favicon/url
    getSelectedTab().then(function (tab) {
      if (tab) {
        showTarget(tab.url, tab.favIconUrl || "");
      }
    });
  });
}
if (refreshTabsBtn) {
  refreshTabsBtn.addEventListener("click", function () {
    loadTabs().then(function () {
      setStatus("// tab list refreshed");
    });
  });
}

// initial tab list
loadTabs();
