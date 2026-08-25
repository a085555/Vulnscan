const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");
const scanBtn = document.getElementById("scanBtn");
const exportBtn = document.getElementById("exportBtn");
const scoreEl = document.getElementById("score");
const summaryBar = document.getElementById("summaryBar");
const headerSection = document.getElementById("headerSection");
const headerResults = document.getElementById("headerResults");
const historyBtn = document.getElementById("historyBtn");
const historyPanel = document.getElementById("historyPanel");
const clearBtn = document.getElementById("clearBtn");
const progressEl = document.getElementById("progress");
const toggleHeadersBtn = document.getElementById("toggleHeaders");
const targetPreview = document.getElementById("targetPreview");
const targetFavicon = document.getElementById("targetFavicon");
const targetHost = document.getElementById("targetHost");

let currentFindings = [];
let currentFilter = "all";
let lastScanData = null;

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function shortUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname + (u.pathname.length > 25 ? u.pathname.substring(0, 25) + "…" : u.pathname);
  } catch (e) {
    return url.substring(0, 45);
  }
}

function renderFindings(data) {
  if (!data || !data.findings) {
    statusEl.textContent = "No scan data yet.";
    scoreEl.textContent = "SCORE --/100";
    scoreEl.className = "score";
    summaryBar.style.display = "none";
    headerSection.style.display = "none";
    return;
  }

  lastScanData = data;
  currentFindings = data.findings;
  if (data.url) showTargetPreview(data.url);
  const count = data.findings.length;
  statusEl.textContent = "Scanned: " + shortUrl(data.url) + "  •  " + count + " finding(s)";

  // score
  const s = typeof data.score === "number" ? data.score : 100;
  scoreEl.textContent = "SCORE " + s + "/100";
  scoreEl.className = "score " + (s >= 80 ? "good" : s >= 50 ? "mid" : "bad");

  // summary
  const sum = data.summary || {};
  document.getElementById("sumHigh").textContent = (sum.high || 0) + " HIGH";
  document.getElementById("sumMed").textContent = (sum.medium || 0) + " MED";
  document.getElementById("sumLow").textContent = (sum.low || 0) + " LOW";
  document.getElementById("sumInfo").textContent = (sum.info || 0) + " INFO";
  summaryBar.style.display = "flex";

  // update filter button counts
  const counts = {
    all: currentFindings.length,
    high: sum.high || 0,
    medium: sum.medium || 0,
    low: sum.low || 0,
    info: sum.info || 0
  };
  document.querySelectorAll(".filter").forEach(function(btn) {
    const sev = btn.getAttribute("data-sev");
    const label = sev === "all" ? "ALL" : (sev === "medium" ? "MED" : sev.toUpperCase());
    const c = counts[sev] || 0;
    btn.innerHTML = label + (c ? ' <span class="count">' + c + '</span>' : '');
  });

  applyFilter();
}



function showTargetPreview(url) {
  if (!targetPreview || !url) return;
  try {
    const u = new URL(url);
    targetHost.textContent = u.hostname + (u.pathname !== "/" ? u.pathname.substring(0, 40) : "");
    targetFavicon.src = "https://www.google.com/s2/favicons?domain=" + encodeURIComponent(u.hostname) + "&sz=32";
    targetPreview.style.display = "flex";
  } catch (e) {
    targetPreview.style.display = "none";
  }
}

function setProgress(msg) {
  if (!progressEl) return;
  if (!msg) {
    progressEl.style.display = "none";
    progressEl.textContent = "";
  } else {
    progressEl.style.display = "block";
    progressEl.textContent = "// " + msg;
  }
}

function clearResults() {
  lastScanData = null;
  currentFindings = [];
  resultsEl.innerHTML = "";
  summaryBar.style.display = "none";
  headerSection.style.display = "none";
  if (historyPanel) historyPanel.style.display = "none";
  scoreEl.textContent = "SCORE --/100";
  scoreEl.className = "score";
  statusEl.textContent = "// results cleared — press S to scan";
  setProgress(null);
  // reset filter labels
  document.querySelectorAll(".filter").forEach(function(btn) {
    const sev = btn.getAttribute("data-sev");
    btn.innerHTML = sev === "all" ? "ALL" : sev.toUpperCase().replace("MEDIUM","MED");
  });
}

function applyFilter() {
  let list = currentFindings;
  if (currentFilter !== "all") {
    list = currentFindings.filter(function (f) { return f.severity === currentFilter; });
  }

  if (list.length === 0) {
    resultsEl.innerHTML = '<div class="empty">' +
      (currentFindings.length === 0 ? "No obvious issues found." : "No findings in this filter.") +
      '</div>';
    return;
  }

  const order = { high: 0, medium: 1, low: 2, info: 3 };
  list = list.slice().sort(function (a, b) {
    return (order[a.severity] || 9) - (order[b.severity] || 9);
  });

  resultsEl.innerHTML = list.map(function (f, idx) {
    return '<div class="finding ' + f.severity + '">' +
      '<div class="type">' +
        '<span class="severity ' + f.severity + '">' + f.severity + '</span>' +
        escapeHtml(f.type) +
        '<button class="copy-btn" data-idx="' + idx + '" title="Copy">copy</button>' +
      '</div>' +
      '<div class="detail' + (f.detail && f.detail.length > 120 ? ' collapsed' : '') + '" data-full="' + escapeHtml(f.detail) + '">' + escapeHtml(f.detail) + '</div>' +
      (f.detail && f.detail.length > 120 ? '<div class="detail-toggle">expand</div>' : '') +
    '</div>';
  }).join("");

  // bind copy buttons
  resultsEl.querySelectorAll(".copy-btn").forEach(function(btn) {
    btn.addEventListener("click", function(e) {
      e.stopPropagation();
      const i = parseInt(btn.getAttribute("data-idx"), 10);
      const item = list[i];
      const textToCopy = (item.full || (item.type + ": " + item.detail));
      navigator.clipboard.writeText(textToCopy).then(function() {
        btn.textContent = "copied";
        setTimeout(function() { btn.textContent = "copy"; }, 1200);
      });
    });
  });

  // bind expand toggles for long details
  resultsEl.querySelectorAll(".detail-toggle").forEach(function(tog) {
    tog.addEventListener("click", function() {
      const detail = tog.previousElementSibling;
      if (!detail) return;
      const collapsed = detail.classList.contains("collapsed");
      if (collapsed) {
        detail.classList.remove("collapsed");
        tog.textContent = "collapse";
      } else {
        detail.classList.add("collapsed");
        tog.textContent = "expand";
      }
    });
  });
}

// Security header analysis
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
          return { status: "weak", note: "Contains unsafe-inline/eval" };
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
        if (v.toLowerCase() === "nosniff") return { status: "ok", note: "nosniff" };
        return { status: "weak", note: v };
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
    html += '<div class="header-item">' +
      '<span class="name">' + c.name + '</span>' +
      '<span class="status ' + result.status + '">' + result.note + '</span>' +
    '</div>';
  });

  // Cookie flag analysis from Set-Cookie headers
  const setCookies = [];
  (headerList || []).forEach(function(h) {
    if (h.name.toLowerCase() === "set-cookie") {
      setCookies.push(h.value);
    }
  });

  if (setCookies.length > 0) {
    html += '<div class="section-title" style="margin-top:12px;">Cookies (from headers)</div>';
    setCookies.forEach(function(c) {
      const name = c.split("=")[0];
      const hasSecure = /;\s*secure/i.test(c);
      const hasHttpOnly = /;\s*httponly/i.test(c);
      const hasSameSite = /;\s*samesite=/i.test(c);
      let flags = [];
      if (!hasSecure) flags.push("missing Secure");
      if (!hasHttpOnly) flags.push("missing HttpOnly");
      if (!hasSameSite) flags.push("missing SameSite");
      const status = flags.length === 0 ? "ok" : (flags.length >= 2 ? "missing" : "weak");
      const note = flags.length === 0 ? "Secure + HttpOnly + SameSite" : flags.join(", ");
      html += '<div class="header-item">' +
        '<span class="name">' + name + '</span>' +
        '<span class="status ' + status + '">' + note + '</span>' +
      '</div>';
    });
  }

  headerResults.innerHTML = html;
  headerSection.style.display = "block";
}

// filter buttons
document.querySelectorAll(".filter").forEach(function (btn) {
  btn.addEventListener("click", function () {
    document.querySelectorAll(".filter").forEach(function (b) { b.classList.remove("active"); });
    btn.classList.add("active");
    currentFilter = btn.getAttribute("data-sev");
    applyFilter();
  });
});

// load last results
chrome.storage.local.get("lastScan", function (data) {
  if (data.lastScan) renderFindings(data.lastScan);
});

// ── light active checks ────────────────────────────────
async function runActiveChecks(pageUrl) {
  const extra = [];
  const canary = "vxscan" + Date.now().toString(36);

  try {
    const u = new URL(pageUrl);

    // 1. Reflected parameter check (common param names)
    const reflectParams = ["q", "search", "s", "id", "page", "name", "query", "keyword", "term"];
    for (const param of reflectParams) {
      try {
        const testUrl = new URL(pageUrl);
        testUrl.searchParams.set(param, canary);
        const resp = await fetch(testUrl.toString(), { credentials: "omit", redirect: "manual" });
        const text = await resp.text();
        if (text.indexOf(canary) !== -1) {
          extra.push({
            severity: "medium",
            type: "Reflected input",
            detail: "Parameter \"" + param + "\" reflects value in response (possible XSS vector)"
          });
          break; // one finding is enough
        }
      } catch (e) {}
    }

    // 2. Open redirect confirmation (very light)
    const redirectParams = ["url", "redirect", "next", "return", "returnTo", "goto", "dest", "redirect_uri", "continue"];
    const evil = "https://example.com/vxscan-redirect-test";
    for (const param of redirectParams) {
      try {
        const testUrl = new URL(pageUrl);
        testUrl.searchParams.set(param, evil);
        const resp = await fetch(testUrl.toString(), { credentials: "omit", redirect: "manual" });
        // manual redirect: status 0 or 3xx, and Location header points outside
        const loc = resp.headers.get("Location") || resp.headers.get("location") || "";
        if ((resp.status >= 300 && resp.status < 400) && loc.indexOf("example.com") !== -1) {
          extra.push({
            severity: "high",
            type: "Open redirect confirmed",
            detail: "Parameter \"" + param + "\" redirects to external URL"
          });
          break;
        }
      } catch (e) {}
    }

    // 3. Simple CORS reflection check
    try {
      const resp = await fetch(pageUrl, {
        method: "GET",
        credentials: "omit",
        headers: { "Origin": "https://evil-vxscan.example" }
      });
      const acao = resp.headers.get("Access-Control-Allow-Origin") || "";
      if (acao === "https://evil-vxscan.example" || acao === "*") {
        extra.push({
          severity: "medium",
          type: "CORS misconfiguration",
          detail: "Access-Control-Allow-Origin reflects arbitrary origin: " + acao
        });
      }
    } catch (e) {}

    // 4. Common path discovery (light)
    const commonPaths = [
      "/admin", "/admin/", "/administrator", "/admin.php", "/admin/login", "/admin/index.php",
      "/login", "/login.php", "/signin", "/sign-in", "/wp-admin", "/wp-login.php",
      "/dashboard", "/panel", "/cpanel", "/manager", "/backend", "/console", "/controlpanel",
      "/user", "/users", "/account", "/accounts", "/member", "/members", "/moderator",
      "/.env", "/.env.local", "/.env.production", "/.git/config", "/.git/HEAD", "/.gitignore",
      "/.svn/entries", "/.DS_Store", "/web.config", "/crossdomain.xml",
      "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/security.txt", "/.well-known/security.txt",
      "/server-status", "/server-info", "/phpinfo.php", "/info.php", "/test.php", "/debug",
      "/api", "/api/v1", "/api/v2", "/graphql", "/swagger", "/swagger-ui", "/swagger.json",
      "/config", "/config.php", "/configuration", "/settings", "/setup", "/install",
      "/backup", "/backups", "/old", "/dev", "/staging", "/test", "/tmp", "/temp",
      "/composer.json", "/package.json", "/yarn.lock", "/package-lock.json",
      "/README.md", "/CHANGELOG.md", "/LICENSE", "/.htaccess", "/web.config",
      "/actuator", "/actuator/health", "/actuator/env", "/jolokia", "/trace",
      "/elmah.axd", "/error", "/errors", "/logs", "/log", "/logging"
    ];

    const origin = u.origin;
    const foundPaths = [];

    // faster path probe with timeout + shorter practical list priority
    const priorityPaths = commonPaths.slice(0, 35); // don't probe everything every time
    async function probe(path) {
      const ctrl = new AbortController();
      const t = setTimeout(function() { ctrl.abort(); }, 2500);
      try {
        const resp = await fetch(origin + path, {
          method: "GET",
          credentials: "omit",
          redirect: "manual",
          signal: ctrl.signal
        });
        clearTimeout(t);
        if (resp.status && resp.status !== 404 && resp.status !== 410 && resp.status !== 0) {
          foundPaths.push(path + " (" + resp.status + ")");
        }
      } catch (e) {
        clearTimeout(t);
      }
    }
    // run in small batches of 5
    for (let i = 0; i < priorityPaths.length; i += 5) {
      const batch = priorityPaths.slice(i, i + 5);
      await Promise.all(batch.map(probe));
      setProgress("path discovery " + Math.min(i + 5, priorityPaths.length) + "/" + priorityPaths.length);
    }

    // only keep interesting status codes (hide mass 403 noise)
    const interesting = foundPaths.filter(function(p) {
      return !p.endsWith("(403)") && !p.endsWith("(404)") && !p.endsWith("(410)");
    });
    if (interesting.length > 0) {
      extra.push({
        severity: "info",
        type: "Interesting paths found",
        detail: interesting.join(", ")
      });
    } else if (foundPaths.length > 0) {
      extra.push({
        severity: "info",
        type: "Path probe summary",
        detail: foundPaths.length + " paths probed — mostly blocked (403/404). Protection likely in place."
      });
    }

    // fetch robots.txt + sitemap hints
    try {
      const robotsResp = await fetch(origin + "/robots.txt", { credentials: "omit" });
      if (robotsResp.ok) {
        const robotsText = await robotsResp.text();
        const sitemapMatch = robotsText.match(/Sitemap:\s*(\S+)/i);
        if (sitemapMatch) {
          extra.push({
            severity: "info",
            type: "Sitemap declared",
            detail: sitemapMatch[1]
          });
        }
        // list Disallow paths that look juicy
        const disallows = [];
        robotsText.split("\n").forEach(function(line) {
          const m = line.match(/^Disallow:\s*(\S+)/i);
          if (m && m[1] !== "/" && m[1].length > 1) disallows.push(m[1]);
        });
        if (disallows.length > 0 && disallows.length <= 15) {
          extra.push({
            severity: "info",
            type: "robots.txt Disallow entries",
            detail: disallows.join(", ")
          });
        }
      }
    } catch (e) {}

    // Suggested payloads when reflection was found
    const hasReflection = extra.some(function(f) { return f.type === "Reflected input"; });
    if (hasReflection) {
      extra.push({
        severity: "info",
        type: "Suggested XSS payloads (manual)",
        detail: "script-alert | img-onerror | svg-onload | onmouseover (copy from docs)"
      });
    }

  } catch (e) {
    console.log("active check error", e);
  }

  return extra;
}

// scan
scanBtn.addEventListener("click", async function () {
  statusEl.textContent = "Scanning…";
  setProgress("starting passive scan...");
  resultsEl.innerHTML = "";
  scoreEl.textContent = "SCORE …";
  scoreEl.className = "score";
  summaryBar.style.display = "none";
  headerSection.style.display = "none";
  if (historyPanel) historyPanel.style.display = "none";

  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs[0];
    if (!tab || !tab.id) {
      statusEl.textContent = "Error: no active tab";
      setProgress(null);
      return;
    }
    if (tab.url) showTargetPreview(tab.url);

    // get headers from background
    chrome.runtime.sendMessage({ type: "get_headers", tabId: tab.id }, function (resp) {
      if (resp && resp.headers) {
        analyzeHeaders(resp.headers);
      }
    });

    // passive scan
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["content.js"]
    });

    // wait for passive results, then run active checks
    setTimeout(async function () {
      try {
        chrome.storage.local.get("lastScan", async function (data) {
          let scan = data.lastScan || { url: tab.url, findings: [], score: 100, summary: { high:0, medium:0, low:0, info:0 } };

          statusEl.textContent = "Running light active checks…";
          setProgress("active probes + path discovery...");

          let activeFindings = [];
          try {
            activeFindings = await runActiveChecks(tab.url);
          } catch (e) {
            console.log("active checks failed", e);
          }

          if (activeFindings.length > 0) {
            scan.findings = (scan.findings || []).concat(activeFindings);
            scan.summary = scan.summary || { high: 0, medium: 0, low: 0, info: 0 };
            activeFindings.forEach(function (f) {
              scan.summary[f.severity] = (scan.summary[f.severity] || 0) + 1;
              if (f.severity === "high") scan.score = Math.max(0, (scan.score || 100) - 15);
              if (f.severity === "medium") scan.score = Math.max(0, (scan.score || 100) - 8);
            });
            chrome.storage.local.set({ lastScan: scan });
          }

          saveToHistory(scan);
          setProgress(null);
          statusEl.textContent = "scan complete";
          renderFindings(scan);
        });
      } catch (e) {
        setProgress(null);
        statusEl.textContent = "Error during active checks: " + e.message;
      }
    }, 700);
  } catch (err) {
    setProgress(null);
    statusEl.textContent = "Error: " + err.message;
  }
});

// export
exportBtn.addEventListener("click", function () {
  if (!lastScanData) {
    statusEl.textContent = "Nothing to export — scan first.";
    return;
  }

  const findings = (lastScanData.findings || []).map(function(f) {
    return {
      severity: f.severity,
      type: f.type,
      detail: f.full || f.detail
    };
  });

  // Markdown report
  let md = "# VulnScan Report\\n\\n";
  md += "**URL:** " + lastScanData.url + "\\n\\n";
  md += "**Score:** " + lastScanData.score + "/100\\n\\n";
  md += "**Time:** " + new Date(lastScanData.timestamp || Date.now()).toISOString() + "\\n\\n";
  md += "## Findings\\n\\n";
  findings.forEach(function(f) {
    md += "- **[" + f.severity.toUpperCase() + "]** " + f.type + " — " + f.detail + "\\n";
  });

  const blob = new Blob([md], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "vuln-scan-" + Date.now() + ".md";
  a.click();
  URL.revokeObjectURL(url);
});

// also keep JSON available via shift+click
exportBtn.addEventListener("contextmenu", function (e) {
  e.preventDefault();
  if (!lastScanData) return;
  const exportData = {
    url: lastScanData.url,
    timestamp: lastScanData.timestamp,
    score: lastScanData.score,
    summary: lastScanData.summary,
    findings: (lastScanData.findings || []).map(function(f) {
      return { severity: f.severity, type: f.type, detail: f.full || f.detail };
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



// ── scan history ───────────────────────────────────────
function saveToHistory(scan) {
  if (!scan || !scan.url) return;
  chrome.storage.local.get("scanHistory", function(data) {
    let hist = data.scanHistory || [];
    hist.unshift({
      url: scan.url,
      score: scan.score,
      timestamp: scan.timestamp || Date.now(),
      summary: scan.summary || {},
      findingsCount: (scan.findings || []).length
    });
    hist = hist.slice(0, 8); // keep last 8
    chrome.storage.local.set({ scanHistory: hist });
  });
}

function showHistory() {
  chrome.storage.local.get("scanHistory", function(data) {
    const hist = data.scanHistory || [];
    if (hist.length === 0) {
      historyPanel.innerHTML = '<div class="hist-empty">// no history yet</div>';
    } else {
      let html = '<div class="hist-actions"><button class="hist-clear" id="deleteHistoryBtn">DELETE HISTORY</button></div>';
      html += hist.map(function(h) {
        const d = new Date(h.timestamp);
        const time = d.toLocaleString();
        return '<div class="hist-item">' +
          '<div class="hist-url">' + escapeHtml(h.url) + '</div>' +
          '<div class="hist-meta">score ' + h.score + ' · ' + h.findingsCount + ' findings · ' + time + '</div>' +
        '</div>';
      }).join("");
      historyPanel.innerHTML = html;
      const delBtn = document.getElementById("deleteHistoryBtn");
      if (delBtn) {
        delBtn.addEventListener("click", function() {
          chrome.storage.local.set({ scanHistory: [] }, function() {
            historyPanel.innerHTML = '<div class="hist-empty">// history deleted</div>';
          });
        });
      }
    }
    historyPanel.style.display = historyPanel.style.display === "none" ? "block" : "none";
  });
}

if (historyBtn) {
  historyBtn.addEventListener("click", showHistory);
}



// clear results
if (clearBtn) {
  clearBtn.addEventListener("click", clearResults);
}

// collapsible headers
if (toggleHeadersBtn) {
  toggleHeadersBtn.addEventListener("click", function() {
    const body = document.getElementById("headerResults");
    if (!body) return;
    const hidden = body.style.display === "none";
    body.style.display = hidden ? "block" : "none";
    toggleHeadersBtn.textContent = hidden ? "hide" : "show";
  });
}

// keyboard shortcuts
document.addEventListener("keydown", function(e) {
  if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
  const k = e.key.toLowerCase();
  if (k === "s") { e.preventDefault(); scanBtn.click(); }
  if (k === "e") { e.preventDefault(); exportBtn.click(); }
  if (k === "c") { e.preventDefault(); clearResults(); }
  if (k === "h") { e.preventDefault(); if (historyBtn) historyBtn.click(); }
});
