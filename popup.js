const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");
const scanBtn = document.getElementById("scanBtn");
const exportBtn = document.getElementById("exportBtn");
const scoreEl = document.getElementById("score");
const summaryBar = document.getElementById("summaryBar");
const headerSection = document.getElementById("headerSection");
const headerResults = document.getElementById("headerResults");

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
    scoreEl.textContent = "--";
    scoreEl.className = "score";
    summaryBar.style.display = "none";
    headerSection.style.display = "none";
    return;
  }

  lastScanData = data;
  currentFindings = data.findings;
  const count = data.findings.length;
  statusEl.textContent = "Scanned: " + shortUrl(data.url) + "  •  " + count + " finding(s)";

  // score
  const s = typeof data.score === "number" ? data.score : 100;
  scoreEl.textContent = "Score: " + s + "/100";
  scoreEl.className = "score " + (s >= 80 ? "good" : s >= 50 ? "mid" : "bad");

  // summary
  const sum = data.summary || {};
  document.getElementById("sumHigh").textContent = (sum.high || 0) + " High";
  document.getElementById("sumMed").textContent = (sum.medium || 0) + " Medium";
  document.getElementById("sumLow").textContent = (sum.low || 0) + " Low";
  document.getElementById("sumInfo").textContent = (sum.info || 0) + " Info";
  summaryBar.style.display = "flex";

  applyFilter();
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

  resultsEl.innerHTML = list.map(function (f) {
    return '<div class="finding ' + f.severity + '">' +
      '<div class="type">' +
        '<span class="severity ' + f.severity + '">' + f.severity + '</span>' +
        escapeHtml(f.type) +
      '</div>' +
      '<div class="detail">' + escapeHtml(f.detail) + '</div>' +
    '</div>';
  }).join("");
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

  } catch (e) {
    console.log("active check error", e);
  }

  return extra;
}

// scan
scanBtn.addEventListener("click", async function () {
  statusEl.textContent = "Scanning…";
  resultsEl.innerHTML = "";
  scoreEl.textContent = "…";
  scoreEl.className = "score";
  summaryBar.style.display = "none";
  headerSection.style.display = "none";

  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs[0];

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
      chrome.storage.local.get("lastScan", async function (data) {
        let scan = data.lastScan || { url: tab.url, findings: [], score: 100, summary: {} };

        statusEl.textContent = "Running light active checks…";

        const activeFindings = await runActiveChecks(tab.url);

        if (activeFindings.length > 0) {
          scan.findings = (scan.findings || []).concat(activeFindings);

          // update summary + score
          scan.summary = scan.summary || { high: 0, medium: 0, low: 0, info: 0 };
          activeFindings.forEach(function (f) {
            scan.summary[f.severity] = (scan.summary[f.severity] || 0) + 1;
            if (f.severity === "high") scan.score = Math.max(0, (scan.score || 100) - 15);
            if (f.severity === "medium") scan.score = Math.max(0, (scan.score || 100) - 8);
          });

          // persist updated results
          chrome.storage.local.set({ lastScan: scan });
        }

        renderFindings(scan);
      });
    }, 600);
  } catch (err) {
    statusEl.textContent = "Error: " + err.message;
  }
});

// export
exportBtn.addEventListener("click", function () {
  if (!lastScanData) {
    statusEl.textContent = "Nothing to export — scan first.";
    return;
  }

  // Build export version that prefers full secrets when available
  const exportData = {
    url: lastScanData.url,
    timestamp: lastScanData.timestamp,
    score: lastScanData.score,
    summary: lastScanData.summary,
    findings: (lastScanData.findings || []).map(function(f) {
      return {
        severity: f.severity,
        type: f.type,
        detail: f.full || f.detail   // full key if we have it, otherwise normal detail
      };
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
