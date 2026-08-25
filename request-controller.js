(function (root) {
  "use strict";

  const allowedModes = new Set(["passive", "safe", "lab"]);
  const allowedMethods = {
    passive: new Set(),
    safe: new Set(["GET", "HEAD", "OPTIONS"]),
    lab: new Set(["GET", "HEAD", "OPTIONS", "POST"])
  };

  function clampBudget(value) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed)) return 20;
    return Math.max(5, Math.min(50, parsed));
  }

  function safeOrigin(value) {
    try { return new URL(value).origin; } catch (e) { return ""; }
  }

  function safeUrl(value) {
    try {
      const url = new URL(value);
      url.username = "";
      url.password = "";
      url.hash = "";
      url.pathname = url.pathname.split("/").map(function (part) {
        return part.length >= 20 && /^[A-Za-z0-9._~-]+$/.test(part) ? "[redacted]" : part;
      }).join("/");
      Array.from(url.searchParams.keys()).forEach(function (name) {
        url.searchParams.set(name, "[redacted]");
      });
      return url.href;
    } catch (e) {
      return "[invalid URL]";
    }
  }

  async function readLimitedText(response, limit, method) {
    if (method === "HEAD") return "";
    const headerValue = response.headers && response.headers.get ? response.headers.get("content-length") : "";
    const contentLength = Number.parseInt(headerValue || "", 10);
    if (Number.isFinite(contentLength) && contentLength > limit) {
      throw new Error("response-too-large");
    }

    if (response.body && response.body.getReader) {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let size = 0;
      let text = "";
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        size += chunk.value.byteLength;
        if (size > limit) {
          await reader.cancel();
          throw new Error("response-too-large");
        }
        text += decoder.decode(chunk.value, { stream: true });
      }
      return text + decoder.decode();
    }

    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > limit) throw new Error("response-too-large");
    return text;
  }

  function create(options) {
    const settings = options || {};
    const mode = allowedModes.has(settings.mode) ? settings.mode : "passive";
    const origin = safeOrigin(settings.origin);
    const budget = clampBudget(settings.budget);
    const timeoutMs = Number.isFinite(settings.timeoutMs) ? settings.timeoutMs : 3000;
    const maxResponseBytes = Number.isFinite(settings.maxResponseBytes) ? settings.maxResponseBytes : 1024 * 1024;
    const fetchFn = settings.fetchFn || root.fetch;
    const onLog = typeof settings.onLog === "function" ? settings.onLog : function () {};
    const entries = [];
    const controllers = new Set();
    let attempted = 0;
    let completed = 0;
    let consecutive403 = 0;
    let consecutive5xx = 0;
    let stoppedReason = "";

    function summary() {
      return {
        mode: mode,
        budget: budget,
        attempted: attempted,
        completed: completed,
        stoppedReason: stoppedReason || null
      };
    }

    function pushLog(entry) {
      entries.push(entry);
      onLog(entry, entries.slice(), summary());
    }

    function stop(reason) {
      if (stoppedReason) return;
      stoppedReason = reason || "cancelled";
      controllers.forEach(function (controller) { controller.abort(); });
      controllers.clear();
    }

    function canRequest() {
      return !stoppedReason && attempted < budget;
    }

    async function request(value, init) {
      const requestOptions = init || {};
      const method = String(requestOptions.method || "GET").toUpperCase();
      let url;
      try { url = new URL(value); } catch (e) { throw new Error("Invalid request URL"); }
      if (!origin || url.origin !== origin) throw new Error("Request blocked outside the selected origin");
      if (!allowedMethods[mode].has(method)) throw new Error(method + " is not allowed in " + mode + " mode");
      if (stoppedReason) return { skipped: true, outcome: stoppedReason };
      if (attempted >= budget) {
        stoppedReason = "budget-exhausted";
        return { skipped: true, outcome: stoppedReason };
      }

      attempted++;
      const controller = new AbortController();
      controllers.add(controller);
      const startedAt = Date.now();
      const timer = setTimeout(function () { controller.abort(); }, timeoutMs);
      let status = 0;
      let outcome = "error";
      let body = "";

      try {
        const response = await fetchFn(url.href, {
          method: method,
          body: requestOptions.body,
          headers: requestOptions.headers,
          credentials: "omit",
          redirect: "manual",
          referrerPolicy: "no-referrer",
          cache: "no-store",
          signal: controller.signal
        });
        status = Number(response.status) || 0;
        body = await readLimitedText(response, maxResponseBytes, method);
        outcome = "complete";
        completed++;

        if (status === 403) consecutive403++;
        else consecutive403 = 0;
        if (status >= 500) consecutive5xx++;
        else consecutive5xx = 0;

        if (status === 429) stop("rate-limited");
        else if (consecutive403 >= 3) stop("repeated-403");
        else if (consecutive5xx >= 3) stop("repeated-5xx");

        return {
          skipped: false,
          status: status,
          ok: !!response.ok,
          body: body,
          headers: response.headers || null,
          outcome: outcome
        };
      } catch (error) {
        if (error && error.message === "response-too-large") outcome = "response-too-large";
        else if (controller.signal.aborted) outcome = stoppedReason || "timeout";
        return { skipped: false, status: status, ok: false, body: "", headers: null, outcome: outcome };
      } finally {
        clearTimeout(timer);
        controllers.delete(controller);
        pushLog({
          method: method,
          url: safeUrl(url.href),
          status: status,
          durationMs: Math.max(0, Date.now() - startedAt),
          outcome: outcome
        });
      }
    }

    return {
      mode: mode,
      origin: origin,
      budget: budget,
      request: request,
      canRequest: canRequest,
      cancel: function () { stop("cancelled"); },
      getLog: function () { return entries.slice(); },
      getSummary: summary
    };
  }

  root.VulnscanRequests = {
    clampBudget: clampBudget,
    safeUrl: safeUrl,
    create: create
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
