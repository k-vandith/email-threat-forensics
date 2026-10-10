/* SignalTrace: browser interactions for the local email-forensics API. */
(function () {
  "use strict";
  var state = { raw: "", filename: "phishing_sample.eml", result: null, toastTimer: null };
  var byId = function (id) { return document.getElementById(id); };
  var all = function (selector, root) { return Array.prototype.slice.call((root || document).querySelectorAll(selector)); };

  function element(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }
  function showToast(message) {
    var toast = byId("toast");
    toast.textContent = message;
    toast.classList.add("visible");
    window.clearTimeout(state.toastTimer);
    state.toastTimer = window.setTimeout(function () { toast.classList.remove("visible"); }, 2600);
  }
  function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
  }
  function pad(value) { return String(value).padStart(2, "0"); }
  function scoreLabel(score) {
    if (score >= 0.75) return "CRITICAL";
    if (score >= 0.5) return "HIGH";
    if (score >= 0.25) return "GUARDED";
    return "LOW";
  }
  function typeOf(value) {
    if (/^https?:\/\//i.test(value)) return "URL";
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return "IP ADDRESS";
    return "DOMAIN";
  }
  function senderDomain(value) {
    var match = String(value || "").match(/@([a-z0-9.-]+)/i);
    return match ? match[1] : "Domain not identified";
  }
  function contextFor(value) {
    var type = typeOf(value);
    if (type === "URL") return "Body / URL extraction";
    if (type === "IP ADDRESS") return "Received header";
    return "Sender or linked hostname";
  }
  function escapeCsv(value) {
    return '"' + String(value == null ? "" : value).replace(/"/g, '""') + '"';
  }
  function downloadBlob(blob, filename) {
    var url = URL.createObjectURL(blob);
    var link = element("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
  }
  function downloadText(text, filename, type) {
    downloadBlob(new Blob([text], { type: type || "text/plain;charset=utf-8" }), filename);
  }
  async function copyText(value) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
      } else {
        var box = element("textarea");
        box.value = value;
        box.setAttribute("readonly", "");
        box.style.position = "fixed";
        box.style.opacity = "0";
        document.body.appendChild(box);
        box.select();
        var copied = document.execCommand("copy");
        box.remove();
        if (!copied) throw new Error("Clipboard access was blocked");
      }
      showToast("Copied to clipboard.");
    } catch (error) {
      showToast("Clipboard access was blocked by the browser.");
    }
  }
  async function fetchJson(url, options) {
    var response = await fetch(url, options || {});
    var data = await response.json();
    if (!response.ok) throw new Error(data.error || "Request failed.");
    return data;
  }
  function setBusy(isBusy, message) {
    byId("loading").hidden = !isBusy;
    byId("workspace").hidden = isBusy || !state.result;
    if (isBusy) {
      byId("loading").querySelector("span:last-child").textContent = message || "Reading message evidence…";
    }
    byId("import-button").disabled = isBusy;
    byId("report-button").disabled = isBusy || !state.result;
  }
  function showNotice(message) {
    var notice = byId("notice");
    notice.textContent = message || "";
    notice.hidden = !message;
  }
  async function analyze(raw, filename) {
    state.raw = raw;
    state.filename = filename || "message.eml";
    setBusy(true, "Examining message structure and signals…");
    showNotice("");
    try {
      state.result = await fetchJson("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw: state.raw, filename: state.filename })
      });
      state.filename = state.result.filename;
      render();
      setBusy(false);
      showToast("Message examined locally.");
    } catch (error) {
      state.result = null;
      setBusy(false);
      byId("workspace").hidden = true;
      showNotice(error.message || "Unable to analyze this message.");
    }
  }
  async function loadSample() {
    setBusy(true, "Loading the bundled training message…");
    showNotice("");
    try {
      var sample = await fetchJson("/api/sample");
      await analyze(sample.raw, sample.filename);
      showNotice("Training fixture loaded. Its domains and IP addresses are illustrative, not reputation-checked.");
    } catch (error) {
      setBusy(false);
      showNotice(error.message || "Could not load the sample fixture.");
    }
  }
  function createPill(text, className) {
    return element("span", className || "risk-pill", text);
  }
  function renderAuth() {
    var result = state.result;
    var grid = byId("auth-grid");
    grid.replaceChildren();
    var items = [
      { label: "SPF", value: result.spf, detail: "Sender policy framework" },
      { label: "DKIM", value: result.dkim, detail: "Message signature result" },
      { label: "DMARC", value: result.dmarc, detail: "Domain alignment policy" }
    ];
    var failures = 0;
    items.forEach(function (item) {
      var value = String(item.value || "unknown").toLowerCase();
      var stateClass = value === "fail" ? "fail" : value === "pass" ? "pass" : "unknown";
      if (stateClass === "fail") failures += 1;
      var card = element("article", "auth-card " + stateClass);
      card.appendChild(element("span", "auth-label", item.label));
      card.appendChild(element("strong", "", value));
      card.appendChild(element("small", "", item.detail));
      grid.appendChild(card);
    });
    byId("auth-failures").replaceChildren(document.createTextNode(pad(failures) + " "));
    byId("auth-failures").appendChild(element("small", "", "failed"));
    byId("auth-foot").textContent = failures ? items.filter(function (item) { return item.value === "fail"; }).map(function (item) { return item.label; }).join(" · ") : "No explicit failures observed";
    byId("auth-summary").textContent = failures ? failures + " authentication failure" + (failures === 1 ? "" : "s") : "No explicit authentication failures";
  }
  function renderSignals() {
    var root = byId("signals-list");
    root.replaceChildren();
    var signals = state.result.phishing_indicators || [];
    if (!signals.length) {
      var empty = element("div", "empty-state", "No configured phishing indicators were flagged. This does not establish that a message is safe.");
      root.appendChild(empty);
      byId("signals-index").textContent = "0 RULES";
      return;
    }
    signals.forEach(function (signal, index) {
      var row = element("div", "signal-row" + (/shortener|urgent|credential/i.test(signal) ? " guard" : ""));
      row.appendChild(element("span", "signal-symbol", /spf|dkim|dmarc/i.test(signal) ? "↯" : "⚑"));
      var copy = element("div");
      copy.appendChild(element("strong", "", signal));
      var description = /spf/i.test(signal) ? "The Authentication-Results / Received-SPF header reports a sender-policy failure." :
        /dkim/i.test(signal) ? "The message reports a failed DKIM signature check." :
        /dmarc/i.test(signal) ? "The message reports a failed DMARC evaluation." :
        /shortener/i.test(signal) ? "A shortened link can obscure the destination before it is resolved." :
        "Language resembles a credential or account-action lure.";
      copy.appendChild(element("p", "", description));
      row.appendChild(copy);
      row.appendChild(element("span", "signal-type", index < 3 ? "AUTH" : "CONTENT"));
      root.appendChild(row);
    });
    byId("signals-index").textContent = pad(signals.length) + " RULES";
  }
  function renderRoute() {
    var root = byId("route-track");
    root.replaceChildren();
    var hops = state.result.hops || [];
    byId("hop-index").textContent = pad(hops.length) + " HOP" + (hops.length === 1 ? "" : "S");
    if (!hops.length) {
      root.appendChild(element("div", "empty-route", "No Received headers with a traceable hop were found."));
      return;
    }
    hops.forEach(function (hop, index) {
      var row = element("div", "route-stop" + (index === 0 ? " origin" : ""));
      row.appendChild(element("span", "route-marker", index === 0 ? "↗" : pad(index + 1)));
      var content = element("div");
      content.appendChild(element("strong", "", hop.ip || "Relay without an extracted IP"));
      content.appendChild(element("p", "", hop.raw || "Received header detected."));
      var geography = hop.geo && hop.geo.country ? "OFFLINE LABEL · " + hop.geo.country : "HEADER EVIDENCE";
      content.appendChild(element("span", "route-tag", geography));
      row.appendChild(content);
      root.appendChild(row);
    });
  }
  function renderIocPreview() {
    var root = byId("ioc-preview");
    root.replaceChildren();
    var iocs = state.result.iocs || [];
    iocs.slice(0, 5).forEach(function (value) {
      var row = element("div", "ioc-preview-row");
      var group = element("div", "ioc-value-group");
      group.appendChild(element("span", "ioc-type", typeOf(value)));
      group.appendChild(element("span", "ioc-value", value));
      row.appendChild(group);
      var copy = element("button", "copy-mini", "Copy");
      copy.type = "button";
      copy.addEventListener("click", function () { copyText(value); });
      row.appendChild(copy);
      root.appendChild(row);
    });
    if (!iocs.length) root.appendChild(element("div", "empty-route", "No IOCs were extracted from this message."));
    if (iocs.length > 5) root.appendChild(element("button", "text-action", "View " + (iocs.length - 5) + " more indicators ↗")).addEventListener("click", function () { showView("indicators"); });
  }
  function renderSource() {
    var result = state.result;
    byId("raw-source").textContent = state.raw;
    byId("source-subject").textContent = result.subject;
    byId("source-message-id").textContent = result.message_id || "Not present";
    byId("header-count").textContent = String((result.headers || []).length);
    var body = byId("header-table");
    body.replaceChildren();
    (result.headers || []).forEach(function (header) {
      var row = element("tr");
      row.appendChild(element("td", "", header.name));
      row.appendChild(element("td", "", header.value));
      body.appendChild(row);
    });
  }
  function renderIndicators() {
    var search = byId("ioc-search").value.trim().toLowerCase();
    var values = (state.result.iocs || []).map(function (value) {
      return { value: value, type: typeOf(value), context: contextFor(value) };
    });
    var filtered = values.filter(function (item) {
      return !search || (item.value + " " + item.type + " " + item.context).toLowerCase().indexOf(search) >= 0;
    });
    var body = byId("ioc-table");
    body.replaceChildren();
    filtered.forEach(function (item) {
      var row = element("tr");
      var typeCell = element("td");
      typeCell.appendChild(createPill(item.type, "type-chip " + (item.type === "URL" ? "url" : item.type === "IP ADDRESS" ? "ip" : "")));
      row.appendChild(typeCell);
      row.appendChild(element("td", "value-cell", item.value));
      row.appendChild(element("td", "", item.context));
      var actionCell = element("td");
      var copy = element("button", "review-button", "Copy value");
      copy.type = "button";
      copy.addEventListener("click", function () { copyText(item.value); });
      actionCell.appendChild(copy);
      row.appendChild(actionCell);
      body.appendChild(row);
    });
    byId("ioc-empty").hidden = filtered.length !== 0;
    byId("filter-count").textContent = filtered.length + " / " + values.length + " indicators";
  }
  function render() {
    var result = state.result;
    var score = Number(result.threat_score || 0);
    var label = scoreLabel(score);
    byId("side-filename").textContent = result.filename;
    byId("file-meta").textContent = result.filename;
    byId("ioc-nav-count").textContent = pad((result.iocs || []).length);
    byId("risk-title").textContent = score >= 0.5 ? "Threat indicators detected" : score >= 0.25 ? "Review signals before trusting" : "Few configured signals observed";
    byId("risk-pill").textContent = label + " SIGNAL";
    byId("risk-pill").className = "risk-pill " + (label === "CRITICAL" ? "critical" : label.toLowerCase());
    byId("risk-description").textContent = score >= 0.5 ? "This message presents multiple signals that warrant a cautious, independent review." : "The configured local rules found limited evidence. A low score is not a clean bill of health.";
    byId("score-ring").style.setProperty("--score-angle", (Math.max(0, Math.min(1, score)) * 360) + "deg");
    byId("score-number").textContent = score.toFixed(2);
    byId("score-band").textContent = label + " RISK";
    byId("score-band").style.color = score >= 0.5 ? "var(--red)" : score >= 0.25 ? "#926322" : "var(--green)";
    byId("signal-count").textContent = pad((result.phishing_indicators || []).length);
    byId("hop-count").replaceChildren(document.createTextNode(pad((result.hops || []).length) + " "));
    byId("hop-count").appendChild(element("small", "", (result.hops || []).length === 1 ? "observed" : "observed"));
    byId("ioc-count").replaceChildren(document.createTextNode(pad((result.iocs || []).length) + " "));
    byId("ioc-count").appendChild(element("small", "", "extracted"));
    byId("message-size").replaceChildren(document.createTextNode(formatSize(result.size_bytes) + " "));
    byId("message-size").appendChild(element("small", "", "total"));
    byId("message-subject").textContent = result.subject;
    byId("message-sender").textContent = result.sender;
    byId("sender-domain").textContent = senderDomain(result.sender);
    byId("message-recipient").textContent = (result.recipients || []).join(", ") || "Not present";
    byId("message-date").textContent = result.date || "Not present";
    byId("message-origin").textContent = result.originating_ip || "Not identified";
    byId("analyst-note").textContent = score >= 0.5 ? "Treat this score as triage guidance—not a verdict. Do not follow embedded links. Verify sender identity, expected context and the full authentication chain independently." : "Treat this score as triage guidance—not a verdict. Verify sender identity and the full authentication chain before acting.";
    renderAuth();
    renderSignals();
    renderRoute();
    renderIocPreview();
    renderSource();
    renderIndicators();
  }
  function showView(view) {
    var valid = ["overview", "source", "indicators"].indexOf(view) >= 0 ? view : "overview";
    all(".nav-item").forEach(function (button) { button.classList.toggle("active", button.dataset.view === valid); });
    all(".view-panel").forEach(function (panel) { panel.classList.toggle("active-view", panel.dataset.panel === valid); panel.hidden = panel.dataset.panel !== valid; });
    document.querySelector(".main-shell").classList.toggle("subpage", valid !== "overview");
    byId("breadcrumb-current").textContent = valid === "overview" ? "CASE OVERVIEW" : valid === "source" ? "MESSAGE SOURCE" : "IOC REGISTER";
    if (valid === "source") byId("raw-source").scrollTop = 0;
  }
  async function importFile(file) {
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      showNotice("This file is larger than the 2 MB local analysis limit.");
      return;
    }
    try {
      var raw = await file.text();
      await analyze(raw, file.name);
    } catch (error) {
      showNotice("Could not read this file in the browser.");
    }
  }
  async function exportReport() {
    if (!state.result) return;
    byId("report-button").disabled = true;
    try {
      var response = await fetch("/api/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw: state.raw, filename: state.filename })
      });
      if (!response.ok) {
        var failure = await response.json();
        throw new Error(failure.error || "Report generation failed.");
      }
      downloadBlob(await response.blob(), "signaltrace-evidence-report.html");
      showToast("Evidence report exported.");
    } catch (error) {
      showNotice(error.message || "Report could not be exported.");
    } finally {
      byId("report-button").disabled = false;
    }
  }
  function exportIocJson() {
    if (!state.result) return;
    downloadText(JSON.stringify({
      case_file: state.filename,
      generated_at: new Date().toISOString(),
      network_lookups: false,
      indicators: (state.result.iocs || []).map(function (value) { return { type: typeOf(value), value: value, context: contextFor(value) }; })
    }, null, 2), "signaltrace-iocs.json", "application/json;charset=utf-8");
    showToast("Indicator register exported as JSON.");
  }
  function exportIocCsv() {
    if (!state.result) return;
    var rows = [["type", "value", "source_context"]];
    (state.result.iocs || []).forEach(function (value) { rows.push([typeOf(value), value, contextFor(value)]); });
    var csv = rows.map(function (row) { return row.map(escapeCsv).join(","); }).join("\r\n");
    downloadText("\ufeff" + csv, "signaltrace-iocs.csv", "text/csv;charset=utf-8");
    showToast("Indicator register exported as CSV.");
  }
  all(".nav-item").forEach(function (button) { button.addEventListener("click", function () { showView(button.dataset.view); }); });
  all("[data-open-view]").forEach(function (button) { button.addEventListener("click", function () { showView(button.dataset.openView); }); });
  byId("import-button").addEventListener("click", function () { byId("file-input").click(); });
  byId("file-input").addEventListener("change", function (event) { importFile(event.target.files && event.target.files[0]); event.target.value = ""; });
  byId("sample-button").addEventListener("click", loadSample);
  byId("report-button").addEventListener("click", exportReport);
  byId("copy-source").addEventListener("click", function () { copyText(state.raw); });
  byId("export-json").addEventListener("click", exportIocJson);
  byId("export-csv").addEventListener("click", exportIocCsv);
  byId("ioc-search").addEventListener("input", renderIndicators);
  loadSample();
}());
