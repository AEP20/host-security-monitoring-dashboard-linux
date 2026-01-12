import { formatTimestamp } from "./utils.js";

let currentOffset = 0;
const LIMIT = 50;
let isLoading = false;

// ============================================
// INTERNAL LOGS (UNCHANGED)
// ============================================
async function fetchInternalLogs() {
    try {
        const res = await fetch("/api/logs/internal");
        const data = await res.json();

        const logBox = document.getElementById("internal-log-box");
        let content = data.data || "";

        content = content
            .replace(/\bINFO\b/g, '<span class="log-info">INFO</span>')
            .replace(/\bWARNING\b/g, '<span class="log-warn">WARNING</span>')
            .replace(/\bERROR\b/g, '<span class="log-error">ERROR</span>');

        logBox.innerHTML = content;
        logBox.scrollTop = logBox.scrollHeight;
        
    } catch (err) {
        console.error("Internal log error:", err);
    }
}


// ============================================
// EVENT LOGS & FILTERING
// ============================================
async function fetchEventLogs(append = false) {
    if (isLoading) return;
    isLoading = true;

    try {
        const severity = document.getElementById("filter-severity").value;
        const source = document.getElementById("filter-source").value;
        const category = document.getElementById("filter-category").value;
        const search = document.getElementById("filter-search").value;

        if (!append) {
            currentOffset = 0;
            document.getElementById("event-table-body").innerHTML = "";
        }

        const params = new URLSearchParams({
            limit: LIMIT,
            offset: currentOffset,
            expand: "true"
        });

        if (severity) params.append("severity", severity);
        if (source) params.append("source", source);
        if (category) params.append("category", category);
        if (search) params.append("search", search);

        const res = await fetch(`/api/logs/events?${params.toString()}`);
        const json = await res.json();
        const rows = json.data || [];

        const tbody = document.getElementById("event-table-body");

        if (rows.length === 0 && !append) {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 10;
            td.style.textAlign = "center";
            td.style.padding = "20px";
            td.textContent = "No logs found.";
            tr.appendChild(td);
            tbody.appendChild(tr);
        }

        rows.forEach(ev => {
            const tr = document.createElement("tr");
            tr.style.cursor = "pointer";
            tr.onclick = () => openLogDetail(ev);

            const tdTime = document.createElement("td");
            tdTime.style.fontFamily = "monospace";
            tdTime.textContent = formatTimestamp(ev.timestamp);

            const tdSev = document.createElement("td");
            const spanSev = document.createElement("span");
            spanSev.textContent = ev.severity;
            spanSev.classList.add("status-badge");
            
            if (ev.severity === "CRITICAL" || ev.severity === "HIGH") {
                spanSev.classList.add("dead");
            } else if (ev.severity === "MEDIUM" || ev.severity === "LOW") {
                spanSev.style.background = "#fff3cd";
                spanSev.style.color = "#856404";
                spanSev.style.border = "1px solid #ffeeba";
            } else if (ev.severity === "INFO") {
                spanSev.classList.add("alive");
            } else {
                spanSev.style.background = "#444";
                spanSev.style.color = "#ddd";
            }
            tdSev.appendChild(spanSev);

            const tdAlerts = document.createElement("td");
            if (ev.related_alerts_count > 0) {
                const spanAlert = document.createElement("span");
                spanAlert.textContent = `${ev.related_alerts_count} ALERTS`;
                spanAlert.classList.add("status-badge");
                spanAlert.style.fontSize = "10px";
                if (ev.related_alerts_max_severity === "HIGH" || ev.related_alerts_max_severity === "CRITICAL") {
                    spanAlert.classList.add("dead");
                } else {
                    spanAlert.classList.add("alive");
                }
                tdAlerts.appendChild(spanAlert);
            }

            const tdCat = document.createElement("td");
            tdCat.textContent = ev.category || "-";

            const tdSrc = document.createElement("td");
            tdSrc.textContent = ev.log_source || "-";

            const tdType = document.createElement("td");
            tdType.textContent = ev.event_type || "-";

            const tdUser = document.createElement("td");
            tdUser.textContent = ev.user || "-";

            const tdIp = document.createElement("td");
            tdIp.textContent = ev.ip_address || "-";

            const tdProc = document.createElement("td");
            tdProc.textContent = ev.process_name || "-";

            const tdMsg = document.createElement("td");
            tdMsg.textContent = ev.message;
            tdMsg.style.maxWidth = "300px";
            tdMsg.style.whiteSpace = "nowrap";
            tdMsg.style.overflow = "hidden";
            tdMsg.style.textOverflow = "ellipsis";
            tdMsg.style.opacity = "0.8";

            tr.appendChild(tdTime);
            tr.appendChild(tdSev);
            tr.appendChild(tdAlerts);
            tr.appendChild(tdCat);
            tr.appendChild(tdSrc);
            tr.appendChild(tdType);
            tr.appendChild(tdUser);
            tr.appendChild(tdIp);
            tr.appendChild(tdProc);
            tr.appendChild(tdMsg);

            tbody.appendChild(tr);
        });
        
        if (rows.length > 0) {
            currentOffset += rows.length;
        }

    } catch (e) {
        console.error("Parsed event error:", e);
    } finally {
        isLoading = false;
    }
}

function openLogDetail(ev) {
    const modal = document.getElementById("log-detail-modal");
    const body = document.getElementById("modal-body");
    body.innerHTML = "";

    if (ev.related_alerts && ev.related_alerts.length > 0) {
        const alertBox = document.createElement("div");
        alertBox.style.marginTop = "20px";
        alertBox.style.padding = "15px";
        alertBox.style.background = "rgba(255,0,0,0.1)";
        alertBox.style.border = "1px solid #ff4444";
        alertBox.style.borderRadius = "6px";
        
        const h4 = document.createElement("h4");
        h4.textContent = "⚠ Related Security Alerts";
        h4.style.marginTop = "0";
        h4.style.color = "#ff6b6b";
        alertBox.appendChild(h4);

        const ul = document.createElement("ul");
        ul.style.margin = "0";
        ul.style.paddingLeft = "20px";

        ev.related_alerts.forEach(a => {
            const li = document.createElement("li");
            
            const strong = document.createElement("strong");
            strong.textContent = a.rule_name;
            
            const badge = document.createElement("span");
            badge.textContent = a.severity;
            badge.classList.add("status-badge", "dead");
            badge.style.transform = "scale(0.8)";
            badge.style.marginLeft = "8px";

            const br = document.createElement("br");
            const small = document.createElement("small");
            small.textContent = formatTimestamp(a.timestamp);
            small.style.opacity = "0.6";

            li.appendChild(strong);
            li.appendChild(badge);
            li.appendChild(br);
            li.appendChild(small);
            ul.appendChild(li);
        });
        alertBox.appendChild(ul);
        body.appendChild(alertBox);
    }

    const grid = document.createElement("div");
    grid.style.display = "grid";
    grid.style.gridTemplateColumns = "1fr 1fr";
    grid.style.gap = "20px";
    grid.style.marginTop = "20px";

    const fields = [
        ["Timestamp", formatTimestamp(ev.timestamp)],
        ["Severity", ev.severity],
        ["Source", ev.log_source],
        ["Category", ev.category],
        ["Event Type", ev.event_type],
        ["User", ev.user],
        ["IP Address", ev.ip_address],
        ["Process Name", ev.process_name]
    ];

    fields.forEach(([label, value]) => {
        const div = document.createElement("div");
        div.innerHTML = `<strong>${label}:</strong> <br>`; 
        const span = document.createElement("span");
        span.textContent = value || "-";
        div.appendChild(span);
        grid.appendChild(div);
    });
    body.appendChild(grid);

    const msgBox = document.createElement("div");
    msgBox.style.marginTop = "20px";
    msgBox.innerHTML = "<strong>Message:</strong>";
    const preMsg = document.createElement("pre");
    preMsg.textContent = ev.message;
    preMsg.style.background = "#111";
    preMsg.style.padding = "10px";
    preMsg.style.borderRadius = "4px";
    preMsg.style.whiteSpace = "pre-wrap";
    preMsg.style.color = "#ddd";
    msgBox.appendChild(preMsg);
    body.appendChild(msgBox);

    const rawBox = document.createElement("div");
    rawBox.style.marginTop = "20px";
    rawBox.innerHTML = "<strong>Raw Event Data:</strong>";
    const preRaw = document.createElement("pre");
    preRaw.textContent = JSON.stringify(ev, null, 2);
    preRaw.style.background = "#111";
    preRaw.style.padding = "10px";
    preRaw.style.borderRadius = "4px";
    preRaw.style.maxHeight = "200px";
    preRaw.style.overflow = "auto";
    preRaw.style.fontSize = "11px";
    preRaw.style.color = "#888";
    rawBox.appendChild(preRaw);
    body.appendChild(rawBox);

    modal.style.display = "flex";
}

// ============================================
// INITIALIZATION
// ============================================
document.addEventListener("DOMContentLoaded", () => {
    // Buttons
    document.getElementById("btn-apply-filter").onclick = () => fetchEventLogs(false);
    document.getElementById("btn-clear-filter").onclick = () => {
        document.getElementById("filter-severity").value = "";
        document.getElementById("filter-source").value = "";
        document.getElementById("filter-category").value = "";
        document.getElementById("filter-search").value = "";
        fetchEventLogs(false);
    };
    document.getElementById("btn-load-more").onclick = () => fetchEventLogs(true);

    // Modal Close
    document.getElementById("close-modal").onclick = () => {
        document.getElementById("log-detail-modal").style.display = "none";
    };
    window.onclick = (event) => {
        const modal = document.getElementById("log-detail-modal");
        if (event.target == modal) {
            modal.style.display = "none";
        }
    };

    // Initial Load
    fetchInternalLogs();
    fetchEventLogs(false);
});