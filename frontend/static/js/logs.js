
import { formatTimestamp } from "./utils.js";

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

async function fetchEventLogs() {
    try {
        const res = await fetch("/api/logs/events?limit=50");
        const json = await res.json();

        const rows = json.data || [];
        const tbody = document.getElementById("event-table-body");
        tbody.innerHTML = "";

        rows.forEach(ev => {
            const tr = document.createElement("tr");

            tr.innerHTML = `
                <td>${formatTimestamp(ev.timestamp)}</td>
                <td>${ev.event_type}</td>
                <td>${ev.severity}</td>
                <td title="${ev.message}">${ev.message}</td>
            `;

            tbody.appendChild(tr);
        });

    } catch (e) {
        console.error("Parsed event error:", e);
    }
}

function refreshAll() {
    fetchInternalLogs();
    fetchEventLogs();
}

document.addEventListener("DOMContentLoaded", () => {
    refreshAll();
    setInterval(refreshAll, 5000);
});