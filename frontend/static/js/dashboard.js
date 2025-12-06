// ====================== FETCH SYSTEM STATUS ======================
async function fetchSystemStatus() {
    try {
        const res = await fetch("/api/system/status");
        const data = await res.json();
        if (!data.success) return;

        const d = data.data;

        document.querySelector("#cpu-card .value").textContent = d.cpu_percent + "%";
        document.querySelector("#ram-card .value").textContent = d.memory_percent + "%";
        document.querySelector("#uptime-card .value").textContent = d.system_uptime_human;
    } catch (e) {
        console.error("System status error:", e);
    }
}


// ====================== FETCH LATEST METRIC SNAPSHOT ======================
async function fetchLatestMetrics() {
    try {
        const res = await fetch("/api/metrics/latest");
        const data = await res.json();
        if (!data.success || !data.data) return;

        const ts = data.data.timestamp;
        document.querySelector("#metric-time-card .value").textContent = ts;

    } catch (e) {
        console.error("Metric fetch error:", e);
    }
}


// ====================== INTERNAL LOG VIEWER ======================
async function fetchInternalLogs() {
    try {
        const res = await fetch("/api/logs/internal");
        const data = await res.json();
        const logBox = document.getElementById("internal-log-box");

        if (!data.success) {
            logBox.textContent = "Failed to load logs.";
            return;
        }

        let content = data.data || "";

        // Renklendirme
        content = content
            .replace(/\bINFO\b/g, '<span class="log-info">INFO</span>')
            .replace(/\bWARNING\b/g, '<span class="log-warn">WARNING</span>')
            .replace(/\bERROR\b/g, '<span class="log-error">ERROR</span>');

        logBox.innerHTML = content;

        logBox.scrollTop = logBox.scrollHeight; // tail -f
    } catch (e) {
        console.error("Internal log error:", e);
    }
}


// ====================== THREAD MONITOR ======================
async function fetchThreadHealth() {
    try {
        const res = await fetch("/api/system/threads");
        const data = await res.json();
        if (!data.success) return;

        const tbody = document.getElementById("thread-table-body");
        tbody.innerHTML = "";

        data.data.forEach(th => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${th.name}</td>
                <td class="${th.alive ? 'thread-ok' : 'thread-dead'}">
                    ${th.alive ? "Alive" : "Dead"}
                </td>
                <td>${th.last_heartbeat}</td>
            `;

            tbody.appendChild(row);
        });

    } catch (e) {
        console.error("Thread monitor error:", e);
    }
}


// ====================== PARSED LOGS PREVIEW ======================
async function fetchParsedLogs() {
    try {
        const res = await fetch("/api/logs/events?limit=20");
        const data = await res.json();
        if (!data.success) return;

        const tbody = document.getElementById("parsed-logs-body");
        tbody.innerHTML = "";

        data.data.forEach(log => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${log.timestamp}</td>
                <td>${log.severity || '-'}</td>
                <td>${log.event_type}</td>
                <td>${log.message}</td>
            `;

            tbody.appendChild(row);
        });

    } catch (e) {
        console.error("Parsed log preview error:", e);
    }
}


// ====================== UPDATE ALL ======================
function updateDashboard() {
    fetchSystemStatus();
    fetchLatestMetrics();
    fetchInternalLogs();
    fetchParsedLogs();
    fetchThreadHealth();
}

setInterval(updateDashboard, 3000);

document.addEventListener("DOMContentLoaded", updateDashboard);
