// ====================== FETCH SYSTEM STATUS ======================
async function fetchSystemStatus() {
    console.log("[DEBUG][fetchSystemStatus] Called");

    try {
        console.log("[DEBUG][fetchSystemStatus] Fetching /api/system/status ...");
        const res = await fetch("/api/system/status");
        console.log("[DEBUG][fetchSystemStatus] Response:", res);

        const data = await res.json();
        console.log("[DEBUG][fetchSystemStatus] JSON:", data);

        if (!data.success) {
            console.warn("[WARN][fetchSystemStatus] success=false");
            return;
        }

        const d = data.data;
        console.log("[DEBUG][fetchSystemStatus] Data payload:", d);

        document.querySelector("#cpu-card .value").textContent = d.cpu_percent + "%";
        document.querySelector("#ram-card .value").textContent = d.memory_percent + "%";
        document.querySelector("#uptime-card .value").textContent = d.system_uptime_human;

        console.log("[DEBUG][fetchSystemStatus] DOM updated");

    } catch (e) {
        console.error("System status error:", e);
    }
}


// ====================== FETCH LATEST METRIC SNAPSHOT ======================
async function fetchLatestMetrics() {
    console.log("[DEBUG][fetchLatestMetrics] Called");

    try {
        console.log("[DEBUG][fetchLatestMetrics] Fetching /api/metrics/latest ...");
        const res = await fetch("/api/metrics/latest");
        console.log("[DEBUG][fetchLatestMetrics] Response:", res);

        const data = await res.json();
        console.log("[DEBUG][fetchLatestMetrics] JSON:", data);

        if (!data.success || !data.data) {
            console.warn("[WARN][fetchLatestMetrics] No metric snapshot found");
            return;
        }

        const ts = data.data.timestamp;
        console.log("[DEBUG][fetchLatestMetrics] Timestamp:", ts);

        document.querySelector("#metric-time-card .value").textContent = ts;

        console.log("[DEBUG][fetchLatestMetrics] DOM updated");

    } catch (e) {
        console.error("Metric fetch error:", e);
    }
}

// ====================== INTERNAL LOG VIEWER ======================
async function fetchInternalLogs() {
    console.log("[DEBUG][fetchInternalLogs] Called");

    try {
        console.log("[DEBUG][fetchInternalLogs] Fetching /api/logs/internal ...");
        const res = await fetch("/api/logs/internal");
        console.log("[DEBUG][fetchInternalLogs] Response:", res);

        const data = await res.json();
        console.log("[DEBUG][fetchInternalLogs] JSON:", data);

        const logBox = document.getElementById("internal-log-box");

        if (!data.success) {
            console.warn("[WARN][fetchInternalLogs] success=false");
            logBox.textContent = "Failed to load logs.";
            return;
        }

        let content = data.data || "";
        console.log("[DEBUG][fetchInternalLogs] Raw content length:", content.length);

        // ======================
        // 1) Future proof: Very large log protection
        // ======================
        if (content.length > 20000) {
            console.warn("[WARN][fetchInternalLogs] Log too large, trimming...");
            content = content.slice(-20000); // keep last 20k chars
        }

        // ======================
        // 2) Syntax highlighting (safe range check)
        // ======================
        if (content.length < 50000) {
            content = content
                .replace(/\bINFO\b/g, '<span class="log-info">INFO</span>')
                .replace(/\bWARNING\b/g, '<span class="log-warn">WARNING</span>')
                .replace(/\bERROR\b/g, '<span class="log-error">ERROR</span>');
        }

        // ======================
        // 3) DOM reset guard
        // ======================
        if (logBox.innerHTML.length > 60000) {
            console.warn("[WARN][fetchInternalLogs] Clearing oversized DOM container...");
            logBox.innerHTML = "";
        }

        // ======================
        // 4) Render and auto-scroll
        // ======================
        logBox.innerHTML = content;
        logBox.scrollTop = logBox.scrollHeight;

        console.log("[DEBUG][fetchInternalLogs] DOM updated, scrolled to bottom");

    } catch (e) {
        console.error("Internal log error:", e);
    }
}



// ====================== THREAD MONITOR ======================
async function fetchThreadHealth() {
    console.log("[DEBUG][fetchThreadHealth] Called");

    try {
        console.log("[DEBUG][fetchThreadHealth] Fetching /api/system/threads ...");
        const res = await fetch("/api/system/threads");
        console.log("[DEBUG][fetchThreadHealth] Response:", res);

        const data = await res.json();
        console.log("[DEBUG][fetchThreadHealth] JSON:", data);

        if (!data.success) {
            console.warn("[WARN][fetchThreadHealth] success=false");
            return;
        }

        const tbody = document.getElementById("thread-table-body");
        tbody.innerHTML = "";

        console.log("[DEBUG][fetchThreadHealth] Threads:", data.data);

        data.data.forEach(th => {
            console.log(`[DEBUG][fetchThreadHealth] Adding row: ${th.name}, alive=${th.alive}`);

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

        console.log("[DEBUG][fetchThreadHealth] DOM updated");

    } catch (e) {
        console.error("Thread monitor error:", e);
    }
}


// ====================== PARSED LOGS PREVIEW ======================
async function fetchParsedLogs() {
    console.log("[DEBUG][fetchParsedLogs] Called");

    try {
        console.log("[DEBUG][fetchParsedLogs] Fetching /api/logs/events?limit=20 ...");
        const res = await fetch("/api/logs/events?limit=20");
        console.log("[DEBUG][fetchParsedLogs] Response:", res);

        const data = await res.json();
        console.log("[DEBUG][fetchParsedLogs] JSON:", data);

        if (!data.success) {
            console.warn("[WARN][fetchParsedLogs] success=false");
            return;
        }

        const tbody = document.getElementById("parsed-logs-body");
        tbody.innerHTML = "";

        console.log("[DEBUG][fetchParsedLogs] Logs count:", data.data.length);

        data.data.forEach(log => {
            console.log(`[DEBUG][fetchParsedLogs] Row: ${log.event_type}`);

            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${log.timestamp}</td>
                <td>${log.severity || '-'}</td>
                <td>${log.event_type}</td>
                <td>${log.message}</td>
            `;

            tbody.appendChild(row);
        });

        console.log("[DEBUG][fetchParsedLogs] DOM updated");

    } catch (e) {
        console.error("Parsed log preview error:", e);
    }
}


// ====================== UPDATE ALL ======================
function updateDashboard() {
    console.log("[DEBUG][updateDashboard] Refresh cycle triggered");

    fetchSystemStatus();
    fetchLatestMetrics();
    // fetchInternalLogs();
    fetchParsedLogs();
    fetchThreadHealth();
}

setInterval(() => {
    console.log("[DEBUG][updateDashboard] Interval tick");
    updateDashboard();
}, 3000);

document.addEventListener("DOMContentLoaded", () => {
    console.log("[DEBUG][DOMContentLoaded] Initial dashboard load");
    updateDashboard();
});
