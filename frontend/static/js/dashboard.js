// frontend/static/js/dashboard.js

import { formatTimestamp } from "./utils.js";

// ====================== FETCH SYSTEM STATUS ======================
async function fetchSystemStatus() {
    console.log("[DEBUG][fetchSystemStatus] Called");

    try {
        console.log("[DEBUG][fetchSystemStatus] Fetching /api/system/status ...");
        const res = await fetch("/api/system/status");
        const data = await res.json();

        if (!data.success) {
            console.warn("[WARN][fetchSystemStatus] success=false");
            return;
        }

        const d = data.data;

        document.querySelector("#cpu-card .value").textContent = d.cpu_percent + "%";
        document.querySelector("#ram-card .value").textContent = d.memory_percent + "%";
        document.querySelector("#uptime-card .value").textContent = d.system_uptime_human;

        const score = d.security_score; 
        const scoreCard = document.querySelector("#security-score-card");
        
        if (scoreCard) {
            const scoreValueEl = scoreCard.querySelector(".value");
            const scoreFill = document.getElementById("score-fill");

            scoreValueEl.textContent = score + "/100";

            // Renk Mantığı
            let color = "#2ecc71"; // Yeşil
            if (score <= 30) {
                color = "#ff4757"; // Agresif Kırmızı
            } else if (score <= 60) {
                color = "#ffa502"; // Turuncu
            } else if (score <= 80) {
                color = "#f1c40f"; // Sarı
            }

            // UI Uygulama
            scoreValueEl.style.color = color;
            if (scoreFill) {
                scoreFill.style.backgroundColor = color;
                scoreFill.style.width = Math.max(score, 3) + "%"; 
                
                if (score <= 30) {
                    scoreFill.style.boxShadow = "0 0 10px " + color;
                } else {
                    scoreFill.style.boxShadow = "none";
                }
            }
        }

        console.log("[DEBUG][fetchSystemStatus] DOM updated. Score:", score);

    } catch (e) {
        console.error("System status error:", e);
    }
}


// ====================== FETCH LATEST METRIC SNAPSHOT ======================
async function fetchLatestMetrics() {
    try {
        const res = await fetch("/api/metrics/latest");
        const json = await res.json();

        if (!json.success || !json.data) {
            console.warn("[metrics] No metric snapshot");
            return;
        }

        const ts = json.data.timestamp;

        const date = new Date(ts);
        const human = date.toLocaleString();

        const el = document.querySelector("#metric-time-card .value");
        if (el) {
            el.textContent = human;
        }

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
        if (content.length > 14000) {
            console.warn("[WARN][fetchInternalLogs] Log too large, trimming...");
            content = content.slice(-14000);
        }

        // ======================
        // 2) Syntax highlighting (safe range check)
        // ======================
        if (content.length < 16000) {
            content = content
                .replace(/\bINFO\b/g, '<span class="log-info">INFO</span>')
                .replace(/\bWARNING\b/g, '<span class="log-warn">WARNING</span>')
                .replace(/\bERROR\b/g, '<span class="log-error">ERROR</span>');
        }

        // ======================
        // 3) DOM reset guard
        // ======================
        if (logBox.innerHTML.length > 20000) {
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
                <td>${formatTimestamp(log.timestamp)}</td>
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



// ====================== RECENT ALERT CHECK ======================

let currentAlertId = null; 

async function fetchRecentAlerts() {
    try {
        const res = await fetch("/api/alerts?limit=1");
        const json = await res.json();
        
        const bannerContainer = document.getElementById("alert-banner-container");
        if (!bannerContainer) return;

        if (json.data && json.data.length > 0) {
            const latest = json.data[0];
            
            let ts = latest.timestamp;
            // Robust parsing: Handle 6-digit microseconds which confuse some browsers
            if (ts && typeof ts === "string") {
                if (ts.endsWith("Z")) ts = ts.slice(0, -1);
                
                const dotIndex = ts.indexOf(".");
                if (dotIndex !== -1) {
                    const parts = ts.split(".");
                    if (parts[1].length > 3) {
                        ts = parts[0] + "." + parts[1].substring(0, 3);
                    }
                }
                ts += "Z"; 
            }
            
            const alertDate = new Date(ts);
            if (isNaN(alertDate.getTime())) {
                console.warn("[dashboard] Invalid alert timestamp:", ts);
                return;
            }

            const now = new Date();
            const diffMs = now - alertDate;
            const fifteenMinsMs = 15 * 60 * 1000;
            

            if (diffMs < fifteenMinsMs) { 
                if (currentAlertId !== latest.id) {
                    bannerContainer.innerHTML = `
                        <div class="alert-banner">
                            <span>
                                <strong>RECENT SECURITY ALERT:</strong> ${latest.rule_name} (${latest.severity}) detected.
                            </span>
                            <a href="/alerts">View Details</a>
                        </div>
                    `;
                    bannerContainer.style.display = "block";
                    currentAlertId = latest.id;
                    console.log("[dashboard] New alert banner displayed", latest.id);
                }
                return;
            }
        }
        
        if (currentAlertId !== null) {
             bannerContainer.style.display = "none";
             bannerContainer.innerHTML = "";
             currentAlertId = null;
             console.log("[dashboard] Alert banner hidden");
        }
        
    } catch (e) {
        console.error("[dashboard] Recent alert fetch error:", e);
    }
}


// ====================== UPDATE ALL ======================
function updateDashboard() {
    console.log("[DEBUG][updateDashboard] Refresh cycle triggered");

    fetchSystemStatus();
    fetchLatestMetrics();
    fetchInternalLogs();
    fetchParsedLogs();
    fetchThreadHealth();
    fetchRecentAlerts();
}

setInterval(() => {
    console.log("[DEBUG][updateDashboard] Interval tick");
    updateDashboard();
}, 3000);

document.addEventListener("DOMContentLoaded", () => {
    console.log("[DEBUG][DOMContentLoaded] Initial dashboard load");
    updateDashboard();
});
