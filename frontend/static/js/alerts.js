import { formatTimestamp } from "./utils.js";

const ALERTS_TIMEZONE = "Europe/Istanbul";

function formatAlertTimestamp(timestamp) {
    if (!timestamp) return "-";

    const date = new Date(timestamp);
    if (isNaN(date.getTime())) return timestamp;

    // UTC → TR (+3)
    date.setHours(date.getHours() + 3);

    // ISO string üretip helper'a ver
    return formatTimestamp(date.toISOString());
}


document.addEventListener("DOMContentLoaded", () => {

    // PAGE GUARD
    if (!document.getElementById("alerts-table-body")) {
        console.debug("[alerts.js] Not on alerts page, aborting");
        return;
    }

    loadAlerts();

    // LOAD ALERT LIST
    function loadAlerts() {
        fetch("/api/alerts")
            .then(res => res.json())
            .then(json => {
                const tbody = document.getElementById("alerts-table-body");
                tbody.innerHTML = "";

                (json.data || []).forEach(alert => {
                    const tr = document.createElement("tr");

                    tr.innerHTML = `
                        <td>${formatAlertTimestamp(alert.timestamp)}</td>
                        <td>
                            <span class="severity ${alert.severity.toLowerCase()}">
                                ${alert.severity}
                            </span>
                        </td>
                        <td>${alert.rule_name}</td>
                        <td title="${alert.message}">
                            ${alert.message}
                        </td>
                        <td>
                            <button class="details-btn"
                                data-id="${alert.id}">
                                View
                            </button>
                        </td>
                    `;

                    tbody.appendChild(tr);
                });

                document.querySelectorAll(".details-btn").forEach(btn => {
                    btn.onclick = () => loadAlertDetail(btn.dataset.id);
                });
            })
            .catch(err => {
                console.error("[alerts.js] Failed to load alerts", err);
            });
    }

    // LOAD ALERT DETAIL + EVIDENCE
    function loadAlertDetail(alertId) {
        fetch(`/api/alerts/${alertId}`)
            .then(res => res.json())
            .then(json => {
                if (!json.data) return;

                renderAlertModal(json.data);
                openModal();
            })
            .catch(err => {
                console.error("[alerts.js] Failed to load alert detail", err);
            });
    }

    // RENDER MODAL CONTENT
    function renderAlertModal(data) {
        const alert = data.alert;
        const evidence = data.evidence || [];

        const container = document.getElementById("alerts-modal-body");
        container.innerHTML = "";

        // ALERT SUMMARY
        const summary = document.createElement("div");
        summary.className = "alert-summary";
        summary.innerHTML = `
            <h3>${alert.rule_name}</h3>
            <p><strong>Severity:</strong> ${alert.severity}</p>
            <p><strong>Time:</strong> ${formatAlertTimestamp(alert.timestamp)}</p>
            <p><strong>Message:</strong> ${alert.message}</p>
        `;
        container.appendChild(summary);

        // EVIDENCE LIST
        const evTitle = document.createElement("h4");
        evTitle.innerText = "Related Events";
        container.appendChild(evTitle);

        evidence.forEach(ev => {
            const card = document.createElement("div");
            card.className = "evidence-card";

            card.innerHTML = `
                <div class="evidence-header">
                    <span class="evidence-role ${ev.role.toLowerCase()}">
                        ${ev.role}
                    </span>
                    <span class="evidence-type">
                        ${ev.event_type}
                    </span>
                </div>

                <pre class="evidence-body">
${JSON.stringify(ev.event, null, 2)}
                </pre>
            `;

            container.appendChild(card);
        });
    }

    // MODAL CONTROL
    function openModal() {
        document.getElementById("alerts-modal").style.display = "block";
    }

    document.getElementById("alerts-modal-close").onclick = () => {
        document.getElementById("alerts-modal").style.display = "none";
    };
});
