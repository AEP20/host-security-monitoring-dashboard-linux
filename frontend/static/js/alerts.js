import { formatTimestamp } from "./utils.js";

document.addEventListener("DOMContentLoaded", () => {

    // PAGE GUARD
    if (!document.getElementById("alerts-table-body")) {
        console.debug("[alerts.js] Not on alerts page, aborting");
        return;
    }

    loadAlerts();

    // -----------------------------
    // LOAD ALERTS
    // -----------------------------
    function loadAlerts() {
        fetch("/api/alerts")
            .then(res => res.json())
            .then(json => {
                const tbody = document.getElementById("alerts-table-body");
                tbody.innerHTML = "";

                (json.data || []).forEach(alert => {
                    const tr = document.createElement("tr");

                    tr.innerHTML = `
                        <td>${formatTimestamp(alert.timestamp)}</td>
                        <td>
                            <span class="severity ${alert.severity.toLowerCase()}">
                                ${alert.severity}
                            </span>
                        </td>
                        <td>${alert.rule_name}</td>
                        <td>${alert.message}</td>
                        <td>
                            <button class="details-btn"
                                data-json='${JSON.stringify(alert)}'>
                                View
                            </button>
                        </td>
                    `;

                    tbody.appendChild(tr);
                });

                document.querySelectorAll(".details-btn").forEach(btn => {
                    btn.onclick = () =>
                        showModal(JSON.parse(btn.dataset.json));
                });
            })
            .catch(err => {
                console.error("[alerts.js] Failed to load alerts", err);
            });
    }

    // -----------------------------
    // MODAL
    // -----------------------------
    function showModal(obj) {
        document.getElementById("alerts-modal-body").innerText =
            JSON.stringify(obj, null, 4);

        document.getElementById("alerts-modal").style.display = "block";
    }

    document.getElementById("alerts-modal-close").onclick = () => {
        document.getElementById("alerts-modal").style.display = "none";
    };

});
