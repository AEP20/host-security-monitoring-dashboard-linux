import { formatTimestamp } from "./utils.js";

document.addEventListener("DOMContentLoaded", () => {

    // PAGE GUARD
    if (!document.getElementById("active-network-table")) {
        console.debug("[network.js] Not on network page, aborting");
        return;
    }

    // -----------------------------
    // TAB SWITCHING
    // -----------------------------
    document.querySelectorAll(".tab").forEach(btn => {
        btn.onclick = () => {
            document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
            btn.classList.add("active");

            const tab = btn.dataset.tab;

            document.querySelectorAll(".tab-content").forEach(c =>
                c.classList.remove("active")
            );

            document
                .querySelector("#network-tab-" + tab)
                .classList.add("active");

            if (tab === "active") loadActiveConnections();
            if (tab === "events") loadNetworkEvents();
        };
    });

    loadActiveConnections();
    loadNetworkEvents();

    // -----------------------------
    // ACTIVE CONNECTIONS
    // -----------------------------
    function loadActiveConnections() {
        fetch("/api/network/active")
            .then(res => res.json())
            .then(json => {
                const tbody = document.getElementById("active-network-table");
                tbody.innerHTML = "";

                (json.data || []).forEach(c => {
                    const tr = document.createElement("tr");

                    tr.innerHTML = `
                        <td>${c.pid || "-"}</td>
                        <td>${c.process_name}</td>
                        <td>${c.protocol}</td>
                        <td>${c.laddr_ip}:${c.laddr_port}</td>
                        <td>${c.raddr_ip ? c.raddr_ip + ":" + c.raddr_port : "-"}</td>
                        <td>${c.status}</td>
                        <td>
                            <button class="details-active-btn"
                                data-json='${JSON.stringify(c)}'>
                                View
                            </button>
                        </td>
                    `;

                    tbody.appendChild(tr);
                });

                document.querySelectorAll(".details-active-btn").forEach(btn => {
                    btn.onclick = () =>
                        showModal(JSON.parse(btn.dataset.json));
                });
            });
    }

    // -----------------------------
    // NETWORK EVENTS
    // -----------------------------
    function loadNetworkEvents() {
        fetch("/api/network/events")
            .then(res => res.json())
            .then(json => {
                const tbody = document.getElementById("network-event-table");
                tbody.innerHTML = "";

                (json.data || []).forEach(ev => {
                    const tr = document.createElement("tr");

                    tr.innerHTML = `
                        <td>${formatTimestamp(ev.timestamp)}</td>
                        <td>${ev.event_type}</td>
                        <td>${ev.pid ?? "-"}</td>
                        <td>${ev.process_name ?? "-"}</td>
                        <td>
                            <button class="details-btn" data-id="${ev.id}">
                                View
                            </button>
                        </td>
                    `;

                    tbody.appendChild(tr);
                });

                document.querySelectorAll(".details-btn").forEach(btn => {
                    btn.onclick = () => loadEventDetail(btn.dataset.id);
                });
            });
    }

    // -----------------------------
    // EVENT DETAIL
    // -----------------------------
    function loadEventDetail(id) {
        fetch(`/api/network/events/${id}`)
            .then(res => res.json())
            .then(json => showModal(json.data));
    }

    // -----------------------------
    // MODAL
    // -----------------------------
    function showModal(obj) {
        document.getElementById("network-modal-body").innerText =
            JSON.stringify(obj, null, 4);

        document.getElementById("network-modal").style.display = "block";
    }

    document.getElementById("network-modal-close").onclick = () => {
        document.getElementById("network-modal").style.display = "none";
    };

});
