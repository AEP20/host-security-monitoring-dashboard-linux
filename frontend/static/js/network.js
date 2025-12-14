document.addEventListener("DOMContentLoaded", () => {

    document.querySelectorAll(".tab").forEach(btn => {
        btn.onclick = () => {
            document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
            btn.classList.add("active");

            let tab = btn.dataset.tab;
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
            document.querySelector("#tab-" + tab).classList.add("active");

            if (tab === "active") loadActiveConnections();
            if (tab === "events") loadNetworkEvents();
        };
    });

    loadActiveConnections();
    loadNetworkEvents();


    // ----------------------------------------
    // ACTIVE NETWORK CONNECTIONS
    // ----------------------------------------
    function loadActiveConnections() {
        fetch("/api/network/active")
            .then(res => res.json())
            .then(json => {
                let tbody = document.getElementById("active-network-table");
                tbody.innerHTML = "";

                (json.data || []).forEach(c => {
                    let tr = document.createElement("tr");

                    tr.innerHTML = `
                        <td>${c.pid || "-"}</td>
                        <td>${c.process_name}</td>
                        <td>${c.protocol}</td>
                        <td>${c.laddr_ip}:${c.laddr_port}</td>
                        <td>${c.raddr_ip ? c.raddr_ip + ":" + c.raddr_port : "-"}</td>
                        <td>${c.status}</td>
                        <td><button class="details-active-btn" data-json='${JSON.stringify(c)}'>View</button></td>
                    `;

                    tbody.appendChild(tr);
                });

                document.querySelectorAll(".details-active-btn").forEach(btn => {
                    btn.onclick = () => showModal(JSON.parse(btn.dataset.json));
                });
            });
    }


    // ----------------------------------------
    // NETWORK EVENT HISTORY
    // ----------------------------------------
    function loadNetworkEvents() {
    console.debug("[FE][NetworkEvents] Fetching /api/network/events");

    fetch("/api/network/events")
        .then(res => {
            console.debug("[FE][NetworkEvents] Response status:", res.status);
            if (!res.ok) {
                throw new Error("HTTP " + res.status);
            }
            return res.json();
        })
        .then(json => {
            console.debug(
                "[FE][NetworkEvents] Response parsed",
                "hasData=", Array.isArray(json.data),
                "count=", json.data ? json.data.length : 0
            );

            let tbody = document.getElementById("network-event-table");
            tbody.innerHTML = "";

            if (!json.data || json.data.length === 0) {
                console.warn("[FE][NetworkEvents] No events returned");
                return;
            }

            json.data.forEach(ev => {
                let tr = document.createElement("tr");

                tr.innerHTML = `
                    <td>${ev.timestamp}</td>
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
        })
        .catch(err => {
            console.error("[FE][NetworkEvents] Failed:", err);
        });
}


    // ----------------------------------------
    // EVENT DETAIL MODAL
    // ----------------------------------------
    function loadEventDetail(id) {
        fetch(`/api/network/events/${id}`)
            .then(res => res.json())
            .then(json => showModal(json.data));
    }


    function showModal(obj) {
        document.getElementById("modal-body").innerText =
            JSON.stringify(obj, null, 4);

        document.getElementById("network-modal").style.display = "block";
    }

    document.getElementById("modal-close").onclick = () => {
        document.getElementById("network-modal").style.display = "none";
    };

});
