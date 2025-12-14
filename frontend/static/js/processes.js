import { formatTimestamp } from "./utils.js";

document.addEventListener("DOMContentLoaded", () => {

    // PAGE GUARD
    if (!document.getElementById("active-process-table")) {
        console.debug("[processes.js] Not on processes page, aborting");
        return;
    }

    // -----------------------
    // TAB SWITCHING
    // -----------------------
    document.querySelectorAll(".tab").forEach(btn => {
        btn.onclick = () => {
            document.querySelectorAll(".tab").forEach(t =>
                t.classList.remove("active")
            );
            btn.classList.add("active");

            const tab = btn.dataset.tab;

            document.querySelectorAll(".tab-content").forEach(c =>
                c.classList.remove("active")
            );

            document
                .querySelector("#process-tab-" + tab)
                .classList.add("active");

            if (tab === "active") loadActiveProcesses();
            if (tab === "events") loadProcessEvents();
        };
    });

    loadActiveProcesses();
    loadProcessEvents();

    // -----------------------
    // LOAD ACTIVE PROCESSES
    // -----------------------
    function loadActiveProcesses() {
        fetch("/api/process/active")
            .then(res => res.json())
            .then(json => {
                const rows = json.data || [];
                const tbody = document.getElementById("active-process-table");
                tbody.innerHTML = "";

                rows.forEach(p => {
                    const tr = document.createElement("tr");

                    tr.innerHTML = `
                        <td>${p.pid}</td>
                        <td>${p.name}</td>
                        <td>${p.username}</td>
                        <td>${p.cpu.toFixed(1)}</td>
                        <td>${p.mem.toFixed(1)}</td>
                        <td>${p.cmdline}</td>
                        <td>
                            <button class="kill-btn" data-pid="${p.pid}">
                                Kill
                            </button>
                        </td>
                    `;

                    tbody.appendChild(tr);
                });
            });
    }

    // -----------------------
    // LOAD EVENT HISTORY
    // -----------------------
    function loadProcessEvents() {
        fetch("/api/process/events")
            .then(res => res.json())
            .then(json => {
                const tbody = document.getElementById("event-table");
                tbody.innerHTML = "";

                (json.data || []).forEach(ev => {
                    const tr = document.createElement("tr");

                    tr.innerHTML = `
                        <td>${formatTimestamp(ev.timestamp)}</td>
                        <td>${ev.event_type}</td>
                        <td>${ev.pid}</td>
                        <td>${ev.process_name}</td>
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

    // -----------------------
    // EVENT DETAIL
    // -----------------------
    function loadEventDetail(id) {
        fetch(`/api/process/events/${id}`)
            .then(res => res.json())
            .then(json => showModal(json.data));
    }

    // -----------------------
    // MODAL
    // -----------------------
    function showModal(obj) {
        document.getElementById("process-modal-body").innerText =
            JSON.stringify(obj, null, 4);

        document.getElementById("process-modal").style.display = "block";
    }

    document.getElementById("process-modal-close").onclick = () => {
        document.getElementById("process-modal").style.display = "none";
    };

});
