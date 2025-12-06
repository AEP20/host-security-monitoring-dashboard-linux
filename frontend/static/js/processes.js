document.addEventListener("DOMContentLoaded", () => {

    // -----------------------
    // TAB SWITCHING
    // -----------------------
    document.querySelectorAll(".tab").forEach(btn => {
        btn.onclick = () => {
            document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
            btn.classList.add("active");

            let tab = btn.dataset.tab;
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
            document.querySelector("#tab-" + tab).classList.add("active");

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
                let rows = json.data || [];
                let tbody = document.getElementById("active-process-table");
                tbody.innerHTML = "";

                rows.forEach(p => {
                    let tr = document.createElement("tr");

                    tr.innerHTML = `
                        <td>${p.pid}</td>
                        <td>${p.name}</td>
                        <td>${p.username}</td>
                        <td>${p.cpu.toFixed(1)}</td>
                        <td>${p.mem.toFixed(1)}</td>
                        <td>${p.cmdline}</td>
                        <td><button class="kill-btn" data-pid="${p.pid}">Kill</button></td>
                    `;

                    tbody.appendChild(tr);
                });

                document.querySelectorAll(".kill-btn").forEach(btn => {
                    // btn.onclick = () => killProcess(btn.dataset.pid); şimdilik yok cunku tehlikeli
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
                let tbody = document.getElementById("event-table");
                tbody.innerHTML = "";

                (json.data || []).forEach(ev => {
                    let tr = document.createElement("tr");

                    tr.innerHTML = `
                        <td>${ev.timestamp}</td>
                        <td>${ev.event_type}</td>
                        <td>${ev.pid}</td>
                        <td>${ev.process_name}</td>
                        <td><button class="details-btn" data-id="${ev.id}">View</button></td>
                    `;

                    tbody.appendChild(tr);
                });

                document.querySelectorAll(".details-btn").forEach(btn => {
                    btn.onclick = () => loadEventDetail(btn.dataset.id);
                });
            });
    }

    // -----------------------
    // KILL PROCESS
    // -----------------------
    function killProcess(pid) {
        fetch(`/api/process/${pid}`, { method: "DELETE" })
            .then(res => res.json())
            .then(() => loadActiveProcesses());
    }

    // -----------------------
    // EVENT DETAIL MODAL
    // -----------------------
    function loadEventDetail(id) {
        fetch(`/api/process/events/${id}`)
            .then(res => res.json())
            .then(json => {
                document.getElementById("modal-body").innerText =
                    JSON.stringify(json.data, null, 4);

                document.getElementById("event-modal").style.display = "block";
            });
    }

    document.getElementById("modal-close").onclick = () => {
        document.getElementById("event-modal").style.display = "none";
    };

});
