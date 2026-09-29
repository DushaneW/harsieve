"use strict";
(() => {
    const body = document.querySelector("tbody");
    const original = Array.from(body.querySelectorAll("tr"));
    const search = document.getElementById("search");
    const status = document.getElementById("status");
    const order = document.getElementById("sort");
    function update() {
        const query = search.value.toLowerCase().trim();
        const rows = [...original];
        if (order.value === "slow")
            rows.sort(
                (a, b) =>
                    Number(b.dataset.duration) - Number(a.dataset.duration),
            );
        let count = 0;
        for (const row of rows) {
            row.hidden = !(
                row.textContent.toLowerCase().includes(query) &&
                (status.value === "all" || row.dataset.group === status.value)
            );
            if (!row.hidden) count += 1;
            body.appendChild(row);
        }
        document.getElementById("count").textContent =
            count + " of " + original.length + " requests";
        document.getElementById("empty").hidden = count !== 0;
    }
    search.addEventListener("input", update);
    status.addEventListener("change", update);
    order.addEventListener("change", update);
})();
