// Helper: fetch JSON with error handling
async function fetchJson(path) {
    const r = await fetch(path);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
}

// ---------------------- LIST PAGE LOGIC ----------------------
if (document.querySelector("#cve-table")) {
    let page = 1;
    const tbody = document.querySelector("#cve-table tbody");
    const totalEl = document.getElementById("total");
    const perSel = document.getElementById("resultsPerPage");
    const pageEl = document.getElementById("page");
    const prevBtn = document.getElementById("prev");
    const nextBtn = document.getElementById("next");
    const rangeEl = document.getElementById("range");
    const syncBtn = document.getElementById("sync");

    // Load CVEs into table
    async function load() {
        const per = parseInt(perSel.value, 10);
        const data = await fetchJson(`/api/cves?page=${page}&resultsPerPage=${per}`);
        totalEl.textContent = data.total;
        pageEl.textContent = data.page;
        tbody.innerHTML = "";
        const start = (data.page - 1) * data.per_page + 1;
        const end = Math.min(data.page * data.per_page, data.total);
        rangeEl.textContent = `${start} - ${end} of ${data.total} records`;

        for (const r of data.results) {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${r.cve_id}</td>
                <td>${r.identifier || ""}</td>
                <td>${r.published_date ? new Date(r.published_date).toLocaleDateString() : ""}</td>
                <td>${r.last_modified_date ? new Date(r.last_modified_date).toLocaleDateString() : ""}</td>
                <td>${r.status || ""}</td>
            `;
            tr.addEventListener("click", () => (location.href = "/cves/" + r.cve_id));
            tbody.appendChild(tr);
        }
    }

    prevBtn.onclick = async () => {
        if (page > 1) page--;
        await load();
    };
    nextBtn.onclick = async () => {
        page++;
        await load();
    };
    perSel.onchange = async () => {
        page = 1;
        await load();
    };

    // Improved Sync button (fetches from NVD API and reloads)
    syncBtn.onclick = async () => {
        syncBtn.disabled = true;
        syncBtn.textContent = "Syncing...";
        try {
            // Call full sync for richer data
            const res = await fetchJson("/sync/full?batch_size=100&max_pages=1");

            if (res.status === "ok" || res.imported) {
                alert(`✅ Sync complete! Imported ${res.imported || 0} records.`);
                page = 1;
                await load(); // reload table automatically
            } else {
                alert("⚠️ Sync finished but no new records were imported.");
            }
        } catch (err) {
            console.error(err);
            alert("❌ Sync failed: " + err.message);
        }
        syncBtn.disabled = false;
        syncBtn.textContent = "Sync (fetch 100)";
    };

    load();
}

// ---------------------- DETAILS PAGE LOGIC ----------------------
if (document.getElementById("cve-id")) {
    (async () => {
        try {
            const data = await fetchJson("/api/cves/" + encodeURIComponent(cveId));
            document.getElementById("cve-id").textContent = data.cve_id;
            document.getElementById("desc").textContent = data.description || "No description available";

            const raw = data.raw_json || {};
            const metrics = raw.metrics || {};
            let v2 = null;
            if (metrics.cvssMetricV2) {
                v2 = metrics.cvssMetricV2[0];
            }

            // CVSS V2 Section
            if (v2 && v2.cvssData) {
                document.getElementById("cvss-v2-section").style.display = "";
                const d = v2.cvssData;
                document.getElementById("severity").textContent = v2.baseSeverity || "";
                document.getElementById("score").textContent = d.baseScore ?? "";
                document.getElementById("vector").textContent = d.vectorString ?? "";
                document.getElementById("accessVector").textContent = d.accessVector ?? "";
                document.getElementById("accessComplexity").textContent = d.accessComplexity ?? "";
                document.getElementById("authentication").textContent = d.authentication ?? "";
                document.getElementById("confImpact").textContent = d.confidentialityImpact ?? "";
                document.getElementById("integImpact").textContent = d.integrityImpact ?? "";
                document.getElementById("availImpact").textContent = d.availabilityImpact ?? "";
            }

            // Scores
            if (v2) {
                document.getElementById("scores-section").style.display = "";
                document.getElementById("exploit").textContent = v2.exploitabilityScore ?? "";
                document.getElementById("impact").textContent = v2.impactScore ?? "";
            }

            // CPE Table
            const configs = raw.configurations || {};
            let cpes = [];
            if (configs.nodes) {
                configs.nodes.forEach((node) => {
                    (node.cpeMatch || []).forEach((match) => {
                        cpes.push({
                            criteria: match.criteria,
                            matchCriteriaId: match.matchCriteriaId,
                            vulnerable: match.vulnerable ? "Yes" : "No",
                        });
                    });
                });
            }

            if (cpes.length > 0) {
                document.getElementById("cpe-section").style.display = "";
                const tbody = document.querySelector("#cpe-table tbody");
                tbody.innerHTML = "";
                for (const c of cpes) {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `<td>${c.criteria}</td><td>${c.matchCriteriaId}</td><td>${c.vulnerable}</td>`;
                    tbody.appendChild(tr);
                }
            }
        } catch (e) {
            document.getElementById("cve-id").textContent = "Not found";
            console.error(e);
        }
    })();
}
