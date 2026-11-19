/**
 * ZEROVANT — Screen 03: Repositories List
 */

window.RepositoriesModule = (function () {
  let allRepos = [];

  async function loadRepositories() {
    const tbody = document.getElementById('repos-table-tbody');
    if (!tbody) return;

    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

    const res = await window.api.getRepos(100, 0);
    if (!res.ok) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.textContent = 'Failed to load repositories.';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    allRepos = res.data.repos || [];
    renderReposTable(allRepos);

    const searchInput = document.getElementById('repos-search-input');
    if (searchInput) {
      searchInput.value = '';
      searchInput.oninput = () => {
        const query = searchInput.value.toLowerCase().trim();
        const filtered = allRepos.filter(
          (r) => (r.name && r.name.toLowerCase().includes(query)) || (r.url && r.url.toLowerCase().includes(query))
        );
        renderReposTable(filtered);
      };
    }
  }

  function renderReposTable(repos) {
    const tbody = document.getElementById('repos-table-tbody');
    if (!tbody) return;

    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

    if (repos.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.textContent = 'No repositories found.';
      td.className = 'text-muted';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    repos.forEach((r) => {
      const tr = document.createElement('tr');

      const tdName = document.createElement('td');
      tdName.className = 'mono';
      tdName.textContent = r.name || 'Unknown';

      const tdUrl = document.createElement('td');
      if (r.url && r.url.startsWith('https://')) {
        const a = document.createElement('a');
        a.href = r.url;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.textContent = r.url;
        tdUrl.appendChild(a);
      } else {
        tdUrl.textContent = r.url || 'Inline Target';
        tdUrl.className = 'text-muted';
      }

      const tdScans = document.createElement('td');
      tdScans.textContent = r.scan_count || 0;

      const tdScore = document.createElement('td');
      if (r.latest_score !== null && r.latest_score !== undefined) {
        tdScore.textContent = `${r.latest_score} / 100`;
      } else {
        tdScore.textContent = 'N/A';
      }

      const tdRisk = document.createElement('td');
      if (r.latest_risk_level) {
        const badge = document.createElement('span');
        badge.className = `badge badge-${r.latest_risk_level.toLowerCase()}`;
        badge.textContent = r.latest_risk_level;
        tdRisk.appendChild(badge);
      } else {
        tdRisk.textContent = '—';
      }

      const tdActions = document.createElement('td');
      const actionsDiv = document.createElement('div');
      actionsDiv.className = 'flex gap-2';

      const historyBtn = document.createElement('button');
      historyBtn.className = 'btn btn-outline btn-sm';
      historyBtn.textContent = 'History';
      historyBtn.addEventListener('click', () => {
        window.router.navigate(`comparison?repoId=${encodeURIComponent(r.id)}`);
      });

      const scanBtn = document.createElement('button');
      scanBtn.className = 'btn btn-primary btn-sm';
      scanBtn.textContent = 'Scan';
      scanBtn.addEventListener('click', () => {
        window.router.navigate('scanner');
        setTimeout(() => {
          const urlInput = document.getElementById('scan-repo-url');
          if (urlInput && r.url && r.url.startsWith('https://')) {
            urlInput.value = r.url;
          }
        }, 100);
      });

      actionsDiv.appendChild(historyBtn);
      actionsDiv.appendChild(scanBtn);
      tdActions.appendChild(actionsDiv);

      tr.appendChild(tdName);
      tr.appendChild(tdUrl);
      tr.appendChild(tdScans);
      tr.appendChild(tdScore);
      tr.appendChild(tdRisk);
      tr.appendChild(tdActions);

      tbody.appendChild(tr);
    });
  }

  return {
    init: loadRepositories,
  };
})();
