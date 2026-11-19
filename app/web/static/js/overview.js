/**
 * ZEROVANT — Screen 01: Command Overview (Dashboard)
 */

window.OverviewModule = (function () {
  let riskTrendChart = null;
  let severityDonutChart = null;

  async function loadDashboard() {
    const res = await window.api.getStats();
    if (!res.ok) {
      console.error('Failed to load stats:', res.message);
      return;
    }

    const data = res.data;

    // 1. Security Score Gauge
    // Posture score: 100 - average_repo_score (clamped 0..100)
    const avgRisk = data.average_repo_score || 0;
    const postureScore = Math.max(0, Math.min(100, Math.round(100 - avgRisk)));
    
    const gaugeEl = document.getElementById('overview-score-gauge');
    const gaugeValEl = document.getElementById('overview-score-val');
    if (gaugeValEl) gaugeValEl.textContent = postureScore;
    if (gaugeEl) {
      gaugeEl.style.setProperty('--gauge-pct', postureScore);
    }

    // 2. Metrics Cards
    const sevCounts = data.severity_counts || {};
    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val !== undefined ? val : 0;
    };

    setVal('stat-total-findings', data.total_findings || 0);
    setVal('stat-critical-count', sevCounts.CRITICAL || data.critical_count || 0);
    setVal('stat-high-count', sevCounts.HIGH || data.high_count || 0);
    setVal('stat-medium-count', sevCounts.MEDIUM || 0);
    setVal('stat-low-count', sevCounts.LOW || 0);

    // Update sidebar findings badge
    const sidebarBadge = document.getElementById('sidebar-findings-count');
    if (sidebarBadge) {
      sidebarBadge.textContent = data.total_findings || 0;
    }

    // 3. Render Severity Donut Chart
    renderSeverityDonut(sevCounts);

    // 4. Render Risk Trend Chart
    renderRiskTrend(data.recent_scans || []);

    // 5. Populate Recent Scans Table
    renderRecentScans(data.recent_scans || []);
  }

  function renderSeverityDonut(sevCounts) {
    const ctx = document.getElementById('chart-severity-donut');
    if (!ctx || !window.Chart) return;

    if (severityDonutChart) {
      severityDonutChart.destroy();
    }

    const labels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
    const values = [
      sevCounts.CRITICAL || 0,
      sevCounts.HIGH || 0,
      sevCounts.MEDIUM || 0,
      sevCounts.LOW || 0,
      sevCounts.INFO || 0,
    ];

    severityDonutChart = new window.Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [
          {
            data: values,
            backgroundColor: [
              '#FF5C5C',
              '#FFA94D',
              '#F1C40F',
              '#2ECC71',
              '#BDC3C7',
            ],
            borderColor: '#101513',
            borderWidth: 2,
            hoverOffset: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: '#9BAAA1',
              font: { size: 11, family: 'sans-serif' },
              boxWidth: 10,
              padding: 10,
            },
          },
        },
        cutout: '68%',
      },
    });
  }

  function renderRiskTrend(recentScans) {
    const ctx = document.getElementById('chart-risk-trend');
    if (!ctx || !window.Chart) return;

    if (riskTrendChart) {
      riskTrendChart.destroy();
    }

    const scans = [...recentScans].reverse();
    const labels = scans.length > 0 
      ? scans.map((s, idx) => `Scan #${idx + 1}`) 
      : ['No scans yet'];
    const scores = scans.length > 0 
      ? scans.map((s) => s.repo_score) 
      : [0];

    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const accentColor = isLight ? '#397B58' : '#A8E6C0';
    const fillColor = isLight ? 'rgba(57, 123, 88, 0.12)' : 'rgba(168, 230, 192, 0.12)';

    riskTrendChart = new window.Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Risk Score (0-100)',
            data: scores,
            borderColor: accentColor,
            backgroundColor: fillColor,
            borderWidth: 2.5,
            fill: true,
            tension: 0.35,
            pointBackgroundColor: accentColor,
            pointBorderColor: '#101513',
            pointRadius: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            max: 100,
            grid: { color: 'rgba(220, 235, 225, 0.06)' },
            ticks: { color: '#64756B', font: { size: 10 } },
          },
          x: {
            grid: { display: false },
            ticks: { color: '#64756B', font: { size: 10 } },
          },
        },
        plugins: {
          legend: { display: false },
        },
      },
    });
  }

  function renderRecentScans(scans) {
    const tbody = document.getElementById('recent-scans-tbody');
    if (!tbody) return;

    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

    if (!scans || scans.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.textContent = 'No scan history recorded yet. Launch your first audit!';
      td.className = 'text-muted';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    scans.forEach((s) => {
      const tr = document.createElement('tr');

      const tdRepo = document.createElement('td');
      tdRepo.className = 'mono';
      tdRepo.textContent = s.repo_name || 'Inline YAML';

      const tdScore = document.createElement('td');
      tdScore.textContent = `${s.repo_score} / 100`;

      const tdRisk = document.createElement('td');
      const riskBadge = document.createElement('span');
      const lvl = (s.risk_level || 'LOW').toUpperCase();
      riskBadge.className = `badge badge-${lvl.toLowerCase()}`;
      riskBadge.textContent = lvl;
      tdRisk.appendChild(riskBadge);

      const tdFindings = document.createElement('td');
      tdFindings.textContent = s.finding_count || 0;

      const tdChains = document.createElement('td');
      tdChains.textContent = s.chain_count || 0;

      const tdAction = document.createElement('td');
      const viewBtn = document.createElement('button');
      viewBtn.className = 'btn btn-outline btn-sm';
      viewBtn.textContent = 'View Scan';
      viewBtn.addEventListener('click', () => {
        window.router.navigate(`findings?scanId=${encodeURIComponent(s.id)}`);
      });
      tdAction.appendChild(viewBtn);

      tr.appendChild(tdRepo);
      tr.appendChild(tdScore);
      tr.appendChild(tdRisk);
      tr.appendChild(tdFindings);
      tr.appendChild(tdChains);
      tr.appendChild(tdAction);

      tbody.appendChild(tr);
    });
  }

  return {
    init: loadDashboard,
  };
})();
