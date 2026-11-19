/**
 * ZEROVANT — Screen 06: Risk Analytics
 */

window.AnalyticsModule = (function () {
  let scoreHistoryChart = null;
  let categoryChart = null;

  async function init() {
    const res = await window.api.getStats();
    if (!res.ok) return;

    const data = res.data;

    // Metrics
    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val !== undefined ? val : '0';
    };

    setVal('analytics-avg-score', `${data.average_repo_score || 0} / 100`);
    setVal('analytics-total-scans', data.total_scans || 0);
    setVal('analytics-critical-count', data.critical_count || 0);
    setVal('analytics-total-repos', data.total_repos || 0);

    // 1. Render Category Distribution Bar Chart
    renderCategoryChart(data.category_counts || {});

    // 2. Render Score Trajectory Line Chart
    renderTrajectoryChart(data.recent_scans || []);
  }

  function renderCategoryChart(categoryCounts) {
    const ctx = document.getElementById('chart-analytics-categories');
    if (!ctx || !window.Chart) return;

    if (categoryChart) categoryChart.destroy();

    const labels = Object.keys(categoryCounts);
    const counts = Object.values(categoryCounts);

    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const barColor = isLight ? 'rgba(57, 123, 88, 0.7)' : 'rgba(168, 230, 192, 0.7)';

    categoryChart = new window.Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels.length > 0 ? labels : ['No findings'],
        datasets: [
          {
            label: 'Findings per Category',
            data: counts.length > 0 ? counts : [0],
            backgroundColor: barColor,
            borderRadius: 6,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
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

  function renderTrajectoryChart(recentScans) {
    const ctx = document.getElementById('chart-analytics-trajectory');
    if (!ctx || !window.Chart) return;

    if (scoreHistoryChart) scoreHistoryChart.destroy();

    const scans = [...recentScans].reverse();
    const labels = scans.map((s, idx) => `Scan #${idx + 1}`);
    const scores = scans.map((s) => s.repo_score);

    scoreHistoryChart = new window.Chart(ctx, {
      type: 'line',
      data: {
        labels: labels.length > 0 ? labels : ['Scan #1'],
        datasets: [
          {
            label: 'Risk Score Over Time',
            data: scores.length > 0 ? scores : [0],
            borderColor: '#79BD99',
            backgroundColor: 'rgba(121, 189, 153, 0.1)',
            borderWidth: 2.5,
            fill: true,
            tension: 0.3,
            pointBackgroundColor: '#79BD99',
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

  return {
    init: init,
  };
})();
