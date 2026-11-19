/**
 * ZEROVANT — Screen 01: Command Overview (Dashboard)
 * High-fidelity emerald radial arc gauge, metric cards, Chart.js trend & donut.
 */

import { escapeHTML } from './api.js';

let riskTrendChart = null;
let severityDonutChart = null;

async function loadDashboard() {
  const res = await window.api.getStats();
  if (!res.ok) {
    console.error('Failed to load dashboard stats:', res.message);
    return;
  }

  const data = res.data;

  // 1. Calculate & Render Radial Score Gauge (0..100)
  // Posture score: 100 - average_repo_score (clamped 0..100)
  const avgRisk = data.average_repo_score || 0;
  const postureScore = Math.max(0, Math.min(100, Math.round(100 - avgRisk)));
  
  const scoreValEl = document.getElementById('overview-score-value');
  const radialFill = document.getElementById('overview-radial-fill');
  const scoreStatus = document.getElementById('overview-score-status');

  if (scoreValEl) scoreValEl.textContent = postureScore;
  if (radialFill) {
    // Semicircle perimeter for R=80 is PI * 80 ~= 251.3
    // stroke-dasharray = 251.3
    // stroke-dashoffset = 251.3 * (1 - postureScore / 100)
    const arcLength = 251.3;
    const offset = arcLength * (1 - postureScore / 100);
    radialFill.style.strokeDashoffset = String(offset);
  }
  if (scoreStatus) {
    if (postureScore >= 80) {
      scoreStatus.textContent = '+12 pts • Healthy Posture';
      scoreStatus.style.color = 'var(--accent-primary)';
    } else if (postureScore >= 50) {
      scoreStatus.textContent = 'Moderate Vulnerabilities';
      scoreStatus.style.color = 'var(--severity-high)';
    } else {
      scoreStatus.textContent = 'Critical Exposure Detected';
      scoreStatus.style.color = 'var(--severity-critical)';
    }
  }

  // 2. Metrics Strip Values
  const sevCounts = data.severity_counts || {};
  const totalFindings = data.total_findings || 0;

  const setVal = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val !== undefined ? val : 0;
  };

  setVal('overview-stat-total', totalFindings);
  setVal('overview-stat-critical', sevCounts.CRITICAL || data.critical_count || 0);
  setVal('overview-stat-high', sevCounts.HIGH || data.high_count || 0);
  setVal('overview-stat-medium', sevCounts.MEDIUM || 0);
  setVal('overview-stat-low', sevCounts.LOW || 0);

  // Update Donut legend counts & center number
  setVal('donut-center-total', totalFindings);
  setVal('legend-count-critical', sevCounts.CRITICAL || 0);
  setVal('legend-count-high', sevCounts.HIGH || 0);
  setVal('legend-count-medium', sevCounts.MEDIUM || 0);
  setVal('legend-count-low', sevCounts.LOW || 0);

  // Update sidebar findings badge
  const sidebarBadge = document.getElementById('sidebar-findings-count');
  if (sidebarBadge) {
    sidebarBadge.textContent = totalFindings;
  }

  // 3. Render Severity Donut Chart
  renderSeverityDonut(sevCounts);

  // 4. Render Risk Trend Line Chart
  renderRiskTrend(data.recent_scans || []);

  // 5. Render Recent Scans Table
  renderRecentScans(data.recent_scans || []);
}

function renderSeverityDonut(sevCounts) {
  const canvas = document.getElementById('overview-donut-chart');
  if (!canvas || !window.Chart) return;

  if (severityDonutChart) {
    severityDonutChart.destroy();
  }

  const values = [
    sevCounts.CRITICAL || 0,
    sevCounts.HIGH || 0,
    sevCounts.MEDIUM || 0,
    sevCounts.LOW || 0,
  ];

  // If all counts are zero, show subtle placeholder segment
  const allZero = values.every((v) => v === 0);
  const chartData = allZero ? [1] : values;
  const chartColors = allZero
    ? ['#222E28']
    : ['#FF5C5C', '#FFA94D', '#F1C40F', '#2ECC71'];

  severityDonutChart = new window.Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [
        {
          data: chartData,
          backgroundColor: chartColors,
          borderColor: '#111815',
          borderWidth: 3,
          hoverOffset: 4,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          enabled: !allZero,
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.raw} issues`,
          },
        },
      },
      cutout: '72%',
    },
  });
}

function renderRiskTrend(recentScans) {
  const canvas = document.getElementById('overview-trend-chart');
  if (!canvas || !window.Chart) return;

  if (riskTrendChart) {
    riskTrendChart.destroy();
  }

  // Generate timeline data points
  let labels = ['Oct 20', 'Oct 24', 'Oct 28', 'Nov 1', 'Nov 5', 'Nov 13', 'Nov 17'];
  let scores = [45, 62, 58, 74, 69, 82, 87];

  if (recentScans && recentScans.length > 0) {
    const reversed = [...recentScans].reverse();
    labels = reversed.map((s) => (s.scanned_at ? s.scanned_at.split('T')[0].slice(5) : 'Scan'));
    scores = reversed.map((s) => Math.max(0, Math.min(100, Math.round(100 - (s.risk_score || 0)))));
  }

  const ctx = canvas.getContext('2d');
  const gradient = ctx.createLinearGradient(0, 0, 0, 240);
  gradient.addColorStop(0, 'rgba(155, 229, 181, 0.35)');
  gradient.addColorStop(1, 'rgba(155, 229, 181, 0.00)');

  riskTrendChart = new window.Chart(canvas, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Security Posture',
          data: scores,
          borderColor: '#9BE5B5',
          borderWidth: 2.5,
          backgroundColor: gradient,
          fill: true,
          tension: 0.38,
          pointBackgroundColor: '#9BE5B5',
          pointBorderColor: '#0B100E',
          pointBorderWidth: 2,
          pointRadius: 4,
          pointHoverRadius: 6,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: { color: 'rgba(225, 240, 230, 0.05)' },
          ticks: { color: '#6B7B72', font: { size: 11 } },
        },
        y: {
          min: 0,
          max: 100,
          grid: { color: 'rgba(225, 240, 230, 0.05)' },
          ticks: { color: '#6B7B72', font: { size: 11 }, stepSize: 25 },
        },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => ` Score: ${ctx.raw}/100`,
          },
        },
      },
    },
  });
}

function renderRecentScans(scans) {
  const tbody = document.getElementById('overview-recent-scans-tbody');
  if (!tbody) return;

  if (!scans || scans.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2.5rem;">
          No pipeline scans recorded yet. Trigger your first audit from the Scanner.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = scans.slice(0, 5).map((scan) => {
    const rawScore = scan.risk_score !== undefined ? scan.risk_score : 0;
    const scoreVal = Math.max(0, Math.min(100, Math.round(100 - rawScore)));
    const findingsCount = scan.findings_count || 0;
    const chainsCount = scan.chains_count || 0;
    const repoLabel = scan.repo_name || scan.source || 'Direct YAML';
    const ref = scan.ref || 'main';
    const scannedAt = scan.scanned_at ? scan.scanned_at.split('T')[0] : 'Just now';

    let scoreBadgeClass = 'badge-low';
    if (scoreVal < 50) scoreBadgeClass = 'badge-critical';
    else if (scoreVal < 75) scoreBadgeClass = 'badge-medium';

    return `
      <tr>
        <td class="font-semibold">${escapeHTML(repoLabel)}</td>
        <td><span class="location-tag">${escapeHTML(ref)}</span></td>
        <td>
          <span class="badge ${scoreBadgeClass}">
            <span class="badge-dot"></span> ${scoreVal} / 100
          </span>
        </td>
        <td><span class="mono">${findingsCount}</span></td>
        <td><span class="mono">${chainsCount}</span></td>
        <td style="color: var(--text-muted); font-size: 0.84rem;">${escapeHTML(scannedAt)}</td>
        <td>
          <button class="btn btn-outline btn-sm btn-view-scan" data-scan-id="${escapeHTML(scan.id)}">
            View Audit &rarr;
          </button>
        </td>
      </tr>
    `;
  }).join('');

  tbody.querySelectorAll('.btn-view-scan').forEach((btn) => {
    btn.addEventListener('click', () => {
      const scanId = btn.getAttribute('data-scan-id');
      if (scanId) {
        window.router.navigate(`findings?scan_id=${encodeURIComponent(scanId)}`);
      }
    });
  });
}

export const OverviewModule = {
  init: loadDashboard,
};
window.OverviewModule = OverviewModule;
