/* charts.js — reusable Chart.js instances for the main dashboard page */

const CHART_COLORS = {
    cyan:   '#0dcaf0',
    yellow: '#ffc107',
    green:  '#198754',
    red:    '#dc3545',
    grey:   '#6c757d',
    purple: '#6f42c1'
};

const GRID_COLOR = '#262a36';

// ---- Traffic volume (line chart) ----
let trafficChartInstance = null;

function initTrafficChart() {
    const ctx = document.getElementById('trafficChart');
    if (!ctx) return;
    trafficChartInstance = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets',
                data: [],
                borderColor: CHART_COLORS.cyan,
                backgroundColor: 'rgba(13,202,240,0.08)',
                fill: true,
                tension: 0.35,
                pointRadius: 2,
                pointHoverRadius: 5,
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            scales: {
                x: { grid: { color: GRID_COLOR }, ticks: { color: '#8b8fa3', maxTicksLimit: 15 } },
                y: { beginAtZero: true, grid: { color: GRID_COLOR }, ticks: { color: '#8b8fa3' } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function updateTrafficChart(labels, data) {
    if (!trafficChartInstance) return;
    trafficChartInstance.data.labels = labels;
    trafficChartInstance.data.datasets[0].data = data;
    trafficChartInstance.update();
}

// ---- Protocol distribution (doughnut) ----
let protocolChartInstance = null;

function initProtocolChart() {
    const ctx = document.getElementById('protocolChart');
    if (!ctx) return;
    protocolChartInstance = new Chart(ctx.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [CHART_COLORS.cyan, CHART_COLORS.yellow, CHART_COLORS.green, CHART_COLORS.grey],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: { position: 'bottom', labels: { color: '#ccc', padding: 14, usePointStyle: true } }
            }
        }
    });
}

function updateProtocolChart(labels, data) {
    if (!protocolChartInstance) return;
    const colors = labels.map(l => ({TCP: CHART_COLORS.cyan, UDP: CHART_COLORS.yellow, ICMP: CHART_COLORS.green}[l] || CHART_COLORS.grey));
    protocolChartInstance.data.labels = labels;
    protocolChartInstance.data.datasets[0].data = data;
    protocolChartInstance.data.datasets[0].backgroundColor = colors;
    protocolChartInstance.update();
}
