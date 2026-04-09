/* charts.js — reusable Chart.js instances — Cyberpunk theme */

const CHART_COLORS = {
    cyan:   '#00ffcc',
    yellow: '#fbbf24',
    green:  '#22d55a',
    red:    '#ff3b5c',
    grey:   '#5b6178',
    purple: '#a855f7',
    blue:   '#00aaff',
    pink:   '#e839f6'
};

const GRID_COLOR = 'rgba(255,255,255,0.04)';
const TICK_COLOR = '#5b6178';

// Global chart defaults
Chart.defaults.font.family = "'Inter', 'Space Grotesk', system-ui, sans-serif";
Chart.defaults.color = TICK_COLOR;

// ---- Traffic volume (line chart) ----
let trafficChartInstance = null;

function initTrafficChart() {
    const ctx = document.getElementById('trafficChart');
    if (!ctx) return;

    const gradient = ctx.getContext('2d').createLinearGradient(0, 0, 0, 280);
    gradient.addColorStop(0, 'rgba(0,255,204,0.15)');
    gradient.addColorStop(0.5, 'rgba(0,255,204,0.04)');
    gradient.addColorStop(1, 'rgba(0,255,204,0)');

    trafficChartInstance = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets',
                data: [],
                borderColor: CHART_COLORS.cyan,
                backgroundColor: gradient,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 6,
                pointHoverBackgroundColor: CHART_COLORS.cyan,
                pointHoverBorderColor: '#0f1119',
                pointHoverBorderWidth: 3,
                borderWidth: 2,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            scales: {
                x: {
                    grid: { color: GRID_COLOR, drawBorder: false },
                    ticks: { color: TICK_COLOR, maxTicksLimit: 12, font: { size: 10, family: "'JetBrains Mono', monospace" } },
                    border: { display: false }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: GRID_COLOR, drawBorder: false },
                    ticks: { color: TICK_COLOR, font: { size: 10, family: "'JetBrains Mono', monospace" } },
                    border: { display: false }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(15,17,25,0.9)',
                    borderColor: 'rgba(0,255,204,0.2)',
                    borderWidth: 1,
                    titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
                    bodyFont: { family: "'Inter', sans-serif", size: 12 },
                    padding: 12,
                    cornerRadius: 8,
                    displayColors: false
                }
            }
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
                borderWidth: 0,
                hoverOffset: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#9ca3af',
                        padding: 16,
                        usePointStyle: true,
                        pointStyleWidth: 8,
                        font: { size: 11, family: "'JetBrains Mono', monospace" }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(15,17,25,0.9)',
                    borderColor: 'rgba(0,255,204,0.2)',
                    borderWidth: 1,
                    padding: 12,
                    cornerRadius: 8,
                }
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
