/* dashboard.js — main dashboard page logic */

(function () {
    // Init charts (defined in charts.js)
    initTrafficChart();
    initProtocolChart();

    // Severity helper
    function severityBadge(sev) {
        const cls = { HIGH: 'danger', MEDIUM: 'warning', LOW: 'info', INFO: 'secondary' }[sev] || 'secondary';
        return '<span class="badge bg-' + cls + '">' + sev + '</span>';
    }

    // --- Fetch status ---
    function fetchStatus() {
        fetch('/api/status')
            .then(r => r.json())
            .then(d => {
                document.getElementById('idsStatus').textContent = d.running ? 'Running' : 'Stopped';
                document.getElementById('idsStatus').className = 'stat-value ' + (d.running ? 'text-success' : 'text-danger');
                document.getElementById('idsUptime').textContent = d.uptime ? 'Uptime: ' + d.uptime : '';
                document.getElementById('totalPackets').textContent = d.total_packets.toLocaleString();
                document.getElementById('totalAlerts').textContent = d.total_alerts.toLocaleString();
            });
    }

    // --- Fetch traffic ---
    function fetchTraffic() {
        fetch('/api/traffic')
            .then(r => r.json())
            .then(d => {
                const snaps = d.traffic_snapshots || [];
                updateTrafficChart(snaps.map(s => s[0]), snaps.map(s => s[1]));

                const proto = d.protocol_distribution || {};
                updateProtocolChart(Object.keys(proto), Object.values(proto));
            });
    }

    // --- Fetch recent alerts ---
    function fetchAlerts() {
        fetch('/api/alerts')
            .then(r => r.json())
            .then(data => {
                const limited = data.slice(0, 10);
                const body = document.getElementById('recentAlertsBody');
                if (!limited.length) {
                    body.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No alerts yet</td></tr>';
                    return;
                }
                let highCount = data.filter(a => a.severity === 'HIGH').length;
                document.getElementById('highSeverity').textContent = highCount;

                body.innerHTML = limited.map(a =>
                    '<tr>' +
                    '<td>' + a.timestamp + '</td>' +
                    '<td><code>' + a.type + '</code></td>' +
                    '<td><code>' + a.src_ip + '</code></td>' +
                    '<td>' + severityBadge(a.severity) + '</td>' +
                    '<td>' + a.message + '</td>' +
                    '</tr>'
                ).join('');
            });
    }

    // --- Fetch top threat IPs ---
    function fetchTopThreats() {
        fetch('/api/top_threats')
            .then(r => r.json())
            .then(data => {
                const body = document.getElementById('topThreatsBody');
                if (!data.length) {
                    body.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No data yet</td></tr>';
                    return;
                }
                body.innerHTML = data.map(t => {
                    const highCls = t.high_alerts > 0 ? 'text-danger fw-bold' : '';
                    return '<tr>' +
                        '<td><code>' + t.ip + '</code></td>' +
                        '<td class="text-center">' + t.total_alerts + '</td>' +
                        '<td class="text-center ' + highCls + '">' + t.high_alerts + '</td>' +
                    '</tr>';
                }).join('');
            });
    }

    // Poll
    function refreshAll() {
        fetchStatus();
        fetchTraffic();
        fetchAlerts();
        fetchTopThreats();
    }

    refreshAll();
    setInterval(refreshAll, 3000);
})();
