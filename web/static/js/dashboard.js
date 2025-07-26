// nginx-defender Dashboard JavaScript

class Dashboard {
    constructor() {
        this.ws = null;
        this.charts = {};
        this.data = {
            blockedIPs: [],
            threats: [],
            metrics: {}
        };
        this.init();
    }

    async init() {
        await this.loadInitialData();
        this.initWebSocket();
        this.initCharts();
        this.initEventListeners();
        this.startPeriodicUpdates();
        console.log('Dashboard initialized successfully');
    }

    // WebSocket connection for real-time updates
    initWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        this.ws = new WebSocket(wsUrl);
        
        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.updateConnectionStatus(true);
        };
        
        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleWebSocketMessage(data);
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        };
        
        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            this.updateConnectionStatus(false);
            // Attempt to reconnect after 5 seconds
            setTimeout(() => this.initWebSocket(), 5000);
        };
        
        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.updateConnectionStatus(false);
        };
    }

    handleWebSocketMessage(data) {
        switch (data.type) {
            case 'threat_detected':
                this.addThreatToFeed(data.threat);
                this.updateThreatMetrics();
                break;
            case 'ip_blocked':
                this.addBlockedIP(data.ip);
                this.updateBlockedIPsCount();
                break;
            case 'metrics_update':
                this.updateMetrics(data.metrics);
                break;
            case 'system_alert':
                this.showNotification(data.message, data.severity);
                break;
            default:
                console.log('Unknown message type:', data.type);
        }
    }

    // Load initial data from API
    async loadInitialData() {
        try {
            const [blockedIPs, threats, metrics] = await Promise.all([
                this.fetchAPI('/api/v1/blocked-ips'),
                this.fetchAPI('/api/v1/threats'),
                this.fetchAPI('/api/v1/metrics')
            ]);

            this.data.blockedIPs = blockedIPs.data || [];
            this.data.threats = threats.data || [];
            this.data.metrics = metrics.data || {};

            this.updateDashboard();
        } catch (error) {
            console.error('Error loading initial data:', error);
            this.showNotification('Failed to load dashboard data', 'error');
        }
    }

    // Initialize charts
    initCharts() {
        this.initThreatChart();
        this.initThreatTypeChart();
        this.initWorldMap();
    }

    initThreatChart() {
        const ctx = document.getElementById('threatChart').getContext('2d');
        
        this.charts.threatChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: this.generateTimeLabels(24),
                datasets: [{
                    label: 'Threats Detected',
                    data: new Array(24).fill(0),
                    borderColor: 'rgb(220, 53, 69)',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.4,
                    fill: true
                }, {
                    label: 'IPs Blocked',
                    data: new Array(24).fill(0),
                    borderColor: 'rgb(0, 123, 255)',
                    backgroundColor: 'rgba(0, 123, 255, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                },
                interaction: {
                    mode: 'nearest',
                    axis: 'x',
                    intersect: false
                }
            }
        });
    }

    initThreatTypeChart() {
        const ctx = document.getElementById('threatTypeChart').getContext('2d');
        
        this.charts.threatTypeChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['SQL Injection', 'XSS', 'Brute Force', 'DDoS', 'Bot Traffic', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#dc3545',
                        '#fd7e14',
                        '#ffc107',
                        '#28a745',
                        '#17a2b8',
                        '#6c757d'
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    }

    initWorldMap() {
        // Initialize Leaflet map for global threat visualization
        this.map = L.map('world-map').setView([20, 0], 2);
        
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        }).addTo(this.map);

        this.threatMarkers = L.layerGroup().addTo(this.map);
    }

    // Event listeners
    initEventListeners() {
        // Refresh buttons
        document.addEventListener('click', (e) => {
            if (e.target.closest('[onclick*="refresh"]')) {
                const button = e.target.closest('button');
                if (button) {
                    button.classList.add('loading');
                    setTimeout(() => button.classList.remove('loading'), 1000);
                }
            }
        });

        // Tab navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const target = e.target.getAttribute('href').substring(1);
                this.switchTab(target);
            });
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch (e.key) {
                    case 'r':
                        e.preventDefault();
                        this.refreshData();
                        break;
                    case 'f':
                        e.preventDefault();
                        document.querySelector('#search-input')?.focus();
                        break;
                }
            }
        });
    }

    // Update dashboard components
    updateDashboard() {
        this.updateStatusCards();
        this.updateBlockedIPsTable();
        this.updateThreatFeed();
        this.updateCharts();
        this.updateSystemMetrics();
    }

    updateStatusCards() {
        const metrics = this.data.metrics;
        
        document.getElementById('blocked-ips-count').textContent = 
            metrics.blocked_ips_total || this.data.blockedIPs.length;
        
        document.getElementById('threats-detected').textContent = 
            metrics.threats_detected_total || this.data.threats.length;
        
        document.getElementById('requests-per-minute').textContent = 
            metrics.requests_per_minute || 0;
        
        // Update uptime
        if (metrics.uptime_seconds) {
            const uptime = this.formatUptime(metrics.uptime_seconds);
            document.getElementById('uptime').textContent = uptime;
        }
    }

    updateBlockedIPsTable() {
        const tbody = document.getElementById('blocked-ips-table');
        tbody.innerHTML = '';

        const recentIPs = this.data.blockedIPs.slice(0, 10);
        
        recentIPs.forEach(ip => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>
                    <code>${ip.address}</code>
                    ${ip.is_tor ? '<span class="badge bg-dark">TOR</span>' : ''}
                    ${ip.is_vpn ? '<span class="badge bg-info">VPN</span>' : ''}
                </td>
                <td>
                    <img src="https://flagcdn.com/16x12/${ip.country_code?.toLowerCase()}.png" 
                         class="country-flag" alt="${ip.country_code}">
                    ${ip.country || 'Unknown'}
                </td>
                <td>
                    <span class="badge bg-${this.getThreatSeverityColor(ip.threat_type)}">
                        ${ip.threat_type || 'Unknown'}
                    </span>
                </td>
                <td>
                    <small class="text-muted">${this.formatTime(ip.blocked_at)}</small>
                </td>
                <td>
                    <button class="btn btn-sm btn-outline-danger" onclick="unblockIP('${ip.address}')">
                        <i class="fas fa-unlock"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-info" onclick="showThreatDetails('${ip.address}')">
                        <i class="fas fa-info"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    updateThreatFeed() {
        const feed = document.getElementById('threat-feed');
        
        // Keep only recent threats (last 50)
        const recentThreats = this.data.threats.slice(-50);
        
        feed.innerHTML = '';
        recentThreats.reverse().forEach(threat => {
            this.addThreatToFeed(threat, false);
        });
    }

    addThreatToFeed(threat, animate = true) {
        const feed = document.getElementById('threat-feed');
        const item = document.createElement('div');
        item.className = `threat-item ${threat.severity || 'medium'}`;
        
        if (animate) {
            item.style.animation = 'slideIn 0.3s ease-out';
        }
        
        item.innerHTML = `
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <strong>${threat.type || 'Unknown Threat'}</strong>
                    <br>
                    <small class="text-muted">
                        IP: <code>${threat.source_ip}</code> | 
                        ${threat.country ? `${threat.country} | ` : ''}
                        ${this.formatTime(threat.detected_at)}
                    </small>
                    ${threat.details ? `<br><small>${threat.details}</small>` : ''}
                </div>
                <span class="badge bg-${this.getThreatSeverityColor(threat.severity)}">
                    ${threat.severity?.toUpperCase() || 'MEDIUM'}
                </span>
            </div>
        `;
        
        // Add to top of feed
        feed.insertBefore(item, feed.firstChild);
        
        // Limit to 50 items
        const items = feed.children;
        if (items.length > 50) {
            feed.removeChild(items[items.length - 1]);
        }
        
        // Auto-scroll to top for new items
        if (animate) {
            feed.scrollTop = 0;
        }
    }

    updateCharts() {
        this.updateThreatChart();
        this.updateThreatTypeChart();
        this.updateWorldMap();
    }

    updateThreatChart() {
        if (!this.charts.threatChart) return;

        // Generate hourly data for the last 24 hours
        const hourlyData = this.generateHourlyData(this.data.threats, 24);
        const hourlyBlocks = this.generateHourlyData(this.data.blockedIPs, 24);
        
        this.charts.threatChart.data.datasets[0].data = hourlyData;
        this.charts.threatChart.data.datasets[1].data = hourlyBlocks;
        this.charts.threatChart.update();
    }

    updateThreatTypeChart() {
        if (!this.charts.threatTypeChart) return;

        const threatCounts = this.countThreatTypes(this.data.threats);
        this.charts.threatTypeChart.data.datasets[0].data = [
            threatCounts['sql_injection'] || 0,
            threatCounts['xss'] || 0,
            threatCounts['brute_force'] || 0,
            threatCounts['ddos'] || 0,
            threatCounts['bot_traffic'] || 0,
            threatCounts['other'] || 0
        ];
        this.charts.threatTypeChart.update();
    }

    updateWorldMap() {
        if (!this.map || !this.threatMarkers) return;

        // Clear existing markers
        this.threatMarkers.clearLayers();

        // Group threats by country
        const countryThreats = {};
        this.data.threats.forEach(threat => {
            if (threat.latitude && threat.longitude) {
                const key = `${threat.latitude},${threat.longitude}`;
                if (!countryThreats[key]) {
                    countryThreats[key] = {
                        lat: threat.latitude,
                        lng: threat.longitude,
                        country: threat.country,
                        count: 0,
                        threats: []
                    };
                }
                countryThreats[key].count++;
                countryThreats[key].threats.push(threat);
            }
        });

        // Add markers for each country with threats
        Object.values(countryThreats).forEach(location => {
            const marker = L.circleMarker([location.lat, location.lng], {
                radius: Math.min(Math.sqrt(location.count) * 3, 20),
                fillColor: this.getThreatMarkerColor(location.count),
                color: '#fff',
                weight: 2,
                opacity: 1,
                fillOpacity: 0.7
            });

            marker.bindPopup(`
                <strong>${location.country}</strong><br>
                Threats: ${location.count}<br>
                <small>Click for details</small>
            `);

            this.threatMarkers.addLayer(marker);
        });
    }

    updateSystemMetrics() {
        const metrics = this.data.metrics;
        
        // Update CPU usage
        const cpuUsage = metrics.cpu_usage || 0;
        this.updateProgressCircle('cpu-usage', cpuUsage);
        
        // Update memory usage
        const memoryUsage = metrics.memory_usage || 0;
        this.updateProgressCircle('memory-usage', memoryUsage);
        
        // Update active connections
        document.getElementById('active-connections').textContent = 
            metrics.active_connections || 0;
    }

    updateProgressCircle(elementId, percentage) {
        const element = document.getElementById(elementId);
        const span = element.querySelector('span');
        
        span.textContent = `${Math.round(percentage)}%`;
        
        const color = percentage > 80 ? '#dc3545' : 
                     percentage > 60 ? '#ffc107' : '#28a745';
        
        element.style.background = `conic-gradient(from 0deg, ${color} 0%, ${color} ${percentage}%, #e9ecef ${percentage}%, #e9ecef 100%)`;
    }

    // Utility functions
    generateTimeLabels(hours) {
        const labels = [];
        const now = new Date();
        
        for (let i = hours - 1; i >= 0; i--) {
            const time = new Date(now.getTime() - (i * 60 * 60 * 1000));
            labels.push(time.getHours().toString().padStart(2, '0') + ':00');
        }
        
        return labels;
    }

    generateHourlyData(items, hours) {
        const data = new Array(hours).fill(0);
        const now = new Date();
        
        items.forEach(item => {
            const itemTime = new Date(item.created_at || item.detected_at || item.blocked_at);
            const hoursDiff = Math.floor((now - itemTime) / (1000 * 60 * 60));
            
            if (hoursDiff >= 0 && hoursDiff < hours) {
                data[hours - 1 - hoursDiff]++;
            }
        });
        
        return data;
    }

    countThreatTypes(threats) {
        const counts = {};
        
        threats.forEach(threat => {
            const type = threat.type?.toLowerCase() || 'other';
            counts[type] = (counts[type] || 0) + 1;
        });
        
        return counts;
    }

    getThreatSeverityColor(severity) {
        switch (severity?.toLowerCase()) {
            case 'critical': return 'danger';
            case 'high': return 'danger';
            case 'medium': return 'warning';
            case 'low': return 'info';
            default: return 'secondary';
        }
    }

    getThreatMarkerColor(count) {
        if (count > 100) return '#dc3545';
        if (count > 50) return '#fd7e14';
        if (count > 10) return '#ffc107';
        return '#28a745';
    }

    formatTime(timestamp) {
        if (!timestamp) return 'Unknown';
        
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        
        if (diff < 60000) return 'Just now';
        if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
        if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
        
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    }

    formatUptime(seconds) {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        
        return `${days}d ${hours}h ${minutes}m`;
    }

    // API functions
    async fetchAPI(endpoint) {
        const response = await fetch(endpoint);
        if (!response.ok) {
            throw new Error(`API request failed: ${response.statusText}`);
        }
        return response.json();
    }

    async postAPI(endpoint, data) {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        if (!response.ok) {
            throw new Error(`API request failed: ${response.statusText}`);
        }
        
        return response.json();
    }

    // UI functions
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <div class="d-flex justify-content-between align-items-center">
                <span>${message}</span>
                <button type="button" class="btn-close btn-close-white" onclick="this.parentElement.parentElement.remove()"></button>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    updateConnectionStatus(connected) {
        const statusElement = document.querySelector('.navbar-text');
        const icon = statusElement.querySelector('i');
        
        if (connected) {
            icon.className = 'fas fa-circle text-success';
            statusElement.innerHTML = '<i class="fas fa-circle text-success"></i> System Online';
        } else {
            icon.className = 'fas fa-circle text-danger';
            statusElement.innerHTML = '<i class="fas fa-circle text-danger"></i> System Offline';
        }
    }

    // Periodic updates
    startPeriodicUpdates() {
        // Update metrics every 30 seconds
        setInterval(async () => {
            try {
                const metrics = await this.fetchAPI('/api/v1/metrics');
                this.data.metrics = metrics.data || {};
                this.updateSystemMetrics();
                this.updateStatusCards();
            } catch (error) {
                console.error('Error updating metrics:', error);
            }
        }, 30000);

        // Refresh blocked IPs every 60 seconds
        setInterval(async () => {
            try {
                const blockedIPs = await this.fetchAPI('/api/v1/blocked-ips');
                this.data.blockedIPs = blockedIPs.data || [];
                this.updateBlockedIPsTable();
            } catch (error) {
                console.error('Error updating blocked IPs:', error);
            }
        }, 60000);
    }

    refreshData() {
        this.loadInitialData();
        this.showNotification('Dashboard data refreshed', 'success');
    }
}

// Global functions for UI interactions
window.refreshBlockedIPs = function() {
    dashboard.loadInitialData();
};

window.unblockIP = async function(ip) {
    try {
        await dashboard.postAPI('/api/v1/firewall/unblock', { ip });
        dashboard.showNotification(`IP ${ip} unblocked successfully`, 'success');
        dashboard.refreshData();
    } catch (error) {
        dashboard.showNotification(`Failed to unblock IP ${ip}`, 'error');
    }
};

window.blockIP = async function() {
    const ip = document.getElementById('threat-ip-input')?.value;
    if (!ip) return;
    
    try {
        await dashboard.postAPI('/api/v1/firewall/block', { ip });
        dashboard.showNotification(`IP ${ip} blocked successfully`, 'success');
        dashboard.refreshData();
    } catch (error) {
        dashboard.showNotification(`Failed to block IP ${ip}`, 'error');
    }
};

window.whitelistIP = async function() {
    const ip = document.getElementById('threat-ip-input')?.value;
    if (!ip) return;
    
    try {
        await dashboard.postAPI('/api/v1/firewall/whitelist', { ip });
        dashboard.showNotification(`IP ${ip} whitelisted successfully`, 'success');
        dashboard.refreshData();
    } catch (error) {
        dashboard.showNotification(`Failed to whitelist IP ${ip}`, 'error');
    }
};

window.showThreatDetails = function(ip) {
    // Implementation for showing threat details modal
    console.log('Show threat details for IP:', ip);
};

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.dashboard = new Dashboard();
});
