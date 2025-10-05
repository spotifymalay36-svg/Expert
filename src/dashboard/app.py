"""
Real-time Security Dashboard
Interactive web dashboard for WAF monitoring and management
"""

import dash
from dash import dcc, html, Input, Output, State, callback_context, dash_table
import plotly.graph_objs as go
import plotly.express as px
import pandas as pd
import json
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Any
import threading
import time

from ..utils.logger import get_logger

logger = get_logger(__name__)

# Dashboard configuration
DASHBOARD_CONFIG = {
    'title': 'AI-Driven WAF Security Dashboard',
    'refresh_interval': 5000,  # 5 seconds
    'api_base_url': 'http://localhost:8000/api/v1'
}

class WAFDashboard:
    """Main dashboard application"""
    
    def __init__(self):
        self.app = dash.Dash(__name__, external_stylesheets=[
            'https://codepen.io/chriddyp/pen/bWLwgP.css',
            'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css'
        ])
        
        # Data storage for real-time updates
        self.data_store = {
            'waf_stats': {},
            'threat_alerts': [],
            'metrics_history': {},
            'system_info': {},
            'last_update': None
        }
        
        # Setup layout and callbacks
        self._setup_layout()
        self._setup_callbacks()
        
        logger.info("WAF Dashboard initialized")
    
    def _setup_layout(self):
        """Setup dashboard layout"""
        
        self.app.layout = html.Div([
            # Header
            html.Div([
                html.H1([
                    html.I(className="fas fa-shield-alt", style={'margin-right': '10px'}),
                    "AI-Driven WAF Security Dashboard"
                ], className="header-title"),
                html.Div([
                    html.Span("Last Updated: ", className="status-label"),
                    html.Span(id="last-update-time", className="status-value"),
                    html.Div(id="connection-status", className="connection-indicator")
                ], className="header-status")
            ], className="header"),
            
            # Auto-refresh interval
            dcc.Interval(
                id='interval-component',
                interval=DASHBOARD_CONFIG['refresh_interval'],
                n_intervals=0
            ),
            
            # Main content
            html.Div([
                # Top row - Key metrics
                html.Div([
                    html.Div([
                        html.H3("Packets Processed"),
                        html.H2(id="packets-processed", children="0"),
                        html.P("packets/sec", className="metric-unit")
                    ], className="metric-card"),
                    
                    html.Div([
                        html.H3("Threats Detected"),
                        html.H2(id="threats-detected", children="0"),
                        html.P("threats/hour", className="metric-unit")
                    ], className="metric-card threat-card"),
                    
                    html.Div([
                        html.H3("Blocked Requests"),
                        html.H2(id="blocked-requests", children="0"),
                        html.P("total blocked", className="metric-unit")
                    ], className="metric-card blocked-card"),
                    
                    html.Div([
                        html.H3("System Status"),
                        html.H2(id="system-status", children="HEALTHY"),
                        html.P("current state", className="metric-unit")
                    ], className="metric-card status-card")
                ], className="metrics-row"),
                
                # Second row - Charts
                html.Div([
                    html.Div([
                        html.H3("Traffic Analysis"),
                        dcc.Graph(id="traffic-chart")
                    ], className="chart-container"),
                    
                    html.Div([
                        html.H3("Threat Distribution"),
                        dcc.Graph(id="threat-pie-chart")
                    ], className="chart-container")
                ], className="charts-row"),
                
                # Third row - Time series
                html.Div([
                    html.Div([
                        html.H3("Real-time Metrics"),
                        dcc.Graph(id="realtime-metrics-chart")
                    ], className="full-width-chart")
                ], className="charts-row"),
                
                # Fourth row - Alerts and logs
                html.Div([
                    html.Div([
                        html.H3("Recent Threat Alerts"),
                        html.Div(id="threat-alerts-table")
                    ], className="alerts-container"),
                    
                    html.Div([
                        html.H3("System Information"),
                        html.Div(id="system-info-panel")
                    ], className="info-container")
                ], className="bottom-row")
            ], className="main-content"),
            
            # Hidden div to store data
            html.Div(id="data-store", style={'display': 'none'})
            
        ], className="dashboard-container")
    
    def _setup_callbacks(self):
        """Setup dashboard callbacks"""
        
        @self.app.callback(
            [Output('data-store', 'children'),
             Output('last-update-time', 'children'),
             Output('connection-status', 'children')],
            [Input('interval-component', 'n_intervals')]
        )
        def update_data_store(n):
            """Update data store with fresh data from API"""
            try:
                # This would normally make async API calls
                # For demo purposes, we'll simulate data
                current_time = datetime.now()
                
                # Simulate WAF stats
                waf_stats = {
                    'packets_processed': 15420 + (n * 10),
                    'threats_detected': 23 + (n % 5),
                    'blocked_requests': 156 + (n % 3),
                    'packets_per_second': 1250 + (n % 100),
                    'is_running': True
                }
                
                # Simulate threat alerts
                threat_types = ['SQL_INJECTION', 'XSS', 'COMMAND_INJECTION', 'ANOMALY']
                severities = ['HIGH', 'MEDIUM', 'CRITICAL', 'LOW']
                
                threat_alerts = []
                for i in range(min(10, n % 15 + 5)):
                    alert = {
                        'id': f'alert_{n}_{i}',
                        'timestamp': (current_time - timedelta(minutes=i*5)).isoformat(),
                        'threat_type': threat_types[i % len(threat_types)],
                        'severity': severities[i % len(severities)],
                        'source_ip': f'192.168.1.{100 + (i % 50)}',
                        'description': f'Threat detected from source IP',
                        'confidence': 0.85 + (i % 10) * 0.01
                    }
                    threat_alerts.append(alert)
                
                # Store data
                self.data_store.update({
                    'waf_stats': waf_stats,
                    'threat_alerts': threat_alerts,
                    'last_update': current_time.isoformat()
                })
                
                # Return data as JSON
                data_json = json.dumps(self.data_store)
                update_time = current_time.strftime("%H:%M:%S")
                status_indicator = html.Div("●", className="status-online", title="Connected")
                
                return data_json, update_time, status_indicator
                
            except Exception as e:
                logger.error(f"Error updating data store: {e}")
                error_indicator = html.Div("●", className="status-offline", title="Connection Error")
                return "{}", "Error", error_indicator
        
        @self.app.callback(
            [Output('packets-processed', 'children'),
             Output('threats-detected', 'children'),
             Output('blocked-requests', 'children'),
             Output('system-status', 'children')],
            [Input('data-store', 'children')]
        )
        def update_metrics(data_json):
            """Update key metrics display"""
            try:
                if not data_json:
                    return "0", "0", "0", "UNKNOWN"
                
                data = json.loads(data_json)
                waf_stats = data.get('waf_stats', {})
                
                packets_per_sec = f"{waf_stats.get('packets_per_second', 0):,}"
                threats_count = f"{waf_stats.get('threats_detected', 0)}"
                blocked_count = f"{waf_stats.get('blocked_requests', 0):,}"
                status = "HEALTHY" if waf_stats.get('is_running', False) else "OFFLINE"
                
                return packets_per_sec, threats_count, blocked_count, status
                
            except Exception as e:
                logger.error(f"Error updating metrics: {e}")
                return "Error", "Error", "Error", "ERROR"
        
        @self.app.callback(
            Output('traffic-chart', 'figure'),
            [Input('data-store', 'children')]
        )
        def update_traffic_chart(data_json):
            """Update traffic analysis chart"""
            try:
                # Generate sample time series data
                timestamps = pd.date_range(
                    start=datetime.now() - timedelta(hours=1),
                    end=datetime.now(),
                    freq='5min'
                )
                
                # Simulate traffic data
                traffic_data = []
                for i, ts in enumerate(timestamps):
                    traffic_data.append({
                        'timestamp': ts,
                        'packets': 1000 + (i * 50) + (i % 3) * 200,
                        'bytes': (1000 + (i * 50)) * 1024
                    })
                
                df = pd.DataFrame(traffic_data)
                
                fig = go.Figure()
                
                # Add packets trace
                fig.add_trace(go.Scatter(
                    x=df['timestamp'],
                    y=df['packets'],
                    mode='lines+markers',
                    name='Packets/min',
                    line=dict(color='#1f77b4', width=2),
                    marker=dict(size=4)
                ))
                
                fig.update_layout(
                    title="Network Traffic Over Time",
                    xaxis_title="Time",
                    yaxis_title="Packets per Minute",
                    template="plotly_white",
                    height=300,
                    margin=dict(l=50, r=50, t=50, b=50)
                )
                
                return fig
                
            except Exception as e:
                logger.error(f"Error updating traffic chart: {e}")
                return go.Figure()
        
        @self.app.callback(
            Output('threat-pie-chart', 'figure'),
            [Input('data-store', 'children')]
        )
        def update_threat_pie_chart(data_json):
            """Update threat distribution pie chart"""
            try:
                if not data_json:
                    return go.Figure()
                
                data = json.loads(data_json)
                threat_alerts = data.get('threat_alerts', [])
                
                # Count threats by type
                threat_counts = {}
                for alert in threat_alerts:
                    threat_type = alert.get('threat_type', 'Unknown')
                    threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
                
                if not threat_counts:
                    threat_counts = {'No Threats': 1}
                
                fig = go.Figure(data=[go.Pie(
                    labels=list(threat_counts.keys()),
                    values=list(threat_counts.values()),
                    hole=0.4,
                    marker_colors=['#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b']
                )])
                
                fig.update_layout(
                    title="Threat Types Distribution",
                    template="plotly_white",
                    height=300,
                    margin=dict(l=50, r=50, t=50, b=50)
                )
                
                return fig
                
            except Exception as e:
                logger.error(f"Error updating threat pie chart: {e}")
                return go.Figure()
        
        @self.app.callback(
            Output('realtime-metrics-chart', 'figure'),
            [Input('data-store', 'children')]
        )
        def update_realtime_metrics_chart(data_json):
            """Update real-time metrics chart"""
            try:
                # Generate sample real-time data
                timestamps = pd.date_range(
                    start=datetime.now() - timedelta(minutes=30),
                    end=datetime.now(),
                    freq='1min'
                )
                
                # Simulate multiple metrics
                metrics_data = []
                for i, ts in enumerate(timestamps):
                    metrics_data.append({
                        'timestamp': ts,
                        'cpu_usage': 20 + (i % 10) * 5 + (i % 3) * 10,
                        'memory_usage': 60 + (i % 5) * 3,
                        'network_io': 50 + (i % 7) * 15,
                        'threat_score': max(0, 10 + (i % 15) * 2 - 5)
                    })
                
                df = pd.DataFrame(metrics_data)
                
                fig = go.Figure()
                
                # Add multiple traces
                fig.add_trace(go.Scatter(
                    x=df['timestamp'],
                    y=df['cpu_usage'],
                    mode='lines',
                    name='CPU Usage (%)',
                    line=dict(color='#1f77b4', width=2)
                ))
                
                fig.add_trace(go.Scatter(
                    x=df['timestamp'],
                    y=df['memory_usage'],
                    mode='lines',
                    name='Memory Usage (%)',
                    line=dict(color='#ff7f0e', width=2)
                ))
                
                fig.add_trace(go.Scatter(
                    x=df['timestamp'],
                    y=df['network_io'],
                    mode='lines',
                    name='Network I/O (MB/s)',
                    line=dict(color='#2ca02c', width=2)
                ))
                
                fig.add_trace(go.Scatter(
                    x=df['timestamp'],
                    y=df['threat_score'],
                    mode='lines',
                    name='Threat Score',
                    line=dict(color='#d62728', width=2),
                    yaxis='y2'
                ))
                
                fig.update_layout(
                    title="Real-time System Metrics",
                    xaxis_title="Time",
                    yaxis=dict(title="System Metrics (%)", side='left'),
                    yaxis2=dict(title="Threat Score", side='right', overlaying='y'),
                    template="plotly_white",
                    height=400,
                    margin=dict(l=50, r=50, t=50, b=50),
                    legend=dict(x=0.01, y=0.99)
                )
                
                return fig
                
            except Exception as e:
                logger.error(f"Error updating realtime metrics chart: {e}")
                return go.Figure()
        
        @self.app.callback(
            Output('threat-alerts-table', 'children'),
            [Input('data-store', 'children')]
        )
        def update_threat_alerts_table(data_json):
            """Update threat alerts table"""
            try:
                if not data_json:
                    return html.Div("No alerts available")
                
                data = json.loads(data_json)
                threat_alerts = data.get('threat_alerts', [])
                
                if not threat_alerts:
                    return html.Div("No recent threats detected", className="no-data")
                
                # Prepare table data
                table_data = []
                for alert in threat_alerts[:10]:  # Show last 10 alerts
                    timestamp = datetime.fromisoformat(alert['timestamp'])
                    table_data.append({
                        'Time': timestamp.strftime('%H:%M:%S'),
                        'Type': alert['threat_type'],
                        'Severity': alert['severity'],
                        'Source IP': alert['source_ip'],
                        'Confidence': f"{alert['confidence']:.2f}"
                    })
                
                # Create table
                table = dash_table.DataTable(
                    data=table_data,
                    columns=[
                        {'name': 'Time', 'id': 'Time'},
                        {'name': 'Type', 'id': 'Type'},
                        {'name': 'Severity', 'id': 'Severity'},
                        {'name': 'Source IP', 'id': 'Source IP'},
                        {'name': 'Confidence', 'id': 'Confidence'}
                    ],
                    style_cell={
                        'textAlign': 'left',
                        'padding': '10px',
                        'fontFamily': 'Arial'
                    },
                    style_data_conditional=[
                        {
                            'if': {'filter_query': '{Severity} = CRITICAL'},
                            'backgroundColor': '#ffebee',
                            'color': 'black',
                        },
                        {
                            'if': {'filter_query': '{Severity} = HIGH'},
                            'backgroundColor': '#fff3e0',
                            'color': 'black',
                        }
                    ],
                    style_header={
                        'backgroundColor': '#f5f5f5',
                        'fontWeight': 'bold'
                    }
                )
                
                return table
                
            except Exception as e:
                logger.error(f"Error updating threat alerts table: {e}")
                return html.Div("Error loading alerts")
        
        @self.app.callback(
            Output('system-info-panel', 'children'),
            [Input('data-store', 'children')]
        )
        def update_system_info_panel(data_json):
            """Update system information panel"""
            try:
                # Simulate system info
                system_info = {
                    'WAF Version': '1.0.0',
                    'Uptime': '2d 14h 32m',
                    'ML Models': 'Active (3/3)',
                    'Threat Intel': 'Connected',
                    'Zero Trust': 'Enabled',
                    'SSL Inspection': 'Enabled',
                    'Active Sessions': '127',
                    'Blocked IPs': '45'
                }
                
                info_items = []
                for key, value in system_info.items():
                    info_items.append(
                        html.Div([
                            html.Span(f"{key}: ", className="info-label"),
                            html.Span(value, className="info-value")
                        ], className="info-item")
                    )
                
                return html.Div(info_items, className="system-info-grid")
                
            except Exception as e:
                logger.error(f"Error updating system info panel: {e}")
                return html.Div("Error loading system info")
    
    def run(self, host='0.0.0.0', port=8080, debug=False):
        """Run the dashboard server"""
        try:
            self.app.run_server(host=host, port=port, debug=debug)
        except Exception as e:
            logger.error(f"Error running dashboard: {e}")

def create_dashboard_app():
    """Create and return dashboard app instance"""
    dashboard = WAFDashboard()
    return dashboard

# Custom CSS styles
CUSTOM_CSS = """
.dashboard-container {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    margin: 0;
    padding: 20px;
    background-color: #f5f7fa;
}

.header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 20px;
    border-radius: 10px;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.header-title {
    margin: 0;
    font-size: 28px;
    font-weight: 300;
}

.header-status {
    display: flex;
    align-items: center;
    gap: 15px;
}

.status-label {
    font-size: 14px;
    opacity: 0.9;
}

.status-value {
    font-size: 16px;
    font-weight: 500;
}

.connection-indicator {
    margin-left: 10px;
}

.status-online {
    color: #4caf50;
    font-size: 20px;
}

.status-offline {
    color: #f44336;
    font-size: 20px;
}

.metrics-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.metric-card {
    background: white;
    padding: 25px;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    text-align: center;
    border-left: 4px solid #667eea;
}

.threat-card {
    border-left-color: #ff6b6b;
}

.blocked-card {
    border-left-color: #feca57;
}

.status-card {
    border-left-color: #48dbfb;
}

.metric-card h3 {
    margin: 0 0 10px 0;
    color: #666;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.metric-card h2 {
    margin: 0 0 5px 0;
    color: #333;
    font-size: 32px;
    font-weight: 600;
}

.metric-unit {
    margin: 0;
    color: #999;
    font-size: 12px;
}

.charts-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.chart-container {
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.full-width-chart {
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    grid-column: 1 / -1;
}

.bottom-row {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 20px;
}

.alerts-container, .info-container {
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.system-info-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 10px;
}

.info-item {
    padding: 8px 0;
    border-bottom: 1px solid #eee;
}

.info-label {
    font-weight: 500;
    color: #666;
}

.info-value {
    color: #333;
}

.no-data {
    text-align: center;
    color: #999;
    font-style: italic;
    padding: 20px;
}

@media (max-width: 768px) {
    .metrics-row {
        grid-template-columns: 1fr;
    }
    
    .charts-row {
        grid-template-columns: 1fr;
    }
    
    .bottom-row {
        grid-template-columns: 1fr;
    }
}
"""