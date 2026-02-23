"""AEON Team Dashboard — Web-based Analytics for Teams.

Provides a web dashboard for teams to track verification metrics,
code quality trends, and team performance over time.

Usage:
    python -m aeon.dashboard --port 8080
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, render_template, jsonify, request, send_from_directory
import plotly.graph_objs as go
import plotly.utils


class TeamDashboard:
    """Web dashboard for AEON team metrics and analytics."""
    
    def __init__(self, db_path: str = ".aeon-dashboard.db"):
        self.db_path = db_path
        self.app = Flask(__name__)
        self._init_database()
        self._setup_routes()
    
    def _init_database(self) -> None:
        """Initialize SQLite database for metrics storage."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS verification_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    team_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    project_path TEXT NOT NULL,
                    branch TEXT,
                    commit_hash TEXT,
                    files_scanned INTEGER,
                    files_verified INTEGER,
                    total_errors INTEGER,
                    total_warnings INTEGER,
                    total_functions INTEGER,
                    total_classes INTEGER,
                    duration_ms REAL,
                    profile TEXT,
                    languages TEXT,
                    cache_hit_rate REAL,
                    metadata TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    file_path TEXT NOT NULL,
                    project_path TEXT NOT NULL,
                    language TEXT NOT NULL,
                    verified BOOLEAN,
                    errors INTEGER,
                    warnings INTEGER,
                    functions INTEGER,
                    classes INTEGER,
                    complexity_score REAL,
                    verification_time_ms REAL,
                    last_modified REAL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS team_members (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT,
                    role TEXT,
                    join_date REAL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL,
                    description TEXT,
                    created_date REAL,
                    last_activity REAL
                )
            """)
            
            # Create indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_verification_timestamp ON verification_runs(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_verification_team ON verification_runs(team_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_file_metrics_timestamp ON file_metrics(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_file_metrics_project ON file_metrics(project_path)")
            
            conn.commit()
        finally:
            conn.close()
    
    def _setup_routes(self) -> None:
        """Setup Flask routes for the dashboard."""
        
        @self.app.route('/')
        def index():
            return render_template('dashboard.html')
        
        @self.app.route('/api/metrics/overview')
        def get_overview_metrics():
            """Get overview metrics for the dashboard."""
            conn = sqlite3.connect(self.db_path)
            try:
                # Last 30 days metrics
                thirty_days_ago = time.time() - (30 * 24 * 60 * 60)
                
                cursor = conn.execute("""
                    SELECT 
                        COUNT(*) as total_runs,
                        AVG(duration_ms) as avg_duration,
                        SUM(total_errors) as total_errors,
                        AVG(cache_hit_rate) as avg_cache_hit_rate,
                        COUNT(DISTINCT team_id) as active_teams,
                        COUNT(DISTINCT project_path) as active_projects
                    FROM verification_runs 
                    WHERE timestamp >= ?
                """, (thirty_days_ago,))
                
                row = cursor.fetchone()
                
                # Trend data (last 7 days)
                seven_days_ago = time.time() - (7 * 24 * 60 * 60)
                cursor = conn.execute("""
                    SELECT 
                        DATE(timestamp, 'unixepoch') as date,
                        COUNT(*) as runs,
                        AVG(duration_ms) as avg_duration,
                        SUM(total_errors) as errors
                    FROM verification_runs 
                    WHERE timestamp >= ?
                    GROUP BY DATE(timestamp, 'unixepoch')
                    ORDER BY date
                """, (seven_days_ago,))
                
                trend_data = cursor.fetchall()
                
                return jsonify({
                    'summary': {
                        'total_runs': row[0] or 0,
                        'avg_duration_ms': round(row[1] or 0, 2),
                        'total_errors': row[2] or 0,
                        'avg_cache_hit_rate': round((row[3] or 0) * 100, 1),
                        'active_teams': row[4] or 0,
                        'active_projects': row[5] or 0
                    },
                    'trend': [
                        {
                            'date': row[0],
                            'runs': row[1],
                            'avg_duration_ms': round(row[2] or 0, 2),
                            'errors': row[3] or 0
                        } for row in trend_data
                    ]
                })
            finally:
                conn.close()
        
        @self.app.route('/api/metrics/teams')
        def get_team_metrics():
            """Get metrics by team."""
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute("""
                    SELECT 
                        team_id,
                        COUNT(*) as runs,
                        AVG(duration_ms) as avg_duration,
                        SUM(total_errors) as total_errors,
                        AVG(cache_hit_rate) as avg_cache_hit_rate,
                        MAX(timestamp) as last_activity
                    FROM verification_runs 
                    WHERE timestamp >= ?
                    GROUP BY team_id
                    ORDER BY runs DESC
                """, (time.time() - (30 * 24 * 60 * 60),))
                
                teams = []
                for row in cursor.fetchall():
                    teams.append({
                        'team_id': row[0],
                        'runs': row[1],
                        'avg_duration_ms': round(row[2] or 0, 2),
                        'total_errors': row[3] or 0,
                        'avg_cache_hit_rate': round((row[4] or 0) * 100, 1),
                        'last_activity': row[5]
                    })
                
                return jsonify({'teams': teams})
            finally:
                conn.close()
        
        @self.app.route('/api/metrics/projects')
        def get_project_metrics():
            """Get metrics by project."""
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute("""
                    SELECT 
                        project_path,
                        COUNT(*) as runs,
                        AVG(duration_ms) as avg_duration,
                        SUM(total_errors) as total_errors,
                        COUNT(DISTINCT team_id) as teams,
                        MAX(timestamp) as last_activity
                    FROM verification_runs 
                    WHERE timestamp >= ?
                    GROUP BY project_path
                    ORDER BY runs DESC
                """, (time.time() - (30 * 24 * 60 * 60),))
                
                projects = []
                for row in cursor.fetchall():
                    projects.append({
                        'project_path': row[0],
                        'runs': row[1],
                        'avg_duration_ms': round(row[2] or 0, 2),
                        'total_errors': row[3] or 0,
                        'teams': row[4],
                        'last_activity': row[5]
                    })
                
                return jsonify({'projects': projects})
            finally:
                conn.close()
        
        @self.app.route('/api/metrics/languages')
        def get_language_metrics():
            """Get metrics by programming language."""
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute("""
                    SELECT 
                        json_extract(languages, '$') as languages_json,
                        COUNT(*) as runs,
                        AVG(duration_ms) as avg_duration,
                        SUM(total_errors) as total_errors
                    FROM verification_runs 
                    WHERE timestamp >= ? AND languages IS NOT NULL
                """, (time.time() - (30 * 24 * 60 * 60),))
                
                language_stats = {}
                for row in cursor.fetchall():
                    try:
                        languages = json.loads(row[0] or '{}')
                        for lang, count in languages.items():
                            if lang not in language_stats:
                                language_stats[lang] = {
                                    'files': 0,
                                    'runs': 0,
                                    'total_duration': 0,
                                    'total_errors': 0
                                }
                            language_stats[lang]['files'] += count
                            language_stats[lang]['runs'] += 1
                            language_stats[lang]['total_duration'] += row[2] or 0
                            language_stats[lang]['total_errors'] += row[3] or 0
                    except json.JSONDecodeError:
                        continue
                
                # Calculate averages
                for stats in language_stats.values():
                    stats['avg_duration_ms'] = round(
                        stats['total_duration'] / stats['runs'], 2
                    ) if stats['runs'] > 0 else 0
                
                return jsonify({'languages': language_stats})
            finally:
                conn.close()
        
        @self.app.route('/api/metrics/quality-trends')
        def get_quality_trends():
            """Get code quality trends over time."""
            conn = sqlite3.connect(self.db_path)
            try:
                # Daily trends for last 90 days
                ninety_days_ago = time.time() - (90 * 24 * 60 * 60)
                
                cursor = conn.execute("""
                    SELECT 
                        DATE(timestamp, 'unixepoch') as date,
                        COUNT(*) as runs,
                        SUM(total_errors) as errors,
                        SUM(total_warnings) as warnings,
                        AVG(duration_ms) as avg_duration,
                        SUM(files_scanned) as files_scanned,
                        SUM(files_verified) as files_verified
                    FROM verification_runs 
                    WHERE timestamp >= ?
                    GROUP BY DATE(timestamp, 'unixepoch')
                    ORDER BY date
                """, (ninety_days_ago,))
                
                trends = []
                for row in cursor.fetchall():
                    trends.append({
                        'date': row[0],
                        'runs': row[1],
                        'errors': row[2] or 0,
                        'warnings': row[3] or 0,
                        'avg_duration_ms': round(row[4] or 0, 2),
                        'files_scanned': row[5] or 0,
                        'files_verified': row[6] or 0,
                        'success_rate': round((row[6] or 0) / max(row[5] or 1, 1) * 100, 1)
                    })
                
                return jsonify({'trends': trends})
            finally:
                conn.close()
        
        @self.app.route('/api/metrics/top-files')
        def get_top_files():
            """Get files with most issues or most frequently analyzed."""
            conn = sqlite3.connect(self.db_path)
            try:
                # Files with most errors
                cursor = conn.execute("""
                    SELECT 
                        file_path,
                        COUNT(*) as analyses,
                        SUM(errors) as total_errors,
                        AVG(verification_time_ms) as avg_duration,
                        MAX(timestamp) as last_analysis
                    FROM file_metrics 
                    WHERE timestamp >= ?
                    GROUP BY file_path
                    ORDER BY total_errors DESC, analyses DESC
                    LIMIT 20
                """, (time.time() - (30 * 24 * 60 * 60),))
                
                error_files = []
                for row in cursor.fetchall():
                    error_files.append({
                        'file_path': row[0],
                        'analyses': row[1],
                        'total_errors': row[2] or 0,
                        'avg_duration_ms': round(row[3] or 0, 2),
                        'last_analysis': row[4]
                    })
                
                # Most frequently analyzed files
                cursor = conn.execute("""
                    SELECT 
                        file_path,
                        COUNT(*) as analyses,
                        SUM(errors) as total_errors,
                        AVG(verification_time_ms) as avg_duration,
                        language
                    FROM file_metrics 
                    WHERE timestamp >= ?
                    GROUP BY file_path
                    ORDER BY analyses DESC
                    LIMIT 20
                """, (time.time() - (30 * 24 * 60 * 60),))
                
                frequent_files = []
                for row in cursor.fetchall():
                    frequent_files.append({
                        'file_path': row[0],
                        'analyses': row[1],
                        'total_errors': row[2] or 0,
                        'avg_duration_ms': round(row[3] or 0, 2),
                        'language': row[4]
                    })
                
                return jsonify({
                    'error_files': error_files,
                    'frequent_files': frequent_files
                })
            finally:
                conn.close()
        
        @self.app.route('/api/record', methods=['POST'])
        def record_verification():
            """Record verification results from AEON CLI."""
            data = request.json
            
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("""
                    INSERT INTO verification_runs (
                        timestamp, team_id, user_id, project_path, branch, 
                        commit_hash, files_scanned, files_verified, total_errors,
                        total_warnings, total_functions, total_classes, duration_ms,
                        profile, languages, cache_hit_rate, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    time.time(),
                    data.get('team_id', 'default'),
                    data.get('user_id', 'unknown'),
                    data.get('project_path', ''),
                    data.get('branch', ''),
                    data.get('commit_hash', ''),
                    data.get('files_scanned', 0),
                    data.get('files_verified', 0),
                    data.get('total_errors', 0),
                    data.get('total_warnings', 0),
                    data.get('total_functions', 0),
                    data.get('total_classes', 0),
                    data.get('duration_ms', 0),
                    data.get('profile', 'daily'),
                    json.dumps(data.get('languages', {})),
                    data.get('cache_hit_rate', 0),
                    json.dumps(data.get('metadata', {}))
                ))
                
                # Record file-level metrics
                for file_result in data.get('file_results', []):
                    conn.execute("""
                        INSERT OR REPLACE INTO file_metrics (
                            timestamp, file_path, project_path, language,
                            verified, errors, warnings, functions, classes,
                            complexity_score, verification_time_ms, last_modified
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        time.time(),
                        file_result.get('file', ''),
                        data.get('project_path', ''),
                        file_result.get('language', ''),
                        file_result.get('verified', False),
                        file_result.get('errors', 0),
                        file_result.get('warnings', 0),
                        file_result.get('functions', 0),
                        file_result.get('classes', 0),
                        file_result.get('complexity_score', 0),
                        file_result.get('verification_time_ms', 0),
                        file_result.get('last_modified', time.time())
                    ))
                
                conn.commit()
                return jsonify({'status': 'success'})
            except Exception as e:
                conn.rollback()
                return jsonify({'status': 'error', 'message': str(e)}), 500
            finally:
                conn.close()
    
    def record_verification_result(self, result: Dict[str, Any], 
                                  team_id: str = 'default',
                                  user_id: str = 'unknown') -> None:
        """Record verification results in the database."""
        import requests
        
        try:
            requests.post('http://localhost:5000/api/record', json={
                'team_id': team_id,
                'user_id': user_id,
                **result
            }, timeout=5)
        except requests.RequestException:
            # Dashboard server might not be running
            pass
    
    def run(self, host: str = '0.0.0.0', port: int = 8080, debug: bool = False) -> None:
        """Run the dashboard server."""
        # Create templates directory
        templates_dir = Path(__file__).parent / 'templates'
        templates_dir.mkdir(exist_ok=True)
        
        # Create dashboard template
        template_content = self._get_dashboard_template()
        with open(templates_dir / 'dashboard.html', 'w') as f:
            f.write(template_content)
        
        self.app.run(host=host, port=port, debug=debug)
    
    def _get_dashboard_template(self) -> str:
        """Generate the HTML template for the dashboard."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AEON Team Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .metric-card {
            @apply bg-white rounded-lg shadow-md p-6 border border-gray-200;
        }
        .metric-value {
            @apply text-3xl font-bold text-blue-600;
        }
        .metric-label {
            @apply text-sm text-gray-600 mt-1;
        }
    </style>
</head>
<body class="bg-gray-50">
    <div class="min-h-screen">
        <!-- Header -->
        <header class="bg-white shadow-sm border-b">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="flex justify-between items-center py-4">
                    <div class="flex items-center">
                        <h1 class="text-2xl font-bold text-gray-900">🤖 AEON Team Dashboard</h1>
                    </div>
                    <div class="flex items-center space-x-4">
                        <span class="text-sm text-gray-500">Last updated: <span id="lastUpdated">Loading...</span></span>
                        <button onclick="refreshData()" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700">
                            Refresh
                        </button>
                    </div>
                </div>
            </div>
        </header>

        <!-- Main Content -->
        <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <!-- Overview Metrics -->
            <section class="mb-8">
                <h2 class="text-xl font-semibold text-gray-900 mb-4">Overview (Last 30 Days)</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    <div class="metric-card">
                        <div class="metric-value" id="totalRuns">-</div>
                        <div class="metric-label">Total Verifications</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value" id="avgDuration">-</div>
                        <div class="metric-label">Avg Duration (ms)</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value" id="totalErrors">-</div>
                        <div class="metric-label">Total Errors</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value" id="cacheHitRate">-</div>
                        <div class="metric-label">Cache Hit Rate (%)</div>
                    </div>
                </div>
            </section>

            <!-- Charts -->
            <section class="mb-8">
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h3 class="text-lg font-semibold text-gray-900 mb-4">Verification Trends</h3>
                        <div id="trendsChart" style="height: 300px;"></div>
                    </div>
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h3 class="text-lg font-semibold text-gray-900 mb-4">Language Distribution</h3>
                        <div id="languagesChart" style="height: 300px;"></div>
                    </div>
                </div>
            </section>

            <!-- Quality Trends -->
            <section class="mb-8">
                <div class="bg-white p-6 rounded-lg shadow-md">
                    <h3 class="text-lg font-semibold text-gray-900 mb-4">Quality Trends (90 Days)</h3>
                    <div id="qualityChart" style="height: 400px;"></div>
                </div>
            </section>

            <!-- Tables -->
            <section class="mb-8">
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h3 class="text-lg font-semibold text-gray-900 mb-4">Top Teams</h3>
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Team</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Runs</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Errors</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Cache Hit</th>
                                    </tr>
                                </thead>
                                <tbody id="teamsTable" class="bg-white divide-y divide-gray-200">
                                </tbody>
                            </table>
                        </div>
                    </div>
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h3 class="text-lg font-semibold text-gray-900 mb-4">Problem Files</h3>
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">File</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Errors</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Analyses</th>
                                    </tr>
                                </thead>
                                <tbody id="filesTable" class="bg-white divide-y divide-gray-200">
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </section>
        </main>
    </div>

    <script>
        let refreshInterval;

        async function loadData() {
            try {
                // Load overview metrics
                const overviewResponse = await fetch('/api/metrics/overview');
                const overview = await overviewResponse.json();
                
                document.getElementById('totalRuns').textContent = overview.summary.total_runs.toLocaleString();
                document.getElementById('avgDuration').textContent = overview.summary.avg_duration_ms.toLocaleString();
                document.getElementById('totalErrors').textContent = overview.summary.total_errors.toLocaleString();
                document.getElementById('cacheHitRate').textContent = overview.summary.avg_cache_hit_rate + '%';
                
                // Update trends chart
                const trendsData = overview.trend;
                const trendsTrace = {
                    x: trendsData.map(d => d.date),
                    y: trendsData.map(d => d.runs),
                    type: 'scatter',
                    mode: 'lines+markers',
                    name: 'Verifications',
                    line: { color: '#3B82F6' }
                };
                
                const errorsTrace = {
                    x: trendsData.map(d => d.date),
                    y: trendsData.map(d => d.errors),
                    type: 'scatter',
                    mode: 'lines+markers',
                    name: 'Errors',
                    yaxis: 'y2',
                    line: { color: '#EF4444' }
                };
                
                Plotly.newPlot('trendsChart', [trendsTrace, errorsTrace], {
                    xaxis: { title: 'Date' },
                    yaxis: { title: 'Verifications' },
                    yaxis2: {
                        title: 'Errors',
                        overlaying: 'y',
                        side: 'right'
                    },
                    margin: { t: 20, r: 40, b: 40, l: 50 }
                });
                
                // Load language data
                const languagesResponse = await fetch('/api/metrics/languages');
                const languages = await languagesResponse.json();
                
                const langTrace = {
                    labels: Object.keys(languages.languages),
                    values: Object.values(languages.languages).map(l => l.files),
                    type: 'pie'
                };
                
                Plotly.newPlot('languagesChart', [langTrace], {
                    margin: { t: 20, r: 40, b: 40, l: 50 }
                });
                
                // Load quality trends
                const qualityResponse = await fetch('/api/metrics/quality-trends');
                const quality = await qualityResponse.json();
                
                const successRateTrace = {
                    x: quality.trends.map(d => d.date),
                    y: quality.trends.map(d => d.success_rate),
                    type: 'scatter',
                    mode: 'lines+markers',
                    name: 'Success Rate (%)',
                    line: { color: '#10B981' }
                };
                
                const durationTrace = {
                    x: quality.trends.map(d => d.date),
                    y: quality.trends.map(d => d.avg_duration_ms),
                    type: 'scatter',
                    mode: 'lines+markers',
                    name: 'Avg Duration (ms)',
                    yaxis: 'y2',
                    line: { color: '#F59E0B' }
                };
                
                Plotly.newPlot('qualityChart', [successRateTrace, durationTrace], {
                    xaxis: { title: 'Date' },
                    yaxis: { title: 'Success Rate (%)' },
                    yaxis2: {
                        title: 'Duration (ms)',
                        overlaying: 'y',
                        side: 'right'
                    },
                    margin: { t: 20, r: 40, b: 40, l: 50 }
                });
                
                // Load teams data
                const teamsResponse = await fetch('/api/metrics/teams');
                const teams = await teamsResponse.json();
                
                const teamsTable = document.getElementById('teamsTable');
                teamsTable.innerHTML = teams.teams.slice(0, 5).map(team => `
                    <tr>
                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${team.team_id}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${team.runs}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${team.total_errors}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${team.avg_cache_hit_rate}%</td>
                    </tr>
                `).join('');
                
                // Load files data
                const filesResponse = await fetch('/api/metrics/top-files');
                const files = await filesResponse.json();
                
                const filesTable = document.getElementById('filesTable');
                filesTable.innerHTML = files.error_files.slice(0, 5).map(file => `
                    <tr>
                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${file.file_path}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-red-600">${file.total_errors}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${file.analyses}</td>
                    </tr>
                `).join('');
                
                // Update last updated time
                document.getElementById('lastUpdated').textContent = new Date().toLocaleTimeString();
                
            } catch (error) {
                console.error('Error loading data:', error);
            }
        }

        function refreshData() {
            loadData();
        }

        // Initial load
        loadData();
        
        // Auto-refresh every 30 seconds
        refreshInterval = setInterval(loadData, 30000);
        
        // Cleanup on page unload
        window.addEventListener('beforeunload', () => {
            if (refreshInterval) {
                clearInterval(refreshInterval);
            }
        });
    </script>
</body>
</html>
        """


def main():
    """Run the AEON team dashboard."""
    import argparse
    
    parser = argparse.ArgumentParser(description='AEON Team Dashboard')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    dashboard = TeamDashboard()
    print(f"🚀 AEON Team Dashboard starting on http://{args.host}:{args.port}")
    dashboard.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
