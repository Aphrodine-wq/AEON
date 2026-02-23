"""AEON Formal Verification as a Service (FVaaS).

Enterprise-grade API for formal verification with multi-tenant support,
usage tracking, billing, and advanced analytics.

Usage:
    python -m aeon.fvaas --port 9000
"""

from __future__ import annotations

import json
import time
import uuid
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path

from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
from werkzeug.exceptions import HTTPException

from aeon.api_server import verify_source_code
from aeon.cache import VerificationCache
from aeon.incremental import IncrementalAnalyzer
from aeon.test_generation import TestGenerator
from aeon.nl_contracts import NLContractGenerator


@dataclass
class Tenant:
    """Multi-tenant organization."""
    id: str
    name: str
    api_key: str
    plan: str  # 'free', 'pro', 'enterprise'
    usage_limits: Dict[str, int]
    current_usage: Dict[str, int]
    created_at: float
    billing_cycle_start: float


@dataclass
class VerificationJob:
    """A verification job with tracking."""
    id: str
    tenant_id: str
    source_code: str
    language: str
    analysis_config: Dict[str, Any]
    status: str  # 'queued', 'running', 'completed', 'failed'
    result: Optional[Dict[str, Any]]
    created_at: float
    started_at: Optional[float]
    completed_at: Optional[float]
    duration_ms: Optional[float]
    cost_credits: int


class FVaaSService:
    """Formal Verification as a Service implementation."""
    
    def __init__(self, db_path: str = "fvaas.db", jwt_secret: str = None):
        self.db_path = db_path
        self.jwt_secret = jwt_secret or "your-secret-key-change-in-production"
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = self.jwt_secret
        
        # Rate limiting
        self.limiter = Limiter(
            app=self.app,
            key_func=get_remote_address,
            default_limits=["1000 per hour"]
        )
        
        # Initialize components
        self.cache = VerificationCache()
        self.incremental_analyzer = IncrementalAnalyzer()
        self.test_generator = TestGenerator()
        self.contract_generator = NLContractGenerator()
        
        # Initialize database
        self._init_database()
        
        # Setup routes
        self._setup_routes()
    
    def _init_database(self) -> None:
        """Initialize SQLite database for multi-tenant FVaaS."""
        conn = sqlite3.connect(self.db_path)
        try:
            # Tenants table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tenants (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    api_key TEXT UNIQUE NOT NULL,
                    plan TEXT NOT NULL,
                    usage_limits TEXT NOT NULL,
                    current_usage TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    billing_cycle_start REAL NOT NULL
                )
            """)
            
            # Verification jobs table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS verification_jobs (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    source_code TEXT NOT NULL,
                    language TEXT NOT NULL,
                    analysis_config TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result TEXT,
                    created_at REAL NOT NULL,
                    started_at REAL,
                    completed_at REAL,
                    duration_ms REAL,
                    cost_credits INTEGER NOT NULL,
                    FOREIGN KEY (tenant_id) REFERENCES tenants (id)
                )
            """)
            
            # Usage tracking table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS usage_logs (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    endpoint TEXT NOT NULL,
                    cost_credits INTEGER NOT NULL,
                    metadata TEXT,
                    FOREIGN KEY (tenant_id) REFERENCES tenants (id)
                )
            """)
            
            # Analytics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analytics (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    date TEXT NOT NULL,
                    total_verifications INTEGER NOT NULL,
                    total_errors INTEGER NOT NULL,
                    avg_duration_ms REAL NOT NULL,
                    languages_used TEXT NOT NULL,
                    cost_credits INTEGER NOT NULL,
                    FOREIGN KEY (tenant_id) REFERENCES tenants (id)
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_tenant ON verification_jobs(tenant_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON verification_jobs(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_usage_tenant ON usage_logs(tenant_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_analytics_tenant_date ON analytics(tenant_id, date)")
            
            # Create default tenant if none exists
            cursor = conn.execute("SELECT COUNT(*) FROM tenants")
            if cursor.fetchone()[0] == 0:
                self._create_default_tenant(conn)
            
            conn.commit()
        finally:
            conn.close()
    
    def _create_default_tenant(self, conn: sqlite3.Connection) -> None:
        """Create a default tenant for testing."""
        default_tenant = Tenant(
            id="default",
            name="Default Organization",
            api_key="default-api-key-change-in-production",
            plan="pro",
            usage_limits={
                "verifications_per_month": 10000,
                "max_file_size_kb": 1000,
                "max_concurrent_jobs": 10,
                "credits_per_month": 100000
            },
            current_usage={
                "verifications_this_month": 0,
                "credits_used_this_month": 0
            },
            created_at=time.time(),
            billing_cycle_start=time.time()
        )
        
        conn.execute("""
            INSERT INTO tenants (id, name, api_key, plan, usage_limits, current_usage, created_at, billing_cycle_start)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            default_tenant.id,
            default_tenant.name,
            default_tenant.api_key,
            default_tenant.plan,
            json.dumps(default_tenant.usage_limits),
            json.dumps(default_tenant.current_usage),
            default_tenant.created_at,
            default_tenant.billing_cycle_start
        ))
    
    def _setup_routes(self) -> None:
        """Setup Flask routes for FVaaS API."""
        
        # Authentication middleware
        @self.app.before_request
        def authenticate_request():
            if request.endpoint and request.endpoint.startswith('static'):
                return  # Skip auth for static files
            
            if request.path in ['/health', '/docs', '/']:
                return  # Skip auth for public endpoints
            
            api_key = request.headers.get('X-API-Key')
            if not api_key:
                return jsonify({'error': 'API key required'}), 401
            
            tenant = self._get_tenant_by_api_key(api_key)
            if not tenant:
                return jsonify({'error': 'Invalid API key'}), 401
            
            g.tenant = tenant
        
        # API Routes
        @self.app.route('/health')
        def health_check():
            return jsonify({
                'status': 'healthy',
                'timestamp': time.time(),
                'version': '0.5.0'
            })
        
        @self.app.route('/docs')
        def api_docs():
            return jsonify({
                'title': 'AEON Formal Verification as a Service API',
                'version': '1.0.0',
                'endpoints': {
                    'POST /verify': 'Verify source code',
                    'POST /verify/async': 'Submit async verification job',
                    'GET /jobs/{job_id}': 'Get job status and results',
                    'POST /contracts/generate': 'Generate contracts from natural language',
                    'POST /tests/generate': 'Generate tests from verification results',
                    'GET /analytics': 'Get usage analytics',
                    'GET /usage': 'Get current usage statistics'
                }
            })
        
        @self.app.route('/verify', methods=['POST'])
        @self.limiter.limit("100 per minute")
        def verify_code():
            """Synchronous verification endpoint."""
            tenant = g.tenant
            
            # Check usage limits
            if not self._check_usage_limits(tenant, request.get_json()):
                return jsonify({'error': 'Usage limit exceeded'}), 429
            
            data = request.get_json()
            source_code = data.get('source_code', '')
            language = data.get('language', 'auto')
            config = data.get('config', {})
            
            # Validate request
            if not source_code.strip():
                return jsonify({'error': 'Source code is required'}), 400
            
            if len(source_code) > tenant.usage_limits['max_file_size_kb'] * 1024:
                return jsonify({'error': 'Source code too large'}), 400
            
            # Perform verification
            try:
                start_time = time.time()
                result = verify_source_code(source_code, language, config)
                duration_ms = (time.time() - start_time) * 1000
                
                # Calculate cost
                cost_credits = self._calculate_cost(source_code, config)
                
                # Update usage
                self._update_usage(tenant.id, '/verify', cost_credits, {
                    'language': language,
                    'config': config,
                    'duration_ms': duration_ms
                })
                
                # Log verification
                self._log_verification(tenant.id, source_code, language, config, result, duration_ms, cost_credits)
                
                return jsonify({
                    'result': result,
                    'duration_ms': duration_ms,
                    'cost_credits': cost_credits,
                    'tenant_id': tenant.id
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/verify/async', methods=['POST'])
        @self.limiter.limit("50 per minute")
        def submit_async_job():
            """Submit asynchronous verification job."""
            tenant = g.tenant
            
            # Check concurrent job limit
            active_jobs = self._get_active_job_count(tenant.id)
            if active_jobs >= tenant.usage_limits['max_concurrent_jobs']:
                return jsonify({'error': 'Concurrent job limit exceeded'}), 429
            
            data = request.get_json()
            source_code = data.get('source_code', '')
            language = data.get('language', 'auto')
            config = data.get('config', {})
            
            # Create job
            job_id = str(uuid.uuid4())
            cost_credits = self._calculate_cost(source_code, config)
            
            job = VerificationJob(
                id=job_id,
                tenant_id=tenant.id,
                source_code=source_code,
                language=language,
                analysis_config=config,
                status='queued',
                result=None,
                created_at=time.time(),
                started_at=None,
                completed_at=None,
                duration_ms=None,
                cost_credits=cost_credits
            )
            
            self._save_job(job)
            
            # Start async processing (in production, use Celery or similar)
            self._process_job_async(job_id)
            
            return jsonify({
                'job_id': job_id,
                'status': 'queued',
                'estimated_duration_ms': self._estimate_duration(source_code, config)
            })
        
        @self.app.route('/jobs/<job_id>', methods=['GET'])
        def get_job(job_id: str):
            """Get job status and results."""
            tenant = g.tenant
            
            job = self._get_job(job_id)
            if not job or job.tenant_id != tenant.id:
                return jsonify({'error': 'Job not found'}), 404
            
            response = {
                'job_id': job.id,
                'status': job.status,
                'created_at': job.created_at,
                'cost_credits': job.cost_credits
            }
            
            if job.started_at:
                response['started_at'] = job.started_at
            
            if job.completed_at:
                response['completed_at'] = job.completed_at
                response['duration_ms'] = job.duration_ms
            
            if job.result:
                response['result'] = job.result
            
            return jsonify(response)
        
        @self.app.route('/contracts/generate', methods=['POST'])
        @self.limiter.limit("50 per minute")
        def generate_contracts():
            """Generate contracts from natural language."""
            tenant = g.tenant
            
            data = request.get_json()
            text = data.get('text', '')
            context = data.get('context', {})
            
            if not text.strip():
                return jsonify({'error': 'Text is required'}), 400
            
            try:
                contracts = self.contract_generator.generate_from_text(text, context)
                
                # Convert to AEON syntax
                aeon_contracts = self.contract_generator.generate_aeon_contracts(contracts)
                
                cost_credits = len(contracts) * 10  # 10 credits per contract
                
                self._update_usage(tenant.id, '/contracts/generate', cost_credits, {
                    'text_length': len(text),
                    'contracts_generated': len(contracts)
                })
                
                return jsonify({
                    'contracts': [asdict(c) for c in contracts],
                    'aeon_syntax': aeon_contracts,
                    'explanation': self.contract_generator.explain_contracts(contracts),
                    'cost_credits': cost_credits
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/tests/generate', methods=['POST'])
        @self.limiter.limit("30 per minute")
        def generate_tests():
            """Generate tests from verification results."""
            tenant = g.tenant
            
            data = request.get_json()
            file_path = data.get('file_path', 'unknown.py')
            verification_result = data.get('verification_result', {})
            language = data.get('language', 'python')
            
            if not verification_result:
                return jsonify({'error': 'Verification result is required'}), 400
            
            try:
                tests = self.test_generator.generate_tests(file_path, verification_result)
                
                cost_credits = len(tests) * 15  # 15 credits per test
                
                self._update_usage(tenant.id, '/tests/generate', cost_credits, {
                    'file_path': file_path,
                    'tests_generated': len(tests)
                })
                
                # Generate test file content
                test_content = None
                if tests:
                    import tempfile
                    with tempfile.NamedTemporaryFile(mode='w', suffix='_test.py', delete=False) as f:
                        self.test_generator.generate_test_file(tests, f.name, language)
                        with open(f.name, 'r') as test_file:
                            test_content = test_file.read()
                        Path(f.name).unlink()  # Clean up
                
                return jsonify({
                    'tests': [asdict(t) for t in tests],
                    'test_file_content': test_content,
                    'cost_credits': cost_credits
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/analytics', methods=['GET'])
        def get_analytics():
            """Get usage analytics for the tenant."""
            tenant = g.tenant
            
            # Get analytics for last 30 days
            thirty_days_ago = time.time() - (30 * 24 * 60 * 60)
            
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute("""
                    SELECT 
                        date,
                        SUM(total_verifications) as verifications,
                        SUM(total_errors) as errors,
                        AVG(avg_duration_ms) as avg_duration,
                        SUM(cost_credits) as credits
                    FROM analytics 
                    WHERE tenant_id = ? AND date >= date('now', '-30 days')
                    GROUP BY date
                    ORDER BY date
                """, (tenant.id,))
                
                daily_data = []
                for row in cursor.fetchall():
                    daily_data.append({
                        'date': row[0],
                        'verifications': row[1] or 0,
                        'errors': row[2] or 0,
                        'avg_duration_ms': round(row[3] or 0, 2),
                        'credits': row[4] or 0
                    })
                
                # Get language breakdown
                cursor = conn.execute("""
                    SELECT json_extract(languages_used, '$') as languages_json
                    FROM analytics 
                    WHERE tenant_id = ? AND date >= date('now', '-30 days')
                """, (tenant.id,))
                
                language_stats = {}
                for row in cursor.fetchall():
                    try:
                        languages = json.loads(row[0] or '{}')
                        for lang, count in languages.items():
                            language_stats[lang] = language_stats.get(lang, 0) + count
                    except json.JSONDecodeError:
                        continue
                
                return jsonify({
                    'daily_analytics': daily_data,
                    'language_breakdown': language_stats,
                    'current_usage': tenant.current_usage,
                    'usage_limits': tenant.usage_limits
                })
                
            finally:
                conn.close()
        
        @self.app.route('/usage', methods=['GET'])
        def get_usage():
            """Get current usage statistics."""
            tenant = g.tenant
            
            # Calculate usage percentages
            usage_percentages = {}
            for key, limit in tenant.usage_limits.items():
                current = tenant.current_usage.get(key.replace('_per_month', '_this_month'), 0)
                usage_percentages[key] = round((current / limit) * 100, 1) if limit > 0 else 0
            
            return jsonify({
                'current_usage': tenant.current_usage,
                'usage_limits': tenant.usage_limits,
                'usage_percentages': usage_percentages,
                'billing_cycle_start': tenant.billing_cycle_start,
                'next_billing_cycle': tenant.billing_cycle_start + (30 * 24 * 60 * 60)
            })
    
    def _get_tenant_by_api_key(self, api_key: str) -> Optional[Tenant]:
        """Get tenant by API key."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute("""
                SELECT id, name, api_key, plan, usage_limits, current_usage, created_at, billing_cycle_start
                FROM tenants WHERE api_key = ?
            """, (api_key,))
            
            row = cursor.fetchone()
            if row:
                return Tenant(
                    id=row[0],
                    name=row[1],
                    api_key=row[2],
                    plan=row[3],
                    usage_limits=json.loads(row[4]),
                    current_usage=json.loads(row[5]),
                    created_at=row[6],
                    billing_cycle_start=row[7]
                )
            return None
        finally:
            conn.close()
    
    def _check_usage_limits(self, tenant: Tenant, request_data: Dict[str, Any]) -> bool:
        """Check if tenant has exceeded usage limits."""
        # Check monthly verification limit
        if tenant.current_usage['verifications_this_month'] >= tenant.usage_limits['verifications_per_month']:
            return False
        
        # Check credits
        if tenant.current_usage['credits_used_this_month'] >= tenant.usage_limits['credits_per_month']:
            return False
        
        # Check file size
        source_code = request_data.get('source_code', '')
        if len(source_code) > tenant.usage_limits['max_file_size_kb'] * 1024:
            return False
        
        return True
    
    def _calculate_cost(self, source_code: str, config: Dict[str, Any]) -> int:
        """Calculate cost in credits for verification."""
        base_cost = 10  # Base cost per verification
        
        # Add cost for source code size
        size_cost = len(source_code) // 1000  # 1 credit per 1000 characters
        
        # Add cost for analysis depth
        depth_multiplier = 1.0
        if config.get('deep_verify', False):
            depth_multiplier = 3.0
        elif config.get('profile') == 'security':
            depth_multiplier = 2.5
        elif config.get('profile') == 'safety':
            depth_multiplier = 2.0
        
        total_cost = int((base_cost + size_cost) * depth_multiplier)
        return max(total_cost, 1)  # Minimum 1 credit
    
    def _update_usage(self, tenant_id: str, endpoint: str, cost_credits: int, metadata: Dict[str, Any]) -> None:
        """Update tenant usage statistics."""
        conn = sqlite3.connect(self.db_path)
        try:
            # Get current usage
            cursor = conn.execute("SELECT current_usage FROM tenants WHERE id = ?", (tenant_id,))
            row = cursor.fetchone()
            if row:
                current_usage = json.loads(row[0])
                
                # Update usage
                if endpoint == '/verify':
                    current_usage['verifications_this_month'] += 1
                current_usage['credits_used_this_month'] += cost_credits
                
                # Save updated usage
                conn.execute("""
                    UPDATE tenants SET current_usage = ? WHERE id = ?
                """, (json.dumps(current_usage), tenant_id))
                
                # Log usage
                log_id = str(uuid.uuid4())
                conn.execute("""
                    INSERT INTO usage_logs (id, tenant_id, timestamp, endpoint, cost_credits, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (log_id, tenant_id, time.time(), endpoint, cost_credits, json.dumps(metadata)))
                
                conn.commit()
        finally:
            conn.close()
    
    def _log_verification(self, tenant_id: str, source_code: str, language: str, 
                         config: Dict[str, Any], result: Dict[str, Any], 
                         duration_ms: float, cost_credits: int) -> None:
        """Log verification for analytics."""
        conn = sqlite3.connect(self.db_path)
        try:
            # Get or create today's analytics record
            today = datetime.now().strftime('%Y-%m-%d')
            
            cursor = conn.execute("""
                SELECT total_verifications, total_errors, avg_duration_ms, languages_used, cost_credits
                FROM analytics WHERE tenant_id = ? AND date = ?
            """, (tenant_id, today))
            
            row = cursor.fetchone()
            if row:
                # Update existing record
                total_verifications = row[0] + 1
                total_errors = row[1] + (len(result.get('errors', [])))
                avg_duration_ms = (row[2] + duration_ms) / 2
                
                languages = json.loads(row[3])
                languages[language] = languages.get(language, 0) + 1
                
                total_credits = row[4] + cost_credits
                
                conn.execute("""
                    UPDATE analytics SET 
                        total_verifications = ?, total_errors = ?, avg_duration_ms = ?,
                        languages_used = ?, cost_credits = ?
                    WHERE tenant_id = ? AND date = ?
                """, (total_verifications, total_errors, avg_duration_ms,
                      json.dumps(languages), total_credits, tenant_id, today))
            else:
                # Create new record
                languages = {language: 1}
                conn.execute("""
                    INSERT INTO analytics (id, tenant_id, date, total_verifications, total_errors, 
                                          avg_duration_ms, languages_used, cost_credits)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (str(uuid.uuid4()), tenant_id, today, 1, len(result.get('errors', [])),
                      duration_ms, json.dumps(languages), cost_credits))
            
            conn.commit()
        finally:
            conn.close()
    
    def _save_job(self, job: VerificationJob) -> None:
        """Save verification job to database."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                INSERT OR REPLACE INTO verification_jobs 
                (id, tenant_id, source_code, language, analysis_config, status, result,
                 created_at, started_at, completed_at, duration_ms, cost_credits)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                job.id, job.tenant_id, job.source_code, job.language,
                json.dumps(job.analysis_config), job.status,
                json.dumps(job.result) if job.result else None,
                job.created_at, job.started_at, job.completed_at,
                job.duration_ms, job.cost_credits
            ))
            conn.commit()
        finally:
            conn.close()
    
    def _get_job(self, job_id: str) -> Optional[VerificationJob]:
        """Get verification job by ID."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute("""
                SELECT id, tenant_id, source_code, language, analysis_config, status, result,
                       created_at, started_at, completed_at, duration_ms, cost_credits
                FROM verification_jobs WHERE id = ?
            """, (job_id,))
            
            row = cursor.fetchone()
            if row:
                return VerificationJob(
                    id=row[0], tenant_id=row[1], source_code=row[2], language=row[3],
                    analysis_config=json.loads(row[4]), status=row[5],
                    result=json.loads(row[6]) if row[6] else None,
                    created_at=row[7], started_at=row[8], completed_at=row[9],
                    duration_ms=row[10], cost_credits=row[11]
                )
            return None
        finally:
            conn.close()
    
    def _get_active_job_count(self, tenant_id: str) -> int:
        """Get count of active jobs for tenant."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute("""
                SELECT COUNT(*) FROM verification_jobs 
                WHERE tenant_id = ? AND status IN ('queued', 'running')
            """, (tenant_id,))
            return cursor.fetchone()[0]
        finally:
            conn.close()
    
    def _estimate_duration(self, source_code: str, config: Dict[str, Any]) -> int:
        """Estimate verification duration in milliseconds."""
        base_duration = 1000  # 1 second base
        
        # Add time for source code size
        size_duration = len(source_code) * 0.5  # 0.5ms per character
        
        # Add time for analysis depth
        depth_multiplier = 1.0
        if config.get('deep_verify', False):
            depth_multiplier = 5.0
        elif config.get('profile') == 'security':
            depth_multiplier = 3.0
        elif config.get('profile') == 'safety':
            depth_multiplier = 2.5
        
        estimated_ms = int((base_duration + size_duration) * depth_multiplier)
        return estimated_ms
    
    def _process_job_async(self, job_id: str) -> None:
        """Process verification job asynchronously."""
        # In production, this would use a proper task queue like Celery
        import threading
        
        def process_job():
            job = self._get_job(job_id)
            if not job:
                return
            
            try:
                # Update job status to running
                job.status = 'running'
                job.started_at = time.time()
                self._save_job(job)
                
                # Perform verification
                start_time = time.time()
                result = verify_source_code(job.source_code, job.language, job.analysis_config)
                duration_ms = (time.time() - start_time) * 1000
                
                # Update job with results
                job.status = 'completed'
                job.result = result
                job.completed_at = time.time()
                job.duration_ms = duration_ms
                
                # Update usage
                self._update_usage(job.tenant_id, '/verify/async', job.cost_credits, {
                    'job_id': job_id,
                    'language': job.language,
                    'duration_ms': duration_ms
                })
                
                # Log verification
                self._log_verification(job.tenant_id, job.source_code, job.language,
                                     job.analysis_config, result, duration_ms, job.cost_credits)
                
            except Exception as e:
                job.status = 'failed'
                job.result = {'error': str(e)}
                job.completed_at = time.time()
            
            finally:
                self._save_job(job)
        
        # Start processing in background thread
        thread = threading.Thread(target=process_job)
        thread.daemon = True
        thread.start()
    
    def run(self, host: str = '0.0.0.0', port: int = 9000, debug: bool = False) -> None:
        """Run the FVaaS server."""
        print(f"🚀 AEON Formal Verification as a Service starting on http://{host}:{port}")
        print("📊 API Documentation available at http://{}:{}/docs".format(host, port))
        print("🔑 Default API key: default-api-key-change-in-production")
        self.app.run(host=host, port=port, debug=debug)


def verify_source_code(source_code: str, language: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Mock verification function - would integrate with actual AEON verification."""
    # This is a placeholder - in reality would call AEON's verification engines
    import time
    time.sleep(0.1)  # Simulate processing time
    
    # Mock result based on source content
    errors = []
    if 'division' in source_code and '0' in source_code:
        errors.append({
            'type': 'division_by_zero',
            'message': 'Possible division by zero',
            'line': source_code.split('\n').index([line for line in source_code.split('\n') if 'division' in line and '0' in line][0]) + 1
        })
    
    return {
        'verified': len(errors) == 0,
        'errors': errors,
        'warnings': [],
        'functions_analyzed': source_code.count('def ') + source_code.count('function '),
        'classes_analyzed': source_code.count('class '),
        'summary': f"✅ VERIFIED" if len(errors) == 0 else f"❌ {len(errors)} error(s) found"
    }


def main():
    """Run the FVaaS service."""
    import argparse
    
    parser = argparse.ArgumentParser(description='AEON Formal Verification as a Service')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=9000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--jwt-secret', help='JWT secret key')
    
    args = parser.parse_args()
    
    service = FVaaSService(jwt_secret=args.jwt_secret)
    service.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
