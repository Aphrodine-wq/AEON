"""AEON Advanced Caching Layer — Persistent Verification Results Cache.

Provides intelligent caching of verification results across runs with
semantic hash-based invalidation and multi-level cache storage.

Usage:
    from aeon.cache import VerificationCache
    cache = VerificationCache()
    result = cache.get_or_verify(filepath, verifier_func)
"""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import sqlite3
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Tuple, Union
from threading import Lock

from aeon.errors import CompileError


@dataclass
class CacheEntry:
    """A cached verification result."""
    file_path: str
    file_hash: str
    content_hash: str
    dependency_hashes: Dict[str, str]
    analysis_config: Dict[str, Any]
    result: Dict[str, Any]
    timestamp: float
    duration_ms: float
    verification_version: str = "0.5.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CacheEntry:
        """Create from dictionary."""
        return cls(**data)


class VerificationCache:
    """Advanced verification results cache with SQLite backend."""
    
    def __init__(self, cache_dir: str = ".aeon-cache", max_size_mb: int = 500):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.db_path = self.cache_dir / "verification_cache.db"
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.lock = Lock()
        
        self._init_database()
        self._cleanup_old_entries()
    
    def _init_database(self) -> None:
        """Initialize SQLite database for cache storage."""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS cache_entries (
                        file_path TEXT NOT NULL,
                        analysis_config_hash TEXT NOT NULL,
                        file_hash TEXT NOT NULL,
                        content_hash TEXT NOT NULL,
                        dependency_hashes TEXT NOT NULL,
                        analysis_config TEXT NOT NULL,
                        result TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        duration_ms REAL NOT NULL,
                        verification_version TEXT NOT NULL,
                        access_count INTEGER DEFAULT 0,
                        last_access REAL NOT NULL,
                        PRIMARY KEY (file_path, analysis_config_hash)
                    )
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_timestamp 
                    ON cache_entries(timestamp)
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_last_access 
                    ON cache_entries(last_access)
                """)

                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_file_config
                    ON cache_entries(file_path, analysis_config_hash)
                """)
                
                conn.commit()
            finally:
                conn.close()
    
    def _cleanup_old_entries(self) -> None:
        """Remove old entries to maintain cache size limit."""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                # Get current cache size
                cursor = conn.execute(
                    "SELECT SUM(LENGTH(result)) FROM cache_entries"
                )
                current_size = cursor.fetchone()[0] or 0
                
                if current_size > self.max_size_bytes:
                    # Remove oldest entries until under limit
                    cursor = conn.execute("""
                        SELECT file_path FROM cache_entries 
                        ORDER BY last_access ASC
                    """)
                    
                    bytes_to_remove = current_size - self.max_size_bytes * 0.8
                    removed = 0
                    
                    for row in cursor:
                        if removed >= bytes_to_remove:
                            break
                        
                        file_path = row[0]
                        cursor2 = conn.execute(
                            "SELECT LENGTH(result) FROM cache_entries WHERE file_path = ?",
                            (file_path,)
                        )
                        entry_size = cursor2.fetchone()[0] or 0
                        
                        conn.execute(
                            "DELETE FROM cache_entries WHERE file_path = ?",
                            (file_path,)
                        )
                        removed += entry_size
                    
                    conn.commit()
            finally:
                conn.close()
    
    def _compute_file_hash(self, filepath: str) -> str:
        """Compute SHA-256 hash of file contents."""
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""
    
    def _compute_content_hash(self, content: str) -> str:
        """Compute hash of normalized content."""
        # Normalize whitespace and line endings for semantic comparison
        normalized = '\n'.join(line.strip() for line in content.splitlines() if line.strip())
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def _compute_dependency_hashes(self, dependencies: List[str]) -> Dict[str, str]:
        """Compute hashes for dependency files."""
        dep_hashes = {}
        for dep_path in dependencies:
            if os.path.exists(dep_path):
                dep_hashes[dep_path] = self._compute_file_hash(dep_path)
        return dep_hashes
    
    def _serialize_analysis_config(self, config: Dict[str, Any]) -> str:
        """Serialize analysis configuration for cache key."""
        # Normalize config to ensure consistent serialization
        normalized = {
            "deep_verify": config.get("deep_verify", False),
            "analyses": tuple(sorted(config.get("analyses", []))),
            "profile": config.get("profile", ""),
        }
        return json.dumps(normalized, sort_keys=True)
    
    def _get_config_hash(self, analysis_config: Dict[str, Any]) -> str:
        """Compute a stable hash of the analysis configuration."""
        return hashlib.sha256(
            self._serialize_analysis_config(analysis_config).encode()
        ).hexdigest()

    def _get_cache_key(self, filepath: str, analysis_config: Dict[str, Any]) -> str:
        """Generate cache key for a file and analysis configuration."""
        file_hash = self._compute_file_hash(filepath)
        config_hash = self._get_config_hash(analysis_config)
        return f"{filepath}:{file_hash}:{config_hash}"
    
    def get(self, filepath: str, analysis_config: Dict[str, Any],
            dependencies: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        """Get cached verification result if valid."""
        if not os.path.exists(filepath):
            return None
        
        dependencies = dependencies or []
        current_file_hash = self._compute_file_hash(filepath)
        current_dep_hashes = self._compute_dependency_hashes(dependencies)
        config_hash = self._get_config_hash(analysis_config)

        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute("""
                    SELECT result, dependency_hashes, timestamp 
                    FROM cache_entries 
                    WHERE file_path = ? AND analysis_config_hash = ? AND file_hash = ?
                """, (filepath, config_hash, current_file_hash))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                cached_result_json, cached_deps_json, timestamp = row
                cached_deps = json.loads(cached_deps_json)
                
                # Check if dependencies have changed
                for dep_path, dep_hash in cached_deps.items():
                    if dep_path not in current_dep_hashes:
                        return None  # Dependency removed
                    if current_dep_hashes[dep_path] != dep_hash:
                        return None  # Dependency changed
                
                # Check if new dependencies were added
                if set(current_dep_hashes.keys()) != set(cached_deps.keys()):
                    return None
                
                # Update access statistics
                conn.execute("""
                    UPDATE cache_entries 
                    SET access_count = access_count + 1, last_access = ?
                    WHERE file_path = ? AND analysis_config_hash = ?
                """, (time.time(), filepath, config_hash))
                conn.commit()
                
                return json.loads(cached_result_json)
                
            finally:
                conn.close()
    
    def put(self, filepath: str, result: Dict[str, Any], 
            analysis_config: Dict[str, Any], duration_ms: float,
            dependencies: Optional[List[str]] = None) -> None:
        """Cache a verification result."""
        if not os.path.exists(filepath):
            return
        
        dependencies = dependencies or []
        
        config_hash = self._get_config_hash(analysis_config)
        now = time.time()
        entry = CacheEntry(
            file_path=filepath,
            file_hash=self._compute_file_hash(filepath),
            content_hash=self._compute_content_hash(
                json.dumps(result.get("source", ""), sort_keys=True)
            ),
            dependency_hashes=self._compute_dependency_hashes(dependencies),
            analysis_config=analysis_config,
            result=result,
            timestamp=now,
            duration_ms=duration_ms,
        )

        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("""
                    INSERT OR REPLACE INTO cache_entries 
                    (file_path, analysis_config_hash, file_hash, content_hash,
                     dependency_hashes, analysis_config, result, timestamp,
                     duration_ms, verification_version, access_count, last_access)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """, (
                    entry.file_path,
                    config_hash,
                    entry.file_hash,
                    entry.content_hash,
                    json.dumps(entry.dependency_hashes),
                    self._serialize_analysis_config(entry.analysis_config),
                    json.dumps(entry.result),
                    entry.timestamp,
                    entry.duration_ms,
                    entry.verification_version,
                    now,
                ))
                conn.commit()
            finally:
                conn.close()
            
            # Cleanup if needed
            self._cleanup_old_entries()
    
    def get_or_verify(self, filepath: str, verifier_func: Callable[[], Dict[str, Any]],
                      analysis_config: Dict[str, Any],
                      dependencies: Optional[List[str]] = None) -> Tuple[Dict[str, Any], bool]:
        """Get cached result or compute and cache it."""
        # Try to get from cache
        cached = self.get(filepath, analysis_config, dependencies)
        if cached is not None:
            return cached, True
        
        # Compute result
        start_time = time.time()
        try:
            result = verifier_func()
            duration_ms = (time.time() - start_time) * 1000
            
            # Cache the result
            self.put(filepath, result, analysis_config, duration_ms, dependencies)
            
            return result, False
        except Exception as e:
            # Don't cache errors
            raise
    
    def invalidate(self, filepath: str,
                   analysis_config: Optional[Dict[str, Any]] = None) -> None:
        """Invalidate cache entries for a file.

        If analysis_config is given, only that specific config's entry is
        removed.  Otherwise all entries for the file are removed.
        """
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                if analysis_config is not None:
                    config_hash = self._get_config_hash(analysis_config)
                    conn.execute(
                        "DELETE FROM cache_entries "
                        "WHERE file_path = ? AND analysis_config_hash = ?",
                        (filepath, config_hash),
                    )
                else:
                    conn.execute(
                        "DELETE FROM cache_entries WHERE file_path = ?",
                        (filepath,),
                    )
                conn.commit()
            finally:
                conn.close()
    
    def invalidate_all(self) -> None:
        """Clear all cache entries."""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("DELETE FROM cache_entries")
                conn.commit()
            finally:
                conn.close()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute("""
                    SELECT 
                        COUNT(*) as total_entries,
                        SUM(access_count) as total_accesses,
                        AVG(duration_ms) as avg_duration_ms,
                        MAX(timestamp) as newest_entry,
                        MIN(timestamp) as oldest_entry
                    FROM cache_entries
                """)
                
                row = cursor.fetchone()
                total_entries, total_accesses, avg_duration, newest, oldest = row
                
                # Get cache size
                cursor = conn.execute(
                    "SELECT SUM(LENGTH(result)) FROM cache_entries"
                )
                cache_size_bytes = cursor.fetchone()[0] or 0
                
                return {
                    "total_entries": total_entries or 0,
                    "total_accesses": total_accesses or 0,
                    "avg_duration_ms": round(avg_duration or 0, 2),
                    "cache_size_mb": round(cache_size_bytes / (1024 * 1024), 2),
                    "newest_entry": newest,
                    "oldest_entry": oldest,
                    "hit_rate": (total_accesses / max(total_entries, 1)) if total_entries > 0 else 0,
                }
            finally:
                conn.close()
    
    def export_cache(self, export_path: str) -> None:
        """Export cache to a file for sharing across environments."""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute("""
                    SELECT file_path, file_hash, content_hash, dependency_hashes,
                           analysis_config, result, timestamp, duration_ms,
                           verification_version
                    FROM cache_entries
                """)
                
                entries = []
                for row in cursor:
                    entries.append({
                        "file_path": row[0],
                        "file_hash": row[1],
                        "content_hash": row[2],
                        "dependency_hashes": json.loads(row[3]),
                        "analysis_config": json.loads(row[4]),
                        "result": json.loads(row[5]),
                        "timestamp": row[6],
                        "duration_ms": row[7],
                        "verification_version": row[8],
                    })
                
                export_data = {
                    "version": "0.5.0",
                    "export_timestamp": time.time(),
                    "entries": entries,
                }
                
                with open(export_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                    
            finally:
                conn.close()
    
    def import_cache(self, import_path: str) -> int:
        """Import cache entries from a file."""
        if not os.path.exists(import_path):
            return 0
        
        with open(import_path, 'r') as f:
            import_data = json.load(f)
        
        entries_imported = 0
        
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                for entry_data in import_data.get("entries", []):
                    # Verify file still exists and hash matches
                    filepath = entry_data["file_path"]
                    if not os.path.exists(filepath):
                        continue
                    
                    current_hash = self._compute_file_hash(filepath)
                    if current_hash != entry_data["file_hash"]:
                        continue  # File has changed
                    
                    # Import entry
                    conn.execute("""
                        INSERT OR REPLACE INTO cache_entries 
                        (file_path, file_hash, content_hash, dependency_hashes,
                         analysis_config, result, timestamp, duration_ms,
                         verification_version, access_count, last_access)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                    """, (
                        entry_data["file_path"],
                        entry_data["file_hash"],
                        entry_data["content_hash"],
                        json.dumps(entry_data["dependency_hashes"]),
                        json.dumps(entry_data["analysis_config"]),
                        json.dumps(entry_data["result"]),
                        entry_data["timestamp"],
                        entry_data["duration_ms"],
                        entry_data["verification_version"],
                        time.time(),
                    ))
                    entries_imported += 1
                
                conn.commit()
            finally:
                conn.close()
        
        return entries_imported
