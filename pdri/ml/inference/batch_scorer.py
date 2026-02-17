"""
Batch Scorer
============

High-throughput batch risk scoring for large-scale operations.

Use cases:
    - Nightly risk assessment of all assets
    - Periodic compliance scoring
    - Data warehouse population
    - Report generation

Author: PDRI Team
Version: 1.0.0
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
import numpy as np


@dataclass
class BatchJob:
    """A batch scoring job."""
    job_id: str
    status: str  # "pending", "running", "completed", "failed"
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_items: int = 0
    processed_items: int = 0
    failed_items: int = 0
    error_message: Optional[str] = None
    results_path: Optional[str] = None
    
    @property
    def progress(self) -> float:
        if self.total_items == 0:
            return 0.0
        return self.processed_items / self.total_items
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_items": self.total_items,
            "processed_items": self.processed_items,
            "failed_items": self.failed_items,
            "progress": self.progress,
            "error_message": self.error_message,
            "results_path": self.results_path,
        }


@dataclass
class BatchResult:
    """Results from a batch scoring run."""
    job_id: str
    predictions: List[Dict[str, Any]]
    summary: Dict[str, Any]
    duration_seconds: float
    timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "prediction_count": len(self.predictions),
            "summary": self.summary,
            "duration_seconds": self.duration_seconds,
            "timestamp": self.timestamp.isoformat(),
        }


class BatchScorer:
    """
    High-throughput batch risk scoring.
    
    Features:
    - Parallel processing
    - Progress tracking
    - Result aggregation
    - Automatic chunking
    - Error handling and retry
    
    Example:
        scorer = BatchScorer(predictor)
        job = await scorer.submit_job(node_ids)
        result = await scorer.wait_for_completion(job.job_id)
    """
    
    def __init__(
        self,
        predictor: Any,
        graph_engine: Optional[Any] = None,
        chunk_size: int = 100,
        max_workers: int = 4,
        retry_count: int = 3
    ):
        """
        Initialize batch scorer.
        
        Args:
            predictor: RiskPredictor instance
            graph_engine: Optional graph engine for querying nodes
            chunk_size: Number of items per batch
            max_workers: Number of parallel workers
            retry_count: Number of retries for failed items
        """
        self.predictor = predictor
        self.graph_engine = graph_engine
        self.chunk_size = chunk_size
        self.max_workers = max_workers
        self.retry_count = retry_count
        
        # Job tracking
        self._jobs: Dict[str, BatchJob] = {}
        self._results: Dict[str, BatchResult] = {}
        self._job_counter = 0
    
    async def submit_job(
        self,
        node_ids: Optional[List[str]] = None,
        node_types: Optional[List[str]] = None,
        callback: Optional[Callable[[BatchJob], None]] = None
    ) -> BatchJob:
        """
        Submit a batch scoring job.
        
        Args:
            node_ids: Specific nodes to score (if None, query from graph)
            node_types: Filter by node types when querying
            callback: Optional callback for progress updates
        
        Returns:
            BatchJob with job ID for tracking
        """
        self._job_counter += 1
        job_id = f"batch-{self._job_counter:06d}"
        
        job = BatchJob(
            job_id=job_id,
            status="pending",
            created_at=datetime.now(timezone.utc),
        )
        self._jobs[job_id] = job
        
        # Start job in background
        asyncio.create_task(
            self._run_job(job_id, node_ids, node_types, callback)
        )
        
        return job
    
    async def _run_job(
        self,
        job_id: str,
        node_ids: Optional[List[str]],
        node_types: Optional[List[str]],
        callback: Optional[Callable]
    ) -> None:
        """Run a batch job."""
        job = self._jobs[job_id]
        
        try:
            job.status = "running"
            job.started_at = datetime.now(timezone.utc)
            
            # Get nodes to process
            if node_ids is None:
                node_ids = await self._get_all_nodes(node_types)
            
            job.total_items = len(node_ids)
            
            # Process in chunks
            predictions = []
            failed = []
            
            for i in range(0, len(node_ids), self.chunk_size):
                chunk = node_ids[i:i + self.chunk_size]
                
                # Process chunk with semaphore for concurrency control
                chunk_results = await self._process_chunk(chunk)
                
                for node_id, result in chunk_results:
                    if result is not None:
                        predictions.append(result)
                        job.processed_items += 1
                    else:
                        failed.append(node_id)
                        job.failed_items += 1
                
                # Progress callback
                if callback:
                    callback(job)
            
            # Retry failed items
            if failed and self.retry_count > 0:
                retried = await self._retry_failed(failed)
                predictions.extend(retried)
                job.processed_items += len(retried)
                job.failed_items -= len(retried)
            
            # Create result
            job.status = "completed"
            job.completed_at = datetime.now(timezone.utc)
            
            duration = (job.completed_at - job.started_at).total_seconds()
            
            summary = self._create_summary(predictions)
            
            self._results[job_id] = BatchResult(
                job_id=job_id,
                predictions=predictions,
                summary=summary,
                duration_seconds=duration,
                timestamp=job.completed_at,
            )
            
        except Exception as e:
            job.status = "failed"
            job.error_message = str(e)
            job.completed_at = datetime.now(timezone.utc)
    
    async def _get_all_nodes(
        self,
        node_types: Optional[List[str]] = None
    ) -> List[str]:
        """Get all node IDs from graph."""
        if self.graph_engine and hasattr(self.graph_engine, 'get_all_nodes'):
            nodes = await self.graph_engine.get_all_nodes(node_types)
            return [n.get("id") or n.get("node_id") for n in nodes]
        return []
    
    async def _process_chunk(
        self,
        node_ids: List[str]
    ) -> List[tuple]:
        """Process a chunk of nodes."""
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def process_one(node_id: str):
            async with semaphore:
                try:
                    prediction = await self.predictor.predict(node_id)
                    return (node_id, prediction.to_dict())
                except Exception:
                    return (node_id, None)
        
        tasks = [process_one(node_id) for node_id in node_ids]
        return await asyncio.gather(*tasks)
    
    async def _retry_failed(
        self,
        failed_ids: List[str]
    ) -> List[Dict[str, Any]]:
        """Retry failed predictions."""
        results = []
        
        for _ in range(self.retry_count):
            still_failed = []
            
            for node_id in failed_ids:
                try:
                    prediction = await self.predictor.predict(node_id)
                    results.append(prediction.to_dict())
                except Exception:
                    still_failed.append(node_id)
            
            failed_ids = still_failed
            if not failed_ids:
                break
            
            # Exponential backoff
            await asyncio.sleep(1)
        
        return results
    
    def _create_summary(self, predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create summary statistics from predictions."""
        if not predictions:
            return {"total": 0}
        
        probabilities = [p["risk_probability"] for p in predictions]
        
        # Risk distribution
        distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for p in predictions:
            label = p.get("risk_label", "medium")
            distribution[label] = distribution.get(label, 0) + 1
        
        return {
            "total": len(predictions),
            "risk_distribution": distribution,
            "statistics": {
                "mean": float(np.mean(probabilities)),
                "median": float(np.median(probabilities)),
                "std": float(np.std(probabilities)),
                "min": float(np.min(probabilities)),
                "max": float(np.max(probabilities)),
                "p90": float(np.percentile(probabilities, 90)),
                "p95": float(np.percentile(probabilities, 95)),
            },
            "high_risk_count": distribution.get("high", 0) + distribution.get("critical", 0),
            "high_risk_percentage": (
                (distribution.get("high", 0) + distribution.get("critical", 0)) 
                / len(predictions) * 100
            ),
        }
    
    async def get_job_status(self, job_id: str) -> Optional[BatchJob]:
        """Get status of a batch job."""
        return self._jobs.get(job_id)
    
    async def wait_for_completion(
        self,
        job_id: str,
        timeout_seconds: float = 3600,
        poll_interval: float = 1.0
    ) -> Optional[BatchResult]:
        """
        Wait for a job to complete.
        
        Args:
            job_id: Job ID to wait for
            timeout_seconds: Maximum wait time
            poll_interval: Polling interval
        
        Returns:
            BatchResult if completed, None if timeout or not found
        """
        start = datetime.now(timezone.utc)
        
        while True:
            job = self._jobs.get(job_id)
            if not job:
                return None
            
            if job.status in ("completed", "failed"):
                return self._results.get(job_id)
            
            elapsed = (datetime.now(timezone.utc) - start).total_seconds()
            if elapsed >= timeout_seconds:
                return None
            
            await asyncio.sleep(poll_interval)
    
    async def get_results(self, job_id: str) -> Optional[BatchResult]:
        """Get results of a completed job."""
        return self._results.get(job_id)
    
    def list_jobs(
        self,
        status: Optional[str] = None
    ) -> List[BatchJob]:
        """List all jobs, optionally filtered by status."""
        jobs = list(self._jobs.values())
        if status:
            jobs = [j for j in jobs if j.status == status]
        return sorted(jobs, key=lambda j: j.created_at, reverse=True)
    
    async def score_all_nodes(
        self,
        node_types: Optional[List[str]] = None
    ) -> BatchResult:
        """
        Score all nodes and wait for completion.
        
        Convenience method that submits and waits.
        
        Args:
            node_types: Optional filter by node types
        
        Returns:
            BatchResult with all predictions
        """
        job = await self.submit_job(node_types=node_types)
        result = await self.wait_for_completion(job.job_id)
        
        if result is None:
            raise RuntimeError(f"Batch job {job.job_id} failed or timed out")
        
        return result
    
    async def export_results(
        self,
        job_id: str,
        format: str = "json",
        path: Optional[str] = None
    ) -> str:
        """
        Export job results to file.
        
        Args:
            job_id: Job ID
            format: Output format ("json", "csv")
            path: Optional output path
        
        Returns:
            Path to exported file
        """
        result = self._results.get(job_id)
        if not result:
            raise ValueError(f"No results found for job {job_id}")
        
        if path is None:
            path = f"batch_results_{job_id}.{format}"
        
        if format == "json":
            import json
            with open(path, "w") as f:
                json.dump({
                    "job_id": result.job_id,
                    "summary": result.summary,
                    "predictions": result.predictions,
                }, f, indent=2)
        elif format == "csv":
            import csv
            with open(path, "w", newline="") as f:
                if result.predictions:
                    writer = csv.DictWriter(f, fieldnames=result.predictions[0].keys())
                    writer.writeheader()
                    writer.writerows(result.predictions)
        else:
            raise ValueError(f"Unknown format: {format}")
        
        return path
