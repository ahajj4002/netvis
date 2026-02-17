"""
NetVis job managers.
Background scan and coursework execution with persisted state.
"""

import threading
import uuid
from typing import Any, Callable, Optional


class ScanJobManager:
    """Background scan execution manager with persisted state."""

    def __init__(
        self,
        datastore,
        scanner,
        run_profile_scan_fn: Callable[..., dict],
    ):
        self.datastore = datastore
        self.scanner = scanner
        self._run_profile_scan = run_profile_scan_fn

    def start(self, profile: str, target: Optional[str]) -> str:
        job_id = str(uuid.uuid4())
        self.datastore.create_scan_job(job_id, profile, target or self.scanner.network_cidr)
        thread = threading.Thread(
            target=self._run,
            args=(job_id, profile, target),
            daemon=True,
        )
        thread.start()
        return job_id

    def _run(self, job_id: str, profile: str, target: Optional[str]):
        try:
            self.datastore.update_scan_job(job_id, status="running", progress=1, message="Initializing scan")

            def progress_cb(p: int, msg: str):
                self.datastore.update_scan_job(job_id, status="running", progress=p, message=msg)

            result = self._run_profile_scan(
                self.scanner,
                self.datastore,
                profile,
                target,
                progress_cb,
            )
            self.datastore.update_scan_job(
                job_id,
                status="completed",
                progress=100,
                message="Completed",
                result=result,
            )
        except Exception as exc:
            self.datastore.update_scan_job(
                job_id,
                status="failed",
                progress=100,
                message="Failed",
                error=str(exc),
            )


class CourseworkJobManager:
    """Background runner for rubric-aligned module scripts (Module 1–7)."""

    def __init__(
        self,
        datastore,
        run_coursework_action_fn: Callable[..., Any],
        run_multichain_pipeline_fn: Callable[..., Any],
    ):
        self.datastore = datastore
        self._run_coursework_action = run_coursework_action_fn
        self._run_multichain_pipeline = run_multichain_pipeline_fn

    def start(self, module: str, action: str, params: dict) -> str:
        job_id = str(uuid.uuid4())
        self.datastore.create_coursework_job(job_id, module, action, params or {})
        thread = threading.Thread(
            target=self._run,
            args=(job_id, module, action, params or {}),
            daemon=True,
        )
        thread.start()
        return job_id

    def _run(self, job_id: str, module: str, action: str, params: dict):
        try:
            self.datastore.update_coursework_job(job_id, status="running", progress=1, message="Starting")
            if module == "pipeline" and action == "multichain":
                result, log_path = self._run_multichain_pipeline(job_id=job_id, params=params)
            else:
                result, log_path = self._run_coursework_action(module=module, action=action, params=params)
            self.datastore.update_coursework_job(
                job_id,
                status="completed",
                progress=100,
                message="Completed",
                log_path=log_path or "",
                result=result,
            )
        except Exception as exc:
            self.datastore.update_coursework_job(
                job_id,
                status="failed",
                progress=100,
                message="Failed",
                error=str(exc),
            )
