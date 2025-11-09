import logging
import threading

from .db import Database
from .scanner import analyze_headers, demo_snapshot, executed_checks, fetch_headers, ScanNetworkError
from .security import ScopeError

logger = logging.getLogger(__name__)


class Worker:
    def __init__(self, database: Database):
        self.database = database
        self.stop_event = threading.Event()
        self.wake_event = threading.Event()
        self.thread = threading.Thread(target=self.run, name="scopeforge-worker", daemon=True)

    @property
    def running(self):
        return self.thread.is_alive() and not self.stop_event.is_set()

    def start(self):
        self.database.recover_jobs()
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.wake_event.set()
        self.thread.join(timeout=16)

    def wake(self):
        self.wake_event.set()

    def _before_request(self, scan):
        while not self.stop_event.is_set():
            program = self.database.get_program(scan["program_id"])
            self.database.validate_scan(program, scan["target_url"], scan["mode"], scan.get("profile", "headers"))
            wait = self.database.request_gate(scan["id"], scan["program_id"])
            if wait <= 0:
                return
            # Short waits make cancellation and shutdown responsive even when
            # the configured request interval is one minute.
            self.stop_event.wait(min(wait, 0.25))
        raise ScanNetworkError("Worker stopped before the request could start.")

    def execute(self, scan):
        try:
            program = self.database.get_program(scan["program_id"])
            profile = scan.get("profile", "headers")
            target = self.database.validate_scan(program, scan["target_url"], scan["mode"], profile)
            # The default header profile retains compatibility with existing
            # transport integrations; body analysis is an explicit opt-in.
            profile_options = {"profile": profile} if profile == "web" else {}
            snapshot = demo_snapshot(**profile_options) if scan["mode"] == "demo" else fetch_headers(
                target,
                before_request=lambda: self._before_request(scan),
                before_send=lambda: self.database.before_send(scan),
                **profile_options,
            )
            observations = analyze_headers(target, snapshot)
            summary = {
                "analysis": "synthetic-response" if snapshot.synthetic else "single-response",
                "status_code": snapshot.status,
                "synthetic": snapshot.synthetic,
                "body_analyzed": snapshot.body_analyzed,
                "body_truncated": snapshot.body_truncated,
                "body_bytes": snapshot.metadata.get("body_bytes", 0),
                "body_skip_reason": snapshot.metadata.get("body_skip_reason"),
                "raw_body_retained": False,
            }
            self.database.finish_scan(scan, observations, executed_checks(profile, snapshot), summary)
        except (ScopeError, ScanNetworkError, ValueError) as error:
            self.database.fail_scan(scan["id"], str(error))
        except Exception:
            logger.exception("Local scan execution failed for %s", scan["id"])
            self.database.fail_scan(scan["id"], "The local worker encountered an internal error. See the local server log.")

    def run(self):
        while not self.stop_event.is_set():
            try:
                scan = self.database.claim_next()
                if scan is not None:
                    self.execute(scan)
                    continue
            except Exception:
                logger.exception("Local worker queue operation failed")
            self.wake_event.wait(0.25)
            self.wake_event.clear()
