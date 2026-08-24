import threading

from . import repository
from .scanner import ScanStopped, scan_two_pass


class ScanCoordinator:
    def __init__(self, publish):
        self.publish = publish
        self.stops: dict[str, threading.Event] = {}
        self.lock = threading.Lock()

    def start(self, session):
        session_id = session["id"]
        stop = threading.Event()
        with self.lock: self.stops[session_id] = stop
        thread = threading.Thread(target=self._run, args=(session, stop), daemon=True, name=f"scan-{session_id}")
        thread.start()

    def stop(self, session_id):
        with self.lock: event = self.stops.get(session_id)
        if event: event.set()
        session = repository.get_session(session_id)
        if not session: return None
        if session["status"] != "RUNNING": return session
        result = repository.finish_session(session_id, "STOPPED", session["devices_found"])
        self.publish("SESSION_STOPPED", result)
        return result

    def _run(self, session, stop):
        session_id = session["id"]
        try:
            hosts = scan_two_pass(session["subnet"], stop)
            if stop.is_set(): return
            repository.store_scan_results(session_id, session["subnet"], hosts)
            result = repository.finish_session(session_id, "COMPLETED", len(hosts))
            self.publish("SESSION_COMPLETED", result)
        except ScanStopped:
            if repository.get_session(session_id)["status"] == "RUNNING":
                result = repository.finish_session(session_id, "STOPPED")
                self.publish("SESSION_STOPPED", result)
        except Exception as exc:
            result = repository.finish_session(session_id, "FAILED", error=str(exc)[:1000])
            self.publish("SESSION_FAILED", result)
        finally:
            with self.lock: self.stops.pop(session_id, None)
