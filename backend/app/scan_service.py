import logging
import threading
import time

from concurrent.futures import ThreadPoolExecutor

from . import repository, snmp, mdns, dhcp
from .config import settings
from .database import connection
from .identification import IdentificationAccumulator
from .scanner import HostObservation, ScanStopped, discover_hosts, fingerprint_hosts, is_local_target, run_exposure_checks
from .nvd import coordinator as nvd_coordinator

log = logging.getLogger("secureops.scan")


class ScanAlreadyRunning(Exception):
    """Raised when a scan is started while another is still in progress."""

    def __init__(self, running_session_id: str):
        super().__init__("A scan is already running")
        self.running_session_id = running_session_id


class _PhaseTimer:
    """Records wall-clock time per named scan phase so a slow scan can be
    attributed to a stage instead of guessed at. Logging is the only cost."""

    def __init__(self, session_id: str, on_progress=None):
        self.session_id = session_id
        self.on_progress = on_progress
        self.marks: list[tuple[str, float]] = [("start", time.monotonic())]
        self.counts: dict[str, int] = {}

    def count(self, key: str, amount: int = 1) -> None:
        self.counts[key] = self.counts.get(key, 0) + amount

    def lap(self, name: str) -> float:
        now = time.monotonic()
        elapsed = now - self.marks[-1][1]
        self.marks.append((name, now))
        if self.on_progress:
            # Feeds the staleness check: a scan that is still advancing keeps
            # its slot, one that has genuinely stopped loses it.
            self.on_progress()
        # Logged immediately rather than only in report(), so a scan that
        # hangs inside a phase still shows how far it got.
        log.info("    phase %-30s %7.2fs (elapsed %.2fs)", name, elapsed, now - self.marks[0][1])
        return elapsed

    def report(self, outcome: str) -> str:
        total = time.monotonic() - self.marks[0][1]
        log.info("scan %s in %.2fs%s", outcome, total,
                 (" " + ", ".join(f"{k}={v}" for k, v in self.counts.items())) if self.counts else "")
        for (prev_name, _prev_at), (name, at) in zip(self.marks, self.marks[1:]):
            log.info("    phase %-30s %7.2fs", name, at - _prev_at)
        return f"scan {outcome} in {total:.2f}s"


def _store_snmp_arp(router_ip: str, arp_entries: dict[str, str]):
    if not arp_entries:
        return
    try:
        with connection() as conn:
            for ip, mac in arp_entries.items():
                conn.execute("""
                    INSERT INTO snmp_mac_ip_observations(ip_address, mac_address, learned_from_ip, last_seen)
                    VALUES (%s, %s, %s, now())
                    ON CONFLICT (ip_address, mac_address, learned_from_ip)
                    DO UPDATE SET last_seen = now()
                """, (ip, mac, router_ip))
    except Exception:
        pass


def _verify_snmp_arp_hosts(hosts: list[HostObservation], stop: threading.Event):
    """Actively verify snmp_arp_only hosts with a quick TCP SYN probe.
    Marks hosts that don't respond as 'not confirmed live' so stale ARP
    entries don't appear current in the UI."""
    snmp_hosts = [h for h in hosts if h.discovery_sources == ["snmp_arp"]]
    if not snmp_hosts:
        return
    
    log.info("Verifying %d snmp_arp_only hosts with active probe", len(snmp_hosts))
    
    # Common ports that typically respond with SYN/ACK or RST
    verify_ports = [22, 80, 443, 445, 3389]
    
    import socket
    def check_host(host: HostObservation):
        if stop.is_set():
            return
        alive = False
        for port in verify_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                result = sock.connect_ex((host.ip_address, port))
                sock.close()
                if result == 0:
                    alive = True
                    break
            except Exception:
                pass
        if not alive:
            host.discovery_sources.append("not_confirmed_live")
            log.info("snmp_arp_only host %s did not respond to active probe", host.ip_address)
        else:
            host.discovery_sources.append("active_verified")
            log.info("snmp_arp_only host %s confirmed live via active probe", host.ip_address)
    
    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(check_host, snmp_hosts))


def _identify_hosts(hosts: list[HostObservation], stop: threading.Event, timer: "_PhaseTimer | None" = None):
    """Enrich hosts with authoritative sources (SNMP, DHCP, mDNS) alongside Nmap."""
    if not hosts:
        return
    dhcp_started = time.monotonic()
    leases = dhcp.collect_leases()
    if timer:
        timer.lap(f"dhcp_leases({len(leases)})")
        timer.count("hosts", len(hosts))

    def process_host(host: HostObservation):
        if stop.is_set():
            return
        accum = IdentificationAccumulator()
        # SNMP and mDNS are independent lookups against unrelated transports, so
        # they run concurrently. Doing them one after the other made every host
        # cost the sum of both timeouts even though either could answer alone.
        snmp_box: dict = {}
        snmp_thread = threading.Thread(
            target=lambda: snmp_box.__setitem__("result", snmp.collect_identity(host.ip_address)),
            daemon=True,
        )
        snmp_thread.start()

        # 1. Authoritative DHCP lease (client-reported)
        lease_info = leases.get(host.ip_address)
        if lease_info and lease_info.get("hostname"):
            accum.add("dhcp_lease", hostname=lease_info["hostname"])

        # 3. mDNS (.local) query for Apple/IoT/non-Windows devices.
        # Multicast DNS is confined to the local broadcast domain, so on a
        # remote network it cannot answer and only burns its timeout.
        remote = not is_local_target(host.ip_address)
        if not remote:
            mdns_name = mdns.resolve_hostname(host.ip_address)
            if mdns_name:
                accum.add("mdns", hostname=mdns_name)

        # 2. Authoritative SNMP MIB query (vendor-supplied sysDescr/sysName/sysObjectID)
        snmp_thread.join(timeout=settings.snmp_timeout_seconds * 4)
        snmp_data = snmp_box.get("result")
        if snmp_data:
            accum.add(
                "snmp",
                hostname=snmp_data.get("sys_name"),
                vendor=snmp_data.get("vendor"),
                os_family=snmp_data.get("os_family"),
                device_type=snmp_data.get("device_type"),
            )
            # sysServices is a raw signal, not a merged field, but it must
            # survive into stored provenance so a later reclassification of
            # this asset can still use it.
            accum.add_signal("sys_services", snmp_data.get("sys_services"), "snmp")
            # Requirement 2: Cross-segment MAC/vendor visibility via SNMP ARP tables
            dtype = snmp_data.get("device_type")
            sdescr = snmp_data.get("sys_descr") or ""
            if dtype in {"router", "switch", "network device"} or "switch" in sdescr.lower():
                arp_table = snmp.collect_arp_table(host.ip_address)
                if arp_table:
                    _store_snmp_arp(host.ip_address, arp_table)

        # 4. Nmap-inferred fallback values (always registered as nmap_heuristic)
        accum.add(
            "nmap_heuristic",
            hostname=host.hostname,
            vendor=host.vendor,
            os_family=host.os_family,
            device_type=host.device_type if host.device_type != "unknown" else None,
        )

        # Apply winning values per field
        merged = accum.merged()
        if merged.get("hostname"):
            host.hostname = merged["hostname"]
            host.hostname_source = accum.winning_source("hostname")
        elif remote:
            # Say *why* an off-subnet device has no name. NetBIOS and mDNS were
            # deliberately skipped because they cannot cross a router, so this
            # is a network limitation rather than a scanning failure.
            host.hostname_unresolved_reason = (
                "No hostname: this device is on a remote network, so NetBIOS and "
                "mDNS were skipped (both are local-broadcast only) and neither "
                "reverse DNS nor SNMP returned a name."
            )
        if merged.get("vendor"):
            host.vendor = merged["vendor"]
            host.vendor_source = accum.winning_source("vendor")
        if merged.get("os_family"):
            host.os_family = merged["os_family"]
            host.os_source = accum.winning_source("os_family")
            if host.os_source == "snmp":
                host.os_confidence = 0.95  # authoritative vendor string
        if merged.get("device_type"):
            host.device_type = merged["device_type"]
            host.device_type_source = accum.winning_source("device_type")

        host.identification_provenance = accum.provenance()

    with ThreadPoolExecutor(max_workers=min(16, len(hosts))) as pool:
        list(pool.map(process_host, hosts))


class _ActiveScan:
    """An in-flight scan, with enough state to detect that it has died.

    A bare stop-event was not enough: if the worker thread wedged, was killed,
    or failed to start, the entry survived with no way to tell a live scan from
    a dead one, and every later scan was refused as "already running".
    """

    __slots__ = ("event", "thread", "started_at", "last_progress_at")

    def __init__(self):
        self.event = threading.Event()
        self.thread: threading.Thread | None = None
        self.started_at = time.monotonic()
        self.last_progress_at = self.started_at

    def touch(self) -> None:
        self.last_progress_at = time.monotonic()

    @property
    def idle_seconds(self) -> float:
        return time.monotonic() - self.last_progress_at

    @property
    def thread_alive(self) -> bool:
        return bool(self.thread and self.thread.is_alive())


class ScanCoordinator:
    # Comfortably above the per-nmap timeout, so a scan that is still making
    # real progress is never reaped out from under itself.
    STALE_GRACE_SECONDS = 120

    def __init__(self, publish):
        self.publish = publish
        self.stops: dict[str, _ActiveScan] = {}
        self.lock = threading.Lock()
        self._sweeper: threading.Thread | None = None
        self._sweeper_stop: threading.Event | None = None

    @property
    def stale_after_seconds(self) -> float:
        return settings.scan_timeout_seconds + self.STALE_GRACE_SECONDS

    def running_session_id(self):
        with self.lock:
            return next(iter(self.stops), None)

    def _reap_stale_locked(self) -> None:
        """Drop in-memory entries that can no longer be live.

        Called with the lock held, before admitting a new scan.
        """
        limit = self.stale_after_seconds
        for session_id, active in list(self.stops.items()):
            dead_thread = active.thread is not None and not active.thread.is_alive()
            if active.idle_seconds <= limit and not dead_thread:
                continue
            reason = (
                "its worker thread is gone"
                if dead_thread
                else f"it made no progress for {int(active.idle_seconds)}s "
                     f"(limit {int(limit)}s)"
            )
            log.warning("clearing stuck scan %s: %s", session_id, reason)
            self.stops.pop(session_id, None)
            try:
                session = repository.get_session(session_id)
                if session and session["status"] == "RUNNING":
                    self.publish("SESSION_FAILED", repository.finish_session(
                        session_id, "FAILED", session["devices_found"],
                        f"Scan was stuck: {reason}. It has been cleared so a new "
                        f"scan can start."))
            except Exception:
                log.exception("could not close out stuck scan %s", session_id)

    def _reap_stale_database_only(self) -> None:
        """Fail RUNNING rows that no live in-memory thread owns.

        The database is the durable record the dashboard reads, so it can hold a
        RUNNING row with no thread behind it (for example when the backend was
        killed and restarted between the thread dying and startup cleanup).
        """
        try:
            stale = repository.find_stale_running_sessions(self.stale_after_seconds)
        except Exception:
            return
        with self.lock:
            live = set(self.stops)
        for session in stale:
            if session["id"] in live:
                continue
            log.warning("clearing orphaned RUNNING session %s (no live thread)", session["id"])
            try:
                self.publish("SESSION_FAILED", repository.finish_session(
                    session["id"], "FAILED", session["devices_found"],
                    "Scan was left running by a backend restart and had no live "
                    "worker. It has been cleared so a new scan can start."))
            except Exception:
                log.exception("could not close out orphaned session %s", session["id"])

    def reap_stale(self) -> list[str]:
        """Public entry point: clear anything that is not genuinely running."""
        self._reap_stale_database_only()
        with self.lock:
            before = len(self.stops)
            self._reap_stale_locked()
            cleared = before - len(self.stops)
        return [f"{cleared} in-memory"]

    def start(self, session):
        session_id = session["id"]
        active = _ActiveScan()
        self._reap_stale_database_only()
        with self.lock:
            # Nmap work is CPU-bound and each scan already runs several nmap
            # processes in parallel. A second overlapping scan starves the first
            # past the per-command timeout, which is what produced spurious
            # "Nmap exceeded the 180-second scan timeout" failures.
            self._reap_stale_locked()
            if self.stops:
                raise ScanAlreadyRunning(next(iter(self.stops)))
            self.stops[session_id] = active
        try:
            thread = threading.Thread(
                target=self._run, args=(session, active.event, active),
                daemon=True, name=f"scan-{session_id}")
            active.thread = thread
            thread.start()
        except BaseException:
            # A thread that never started would otherwise leave the entry
            # behind and refuse every future scan with no way to recover.
            with self.lock: self.stops.pop(session_id, None)
            try:
                repository.finish_session(
                    session_id, "FAILED", 0,
                    "The scan worker could not be started, so nothing ran.")
            except Exception:
                log.exception("could not close out session %s after thread start failed", session_id)
            raise

    def stop(self, session_id):
        with self.lock: active = self.stops.get(session_id)
        if active: active.event.set()
        session = repository.get_session(session_id)
        if not session: return None
        if session["status"] != "RUNNING": return session
        result = repository.finish_session(session_id, "STOPPED", session["devices_found"])
        self.publish("SESSION_STOPPED", result)
        return result

    def start_sweeper(self, interval_seconds: int = 30):
        """Periodically reap stale state so the UI self-corrects too.

        Without this, a stuck scan would keep the dashboard showing "Stop
        Session" until someone tried to start a new one.
        """
        if self._sweeper and self._sweeper.is_alive():
            return
        stop = threading.Event()
        self._sweeper_stop = stop

        def loop():
            while not stop.wait(interval_seconds):
                try:
                    self.reap_stale()
                except Exception:
                    log.exception("stale-scan sweep failed")

        self._sweeper = threading.Thread(target=loop, daemon=True, name="scan-sweeper")
        self._sweeper.start()

    def stop_sweeper(self):
        if getattr(self, "_sweeper_stop", None):
            self._sweeper_stop.set()

    def _run(self, session, stop, active):
        session_id = session["id"]
        timer = _PhaseTimer(session_id, on_progress=active.touch)
        
        # Track scan summary statistics
        scan_summary = {
            "hosts_by_probe": 0,
            "hosts_from_arp": 0,
            "hosts_from_infrastructure": 0,
            "hosts_excluded": 0,
            "excluded_reasons": [],
        }
        
        try:
            # A cross-network session targets a VLAN's subnet reached through a
            # router, so ARP discovery would return nothing. Everything after
            # discovery - fingerprinting, identification, enrichment, findings -
            # is the same code path a local scan uses.
            is_cross_network = session.get("source") == "cross_network" or bool(session.get("network_id"))
            
            # Get infrastructure hosts for this network (known router/switch IPs)
            infrastructure_hosts = []
            if is_cross_network and session.get("network_id"):
                network = repository.get_network(session["network_id"])
                if network and network.get("sources"):
                    for src in network["sources"]:
                        if src.get("device_ip"):
                            infrastructure_hosts.append(src["device_ip"])
            
            hosts = discover_hosts(session["subnet"], stop, remote=is_cross_network or None, 
                                   include_infrastructure=infrastructure_hosts)
            
            # Count initial probe discoveries
            scan_summary["hosts_by_probe"] = len(hosts)
            
            # For cross-network scans, supplement nmap discovery with SNMP ARP data.
            # The gateway router/switch's ARP table knows which IPs have active MACs
            # even if those hosts don't respond to nmap probes (firewall blocks).
            if is_cross_network:
                snmp_arp = repository.get_snmp_arp_entries_for_subnet(session["subnet"])
                log.info("cross-network scan: SNMP ARP table has %d entries for %s", len(snmp_arp), session["subnet"])
                
                # Deduplicate by MAC address - SNMP ARP may have same MAC for multiple IPs
                # (stale entries, device moved subnets). Keep one entry per MAC.
                seen_macs = set()
                deduped_arp = {}
                for ip, mac in snmp_arp.items():
                    if mac and mac not in seen_macs:
                        seen_macs.add(mac)
                        deduped_arp[ip] = mac
                    elif mac:
                        log.info("cross-network scan: skipping duplicate MAC %s for IP %s", mac, ip)
                
                nmap_ips = {h.ip_address for h in hosts}
                for ip, mac in deduped_arp.items():
                    if ip not in nmap_ips:
                        log.info("cross-network scan: adding host from SNMP ARP: %s (%s)", ip, mac)
                        hosts.append(HostObservation(
                            ip_address=ip,
                            mac_address=mac,
                            vendor=None,
                            hostname=None,
                            device_type="unknown",
                            discovery_sources=["snmp_arp"],
                        ))
                        scan_summary["hosts_from_arp"] += 1
            
            # Count infrastructure hosts that were added
            for h in hosts:
                if h.discovery_sources == ["infrastructure"]:
                    scan_summary["hosts_from_infrastructure"] += 1
            
            # For cross-network scans, actively verify snmp_arp_only hosts.
            # This distinguishes live hosts from stale ARP entries.
            if is_cross_network:
                _verify_snmp_arp_hosts(hosts, stop)
            
            timer.lap(f"nmap_discovery({len(hosts)} hosts)")
            if stop.is_set(): return
            repository.store_scan_results(session_id, session["subnet"], hosts, record_activity=True, network_id=session.get("network_id"))
            timer.lap("store_discovered")
            
            # Add scan summary to session activity
            self.publish("SESSION_TICK", {"id": session_id, "phase": "discovered", "devices_found": len(hosts), "scan_summary": scan_summary})
            
            fingerprint_hosts(hosts, stop)
            timer.lap(f"nmap_fingerprint({len(hosts)} hosts)")
            if stop.is_set(): return
            _identify_hosts(hosts, stop, timer)
            timer.lap("identify_snmp_mdns")
            if stop.is_set(): return
            repository.store_scan_results(session_id, session["subnet"], hosts, record_activity=False, network_id=session.get("network_id"))
            timer.lap("store_identified")
            self.publish("SESSION_TICK", {"id": session_id, "phase": "fingerprinted", "devices_found": len(hosts)})
            try:
                run_exposure_checks(hosts, stop)
                timer.lap("exposure_checks")
                if stop.is_set(): return
                created = repository.store_exposure_results(session_id, hosts)
                timer.lap("store_exposure")
                self.publish("SESSION_TICK", {"id": session_id, "phase": "exposure_checked", "findings_created": created})
            except ScanStopped:
                raise
            except Exception as exc:
                repository.add_activity(session_id, "EXPOSURE_CHECKS_FAILED", "Exposure checks could not complete", str(exc)[:1000])
            
            # Store scan summary in database
            repository.store_scan_summary(session_id, scan_summary)
            
            result = repository.finish_session(session_id, "COMPLETED", len(hosts))
            # Update network's last_scanned_at for manual scans (no network_id)
            session = repository.get_session(session_id)
            if session and not session.get("network_id") and session.get("subnet"):
                repository.mark_network_scanned_by_cidr(session["subnet"])
            
            service_ids = [service.service_id for host in hosts for service in host.services if service.service_id and service.cpe]
            enrichment_job = nvd_coordinator.schedule(session_id, "scan", service_ids)
            repository.add_activity(session_id, "NVD_ENRICHMENT_QUEUED", "NVD enrichment queued", f"Job {enrichment_job} · {len(service_ids)} CPE-bearing service(s)")
            self.publish("SESSION_COMPLETED", result)
            timer.report("COMPLETED")
        except ScanStopped:
            if repository.get_session(session_id)["status"] == "RUNNING":
                result = repository.finish_session(session_id, "STOPPED")
                self.publish("SESSION_STOPPED", result)
            timer.report("STOPPED")
        except Exception as exc:
            result = repository.finish_session(session_id, "FAILED", error=str(exc)[:1000])
            self.publish("SESSION_FAILED", result)
            timer.report("FAILED")
        finally:
            with self.lock: self.stops.pop(session_id, None)
