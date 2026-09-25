import threading

from concurrent.futures import ThreadPoolExecutor

from . import repository, snmp, mdns, dhcp
from .database import connection
from .identification import IdentificationAccumulator
from .scanner import HostObservation, ScanStopped, discover_hosts, fingerprint_hosts, run_exposure_checks
from .nvd import coordinator as nvd_coordinator


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


def _identify_hosts(hosts: list[HostObservation], stop: threading.Event):
    """Enrich hosts with authoritative sources (SNMP, DHCP, mDNS) alongside Nmap."""
    if not hosts:
        return
    leases = dhcp.collect_leases()

    def process_host(host: HostObservation):
        if stop.is_set():
            return
        accum = IdentificationAccumulator()

        # 1. Authoritative DHCP lease (client-reported)
        lease_info = leases.get(host.ip_address)
        if lease_info and lease_info.get("hostname"):
            accum.add("dhcp_lease", hostname=lease_info["hostname"])

        # 2. Authoritative SNMP MIB query (vendor-supplied sysDescr/sysName/sysObjectID)
        snmp_data = snmp.collect_identity(host.ip_address)
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

        # 3. mDNS (.local) query for Apple/IoT/non-Windows devices
        mdns_name = mdns.resolve_hostname(host.ip_address)
        if mdns_name:
            accum.add("mdns", hostname=mdns_name)

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
            hosts = discover_hosts(session["subnet"], stop)
            if stop.is_set(): return
            repository.store_scan_results(session_id, session["subnet"], hosts)
            self.publish("SESSION_TICK", {"id": session_id, "phase": "discovered", "devices_found": len(hosts)})
            fingerprint_hosts(hosts, stop)
            if stop.is_set(): return
            _identify_hosts(hosts, stop)
            if stop.is_set(): return
            repository.store_scan_results(session_id, session["subnet"], hosts, record_activity=False)
            self.publish("SESSION_TICK", {"id": session_id, "phase": "fingerprinted", "devices_found": len(hosts)})
            try:
                run_exposure_checks(hosts, stop)
                if stop.is_set(): return
                created = repository.store_exposure_results(session_id, hosts)
                self.publish("SESSION_TICK", {"id": session_id, "phase": "exposure_checked", "findings_created": created})
            except ScanStopped:
                raise
            except Exception as exc:
                repository.add_activity(session_id, "EXPOSURE_CHECKS_FAILED", "Exposure checks could not complete", str(exc)[:1000])
            result = repository.finish_session(session_id, "COMPLETED", len(hosts))
            service_ids = [service.service_id for host in hosts for service in host.services if service.service_id and service.cpe]
            enrichment_job = nvd_coordinator.schedule(session_id, "scan", service_ids)
            repository.add_activity(session_id, "NVD_ENRICHMENT_QUEUED", "NVD enrichment queued", f"Job {enrichment_job} · {len(service_ids)} CPE-bearing service(s)")
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
