import unittest
from app import identification, dhcp, mdns, snmp
from app.identification import (
    IdentificationAccumulator,
    FieldValue,
    merge_field,
    source_rank,
    confidence_for,
    enterprise_vendor,
    parse_sysdescr,
    derive_device_type,
    classify_device,
    hostname_role_hint,
    network_os_role,
    sys_services_role,
)


class TestEnterpriseVendorLookup(unittest.TestCase):
    def test_known_enterprise_numbers(self):
        self.assertEqual(enterprise_vendor("1.3.6.1.4.1.9.1.123"), "Cisco")
        self.assertEqual(enterprise_vendor(".1.3.6.1.4.1.63.1"), "Apple")
        self.assertEqual(enterprise_vendor("1.3.6.1.4.1.311.1.1"), "Microsoft")
        self.assertEqual(enterprise_vendor("1.3.6.1.4.1.674.10892"), "Dell")
        self.assertEqual(enterprise_vendor("1.3.6.1.4.1.2636.1"), "Juniper Networks")
        self.assertEqual(enterprise_vendor("1.3.6.1.4.1.8072.3.2.10"), "net-snmp (Linux/BSD)")

    def test_unknown_or_malformed_enterprise_numbers(self):
        # Unknown PEN should yield None (honest unknown), never a fabricated vendor
        self.assertIsNone(enterprise_vendor("1.3.6.1.4.1.99999999.1"))
        self.assertIsNone(enterprise_vendor("1.3.6.1.2.1.1.1.0"))  # MIB-2, not enterprise
        self.assertIsNone(enterprise_vendor(None))
        self.assertIsNone(enterprise_vendor(""))


class TestSysDescrParser(unittest.TestCase):
    def test_os_family_extraction(self):
        self.assertEqual(
            parse_sysdescr("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE"),
            "Cisco IOS",
        )
        self.assertEqual(
            parse_sysdescr("Juniper Networks, Inc. ex4200-48t internet router, kernel JUNOS 12.3R12.4"),
            "Juniper Junos",
        )
        self.assertEqual(
            parse_sysdescr("Hardware: Intel64 Family 6 Model 94 Stepping 3 - Software: Windows Version 10.0"),
            "Windows",
        )
        self.assertEqual(
            parse_sysdescr("Linux router 5.15.0-76-generic #83-Ubuntu SMP x86_64"),
            "Ubuntu Linux",
        )
        self.assertEqual(
            parse_sysdescr("HP LaserJet Pro M404dn; Firmware 20200612"),
            "HP printer firmware",
        )

    def test_unknown_sysdescr_returns_none(self):
        self.assertIsNone(parse_sysdescr("Some custom appliance v1.0"))
        self.assertIsNone(parse_sysdescr(None))


class TestDeviceTypeDerivation(unittest.TestCase):
    def test_device_types(self):
        self.assertEqual(derive_device_type("Cisco Catalyst 3850 Switch"), "switch")
        self.assertEqual(derive_device_type("HP LaserJet Enterprise"), "printer")
        self.assertEqual(derive_device_type("Apple iPhone 14 Pro"), "phone")
        self.assertEqual(derive_device_type("Dell PowerEdge R740 Server"), "server")
        self.assertEqual(derive_device_type("Windows 11 Workstation Desktop"), "PC")

    def test_unknown_returns_none(self):
        self.assertIsNone(derive_device_type("Generic Device"))
        self.assertIsNone(derive_device_type(None))


class TestNetworkOsSignatures(unittest.TestCase):
    def test_infrastructure_families_are_recognized(self):
        for os_family, expected in [
            ("Cisco IOS-XE", None), ("Cisco IOS", None), ("Cisco NX-OS", "switch"),
            ("Juniper Junos", "router"), ("RouterOS", "router"),
            ("ArubaOS", "switch"), ("FortiOS", "router"), ("PAN-OS", "router"),
            ("VyOS", "router"),
        ]:
            role, matched = network_os_role(os_family)
            self.assertTrue(matched, os_family)
            self.assertEqual(role, expected, os_family)

    def test_hostname_prefix_hints(self):
        self.assertEqual(hostname_role_hint("SW-NTECHCENTRAL"), "switch")
        self.assertEqual(hostname_role_hint("SWITCH-CORE-01"), "switch")
        self.assertEqual(hostname_role_hint("RTR-EDGE-01"), "router")
        self.assertEqual(hostname_role_hint("ROUTER-BR-1"), "router")
        self.assertEqual(hostname_role_hint("FW-PERIMETER"), "router")
        self.assertEqual(hostname_role_hint("AP-LOBBY-2"), "network device")
        self.assertIsNone(hostname_role_hint("marketing-pc"))
        self.assertIsNone(hostname_role_hint(None))
        # A prefix only counts at the start of the label, never mid-name
        self.assertIsNone(hostname_role_hint("apartment-mgr"))

    def test_sys_services_layers(self):
        # Catalyst 2960: physical + internet + datalink + internetworking
        self.assertEqual(sys_services_role(78), "switch")
        # Routing device that also offers host-level services
        self.assertEqual(sys_services_role(206), "router")
        # No internetworking layer: the bitmask says nothing about the role
        self.assertIsNone(sys_services_role(6))
        self.assertIsNone(sys_services_role(None))


class TestDeviceClassification(unittest.TestCase):
    def test_cisco_ios_with_ssh_and_https_is_not_a_server(self):
        # The reported misclassification: Cisco IOS firmware behind open
        # management ports was typed "server" by the port heuristic alone.
        result = classify_device(
            os_family="Cisco IOS",
            vendor="Cisco",
            hostname="SW-NTECHCENTRAL",
            service_names=["ssh", "https", "http"],
        )
        self.assertEqual(result.device_type, "switch")
        self.assertNotEqual(result.device_type, "server")
        self.assertEqual(result.source, "os_signature")

    def test_ports_never_outrank_an_os_signature(self):
        for os_family, expected in [
            ("Cisco NX-OS", "switch"), ("Juniper Junos", "router"),
            ("RouterOS", "router"), ("FortiOS", "router"), ("ArubaOS", "switch"),
        ]:
            result = classify_device(
                os_family=os_family,
                service_names=["ssh", "https", "mysql"],
            )
            self.assertEqual(result.device_type, expected)

    def test_ambiguous_network_os_without_refinement_stays_generic(self):
        result = classify_device(os_family="Cisco IOS", service_names=["ssh", "https"])
        self.assertEqual(result.device_type, "network device")

    def test_sys_services_breaks_a_router_switch_tie(self):
        result = classify_device(os_family="Cisco IOS", sys_services=78)
        self.assertEqual(result.device_type, "switch")

    def test_sys_services_is_ignored_for_general_purpose_hosts(self):
        # 206 is the internetworking bit every Linux host with ip_forward on
        # reports; it must not turn a server into a router.
        result = classify_device(
            os_family="Ubuntu Linux", sys_services=206,
            service_names=["ssh", "https"],
        )
        self.assertEqual(result.device_type, "server")

    def test_model_string_breaks_a_router_switch_tie(self):
        result = classify_device(
            os_family="Cisco IOS",
            sys_descr="Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE",
        )
        self.assertEqual(result.device_type, "switch")

    def test_hostname_is_secondary_to_a_clear_os_match(self):
        result = classify_device(os_family="Windows", hostname="RTR-TEST-PC",
                                 service_names=["rdp"])
        self.assertEqual(result.device_type, "PC")

    def test_hostname_only_raises_confidence(self):
        result = classify_device(hostname="RTR-BR-1", service_names=["ssh"])
        self.assertEqual(result.device_type, "router")
        self.assertEqual(result.source, "hostname_hint")

    def test_port_heuristic_is_only_a_fallback(self):
        self.assertEqual(
            classify_device(service_names=["ssh", "https"]).device_type, "server")
        self.assertEqual(
            classify_device(service_names=["ssh", "https"]).source, "service_heuristic")
        self.assertEqual(classify_device().device_type, "unknown")

    def test_printer_and_phone_text_still_wins_over_ports(self):
        self.assertEqual(classify_device(os_family="HP printer firmware").device_type, "printer")
        self.assertEqual(
            classify_device(sys_descr="Apple iPhone 14 Pro", service_names=["ssh"]).device_type,
            "phone",
        )

    def test_known_os_beats_a_stale_workstation_hostname(self):
        # A Proxmox hypervisor still named DESKTOP-* is a server.
        result = classify_device(os_family="Linux", hostname="DESKTOP-K6NQQ0K",
                                 service_names=["ssh", "https"])
        self.assertEqual(result.device_type, "server")
        self.assertEqual(
            classify_device(os_family="Proxmox VE", hostname="DESKTOP-K6NQQ0K").device_type,
            "server",
        )
        self.assertEqual(classify_device(os_family="macOS").device_type, "PC")
        self.assertEqual(classify_device(os_family="Android").device_type, "phone")


class TestSignalsProvenance(unittest.TestCase):
    def test_sys_services_survives_into_provenance(self):
        accum = IdentificationAccumulator()
        accum.add("snmp", os_family="Cisco IOS", vendor="Cisco")
        accum.add_signal("sys_services", 78, "snmp")
        prov = accum.provenance()
        self.assertEqual(prov["signals"]["sys_services"]["value"], 78)
        self.assertEqual(prov["signals"]["sys_services"]["source"], "snmp")

    def test_empty_signal_is_not_stored(self):
        accum = IdentificationAccumulator()
        accum.add_signal("sys_services", None, "snmp")
        self.assertNotIn("signals", accum.provenance())


class TestConfidenceAndPriorityMerging(unittest.TestCase):
    def test_source_ranks(self):
        # Authoritative sources must rank higher (lower rank integer) than inferred ones
        self.assertLess(source_rank("dhcp_lease"), source_rank("reverse_dns"))
        self.assertLess(source_rank("snmp"), source_rank("nmap_heuristic"))
        self.assertLess(source_rank("mdns"), source_rank("nmap_heuristic"))
        # A vendor OS signature outranks generic side-signal guesses
        self.assertLess(source_rank("snmp"), source_rank("os_signature"))
        self.assertLess(source_rank("os_signature"), source_rank("nmap_heuristic"))

    def test_authoritative_source_overrides_heuristic(self):
        candidates = [
            FieldValue("inferred-host", "nmap_heuristic"),
            FieldValue("authoritative-host", "dhcp_lease"),
        ]
        winner = merge_field(candidates)
        self.assertIsNotNone(winner)
        self.assertEqual(winner.value, "authoritative-host")
        self.assertEqual(winner.source, "dhcp_lease")
        self.assertEqual(winner.confidence, "high")

    def test_snmp_overrides_nmap_heuristic_for_vendor(self):
        candidates = [
            FieldValue("Hon Hai Precision", "nmap_heuristic"),  # NIC board maker
            FieldValue("Cisco", "snmp"),                         # Real vendor via sysObjectID
        ]
        winner = merge_field(candidates)
        self.assertEqual(winner.value, "Cisco")
        self.assertEqual(winner.source, "snmp")

    def test_identification_accumulator(self):
        accum = IdentificationAccumulator()
        # Nmap registers low-confidence guess first
        accum.add("nmap_heuristic", hostname="ip-192-168-1-50", vendor="Intel", os_family="Linux")
        # DHCP registers client-reported hostname
        accum.add("dhcp_lease", hostname="marys-laptop")
        # SNMP registers sysDescr-derived OS
        accum.add("snmp", os_family="Ubuntu Linux", vendor="Dell")

        merged = accum.merged()
        self.assertEqual(merged["hostname"], "marys-laptop")
        self.assertEqual(accum.winning_source("hostname"), "dhcp_lease")
        self.assertEqual(merged["vendor"], "Dell")
        self.assertEqual(accum.winning_source("vendor"), "snmp")
        self.assertEqual(merged["os_family"], "Ubuntu Linux")
        self.assertEqual(accum.winning_source("os_family"), "snmp")

        prov = accum.provenance()
        self.assertIn("marys-laptop", prov["hostname"]["value"])
        self.assertEqual(prov["hostname"]["source"], "dhcp_lease")
        self.assertEqual(prov["hostname"]["confidence"], "high")


class TestDhcpLeaseParsing(unittest.TestCase):
    def test_parse_isc_leases(self):
        text = """
        lease 192.168.1.101 {
          starts 4 2026/09/25 10:00:00;
          ends 4 2026/09/25 18:00:00;
          hardware ethernet 00:11:22:33:44:55;
          client-hostname "marketing-pc";
        }
        lease 192.168.1.102 {
          starts 4 2026/09/25 10:00:00;
          client-hostname "printer-reception";
        }
        """
        leases = dhcp.parse_isc_leases(text)
        self.assertEqual(leases["192.168.1.101"]["hostname"], "marketing-pc")
        self.assertEqual(leases["192.168.1.102"]["hostname"], "printer-reception")

    def test_parse_windows_leases_csv(self):
        csv_text = "IP Address,Host Name,MAC Address\n192.168.1.105,finance-ws-1,00-11-22-33-44-66\n"
        leases = dhcp.parse_windows_leases(csv_text)
        self.assertEqual(leases["192.168.1.105"]["hostname"], "finance-ws-1")

    def test_parse_windows_leases_json(self):
        json_text = '[{"ip": "192.168.1.106", "hostname": "dev-box"}]'
        leases = dhcp.parse_windows_leases(json_text)
        self.assertEqual(leases["192.168.1.106"]["hostname"], "dev-box")


class TestMdnsPacketBuilding(unittest.TestCase):
    def test_ptr_query_structure(self):
        packet = mdns.build_ptr_query("192.168.1.50")
        self.assertIsInstance(packet, bytes)
        # 12-byte DNS header + encoded qname + 4 bytes qtype/qclass
        self.assertGreater(len(packet), 16)
        # Check that the reverse IP is present in the wire format
        self.assertIn(b"50", packet)
        self.assertIn(b"168", packet)
        self.assertIn(b"in-addr", packet)


class TestSnmpBerEncoding(unittest.TestCase):
    def test_encode_and_decode_oid(self):
        oid = (1, 3, 6, 1, 2, 1, 1, 1, 0)
        encoded = snmp._enc_oid(oid)
        self.assertEqual(encoded[0], 0x06)  # OID tag
        decoded = snmp._dec_oid(encoded[2:])
        self.assertEqual(decoded, oid)

    def test_build_get_request(self):
        req = snmp.build_request("public", [snmp.SYS_DESCR, snmp.SYS_OBJECT_ID])
        self.assertIsInstance(req, bytes)
        self.assertEqual(req[0], 0x30)  # SEQUENCE
        self.assertIn(b"public", req)


if __name__ == "__main__":
    unittest.main()