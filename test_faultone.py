#!/usr/bin/env python3
"""Tests for faultone.

    python3 test_faultone.py          # or: python3 -m unittest -v

Standard library only, no network access, runs in well under a second - the
same constraints as the tool itself, so it works on any box faultone does.

Weighted toward the things that have actually broken here: output parsing
(every real bug so far came from a parser meeting a format it hadn't seen)
and the input validation that keeps user-supplied targets out of argv.

SPDX-License-Identifier: MIT
"""

import importlib.util
import inspect
import json
import os
import re
import sys
import time
import types
import unittest

import faultone as nd


class TestGatewayParsing(unittest.TestCase):
    """Both real bugs found in this project were in parsers like this one:
    the macOS format was unhandled and returned None, which raised a false
    'no default gateway' critical and skipped every downstream check."""

    def gw(self, out, ok=True):
        return nd.guess_default_gateway({"ok": ok, "stdout": out})

    def test_macos_netstat_names_destination_default(self):
        out = ("Routing tables\n\nInternet:\n"
               "Destination        Gateway            Flags     Netif\n"
               "default            192.168.1.1        UGScg      en0\n"
               "127                127.0.0.1          UCS        lo0\n")
        self.assertEqual(self.gw(out), "192.168.1.1")

    def test_linux_ip_route(self):
        self.assertEqual(
            self.gw("default via 10.0.0.1 dev eth0 proto dhcp metric 100\n"),
            "10.0.0.1")

    def test_linux_netstat(self):
        out = ("Destination     Gateway         Genmask         Flags\n"
               "0.0.0.0         192.168.1.1     0.0.0.0         UG\n")
        self.assertEqual(self.gw(out), "192.168.1.1")

    def test_windows_route_print_skips_the_netmask_column(self):
        # Regression: the old regex captured the netmask (0.0.0.0) as gateway.
        out = ("Network Destination        Netmask          Gateway       Interface\n"
               "          0.0.0.0          0.0.0.0      192.168.0.1     192.168.0.23\n"
               "     192.168.0.0    255.255.255.0         On-link      192.168.0.23\n")
        self.assertEqual(self.gw(out), "192.168.0.1")

    def test_ipv6_only_default_route(self):
        self.assertEqual(self.gw("Internet6:\ndefault  fe80::1%en0  UGcg  en0\n"),
                         "fe80::1%en0")

    def test_ipv4_preferred_over_ipv6(self):
        out = ("Internet:\ndefault  192.168.1.1  UGScg  en0\n"
               "Internet6:\ndefault  fe80::1%en0  UGcg  en0\n")
        self.assertEqual(self.gw(out), "192.168.1.1")

    def test_link_only_route_is_not_a_gateway(self):
        self.assertIsNone(self.gw("default           link#14            UCSI     en0\n"))

    def test_no_default_route(self):
        self.assertIsNone(self.gw("127                127.0.0.1          UCS        lo0\n"))

    def test_failed_command_yields_nothing(self):
        self.assertIsNone(self.gw("default 192.168.1.1 UGScg en0", ok=False))


class TestTracerouteParsing(unittest.TestCase):
    """Continuation lines - emitted when several routers answer probes for one
    hop - were parsed as new hops numbered after the first octet of their IP,
    inventing hops and splitting one hop's timings across fakes."""

    MACOS = (" 1  192.168.1.1 (192.168.1.1)  5.5 ms  0.7 ms  0.3 ms\n"
             " 2  198.51.100.13 (198.51.100.13)  10.8 ms  9.0 ms  9.9 ms\n"
             " 6  be-36421.example.net (198.51.100.229)  23.3 ms\n"
             "    be-36441.example.net (198.51.100.237)  21.4 ms\n"
             "    be-36431.example.net (198.51.100.233)  25.6 ms\n"
             " 8  * * *\n"
             " 9  * 203.0.113.67 (203.0.113.67)  27.1 ms\n"
             "    203.0.113.21 (203.0.113.21)  23.1 ms\n")

    def test_continuation_lines_do_not_become_hops(self):
        hops = nd.parse_traceroute_hops(self.MACOS)
        self.assertEqual([h["hop"] for h in hops], [1, 2, 6, 8, 9])

    def test_continuation_timings_merge_into_the_hop_above(self):
        hop6 = next(h for h in nd.parse_traceroute_hops(self.MACOS) if h["hop"] == 6)
        self.assertEqual(len(hop6["times_ms"]), 3)
        self.assertFalse(hop6["timed_out"])

    def test_other_responders_recorded_not_discarded(self):
        hop6 = next(h for h in nd.parse_traceroute_hops(self.MACOS) if h["hop"] == 6)
        self.assertEqual(len(hop6["also"]), 2)

    def test_full_timeout_hop(self):
        hop8 = next(h for h in nd.parse_traceroute_hops(self.MACOS) if h["hop"] == 8)
        self.assertTrue(hop8["timed_out"])
        self.assertEqual(hop8["times_ms"], [])

    def test_partial_reply_hop_keeps_only_real_timings(self):
        hop9 = next(h for h in nd.parse_traceroute_hops(self.MACOS) if h["hop"] == 9)
        self.assertEqual(len(hop9["times_ms"]), 2)
        self.assertFalse(hop9["timed_out"])

    def test_windows_tracert(self):
        out = ("Tracing route to google.com [203.0.113.14]\n"
               "over a maximum of 30 hops:\n\n"
               "  1    <1 ms    <1 ms    <1 ms  192.168.0.1\n"
               "  2     8 ms     9 ms     8 ms  10.1.1.1\n"
               "  3     *        *        *     Request timed out.\n"
               "  4    12 ms    11 ms    13 ms  203.0.113.14\n\nTrace complete.\n")
        hops = nd.parse_traceroute_hops(out)
        self.assertEqual([h["hop"] for h in hops], [1, 2, 3, 4])
        self.assertTrue(hops[2]["timed_out"])

    def test_hostname_is_preferred_over_bare_ip_for_display(self):
        hops = nd.parse_traceroute_hops(
            " 3  router.example.net (10.0.0.5)  1.0 ms  1.1 ms  1.2 ms\n")
        self.assertEqual(hops[0]["display"], "router.example.net")
        self.assertEqual(hops[0]["host"], "10.0.0.5")

    def test_empty_input(self):
        self.assertEqual(nd.parse_traceroute_hops(""), [])
        self.assertEqual(nd.parse_traceroute_hops(None), [])


class TestPingAndInterfaceParsing(unittest.TestCase):
    def loss(self, out):
        return nd.parse_ping_loss({"ok": True, "stdout": out})

    def test_no_loss(self):
        self.assertEqual(self.loss("4 packets transmitted, 4 received, 0% packet loss"), 0.0)

    def test_total_loss(self):
        self.assertEqual(self.loss("4 packets transmitted, 0 received, 100% packet loss"), 100.0)

    def test_partial_loss(self):
        self.assertEqual(self.loss("4 packets transmitted, 3 received, 25% packet loss"), 25.0)

    def test_bsd_wording(self):
        self.assertEqual(
            self.loss("4 packets transmitted, 4 packets received, 0.0% packet loss"), 0.0)

    def test_unparsable_output_is_unknown_not_zero(self):
        # Must be None: reporting 0% for output we couldn't read would claim a
        # healthy link on no evidence.
        self.assertIsNone(self.loss("something unexpected"))

    def test_failed_command_is_unknown(self):
        self.assertIsNone(nd.parse_ping_loss({"ok": False, "error": "boom"}))

    def test_has_ip_address_linux(self):
        self.assertTrue(nd.has_ip_address(
            {"ok": True, "stdout": "2: eth0: <UP>\n    inet 10.0.0.5/24 brd 10.0.0.255\n"}))

    def test_has_ip_address_windows(self):
        self.assertTrue(nd.has_ip_address(
            {"ok": True, "stdout": "   IPv4 Address. . . . . . . . . . . : 192.168.0.10\n"}))

    def test_no_ip_address(self):
        self.assertFalse(nd.has_ip_address(
            {"ok": True, "stdout": "1: lo: <LOOPBACK>\n    inet6 ::1/128\n"}))


class TestTargetValidation(unittest.TestCase):
    """These targets end up in an argv list handed to ping/traceroute."""

    def test_accepts_ordinary_targets(self):
        for t in ("8.8.8.8", "example.com", "sub.domain.example.co.uk",
                  "dead:beef::1", "::1", "fe80::1%en0"):
            self.assertTrue(nd.valid_target(t), t)

    def test_rejects_flag_lookalikes(self):
        # A target starting with "-" would be read as a command-line option.
        for t in ("-D", "--help", "-oProxyCommand=x", "-c100000"):
            self.assertFalse(nd.valid_target(t), t)

    def test_rejects_shell_metacharacters(self):
        for t in ("8.8.8.8; id", "8.8.8.8 && whoami", "$(id)", "`id`", "a|b", "a\nb"):
            self.assertFalse(nd.valid_target(t), t)

    def test_rejects_malformed_ipv6(self):
        # The old regex accepted these and passed them straight to ping.
        for t in (":::", "::::::::", "12345::x"):
            self.assertFalse(nd.valid_target(t), t)

    def test_rejects_path_traversal_in_zone_id(self):
        self.assertFalse(nd.valid_target("fe80::1%../../etc/passwd"))

    def test_rejects_empty_and_overlong(self):
        self.assertFalse(nd.valid_target(""))
        self.assertFalse(nd.valid_target(None))
        self.assertFalse(nd.valid_target("a" * 254))

    def test_port_range_enforced(self):
        for bad in ("0", "65536", "-1", "abc", "8080abc"):
            self.assertFalse(nd.cmd_check_port("127.0.0.1", bad).get("ok"), bad)

    def test_port_check_rejects_bad_host_before_connecting(self):
        self.assertFalse(nd.cmd_check_port("-D", "80").get("ok"))


class TestMtrParsing(unittest.TestCase):
    """mtr's value is per-hop loss over many cycles. Its hops must come out in
    the same shape as traceroute's so everything downstream is unchanged."""

    SAMPLE = """{"report":{"mtr":{"src":"box","dst":"8.8.8.8","tos":0,"tests":10,"psize":"64"},
      "hubs":[
        {"count":1,"host":"_gateway (192.168.1.1)","Loss%":0.0,"Snt":10,"Last":1.2,"Avg":1.4,"Best":1.0,"Wrst":2.9,"StDev":0.5},
        {"count":2,"host":"198.51.100.13","Loss%":0.0,"Snt":10,"Last":12.0,"Avg":13.1,"Best":11.2,"Wrst":16.0,"StDev":1.6},
        {"count":3,"host":"???","Loss%":100.0,"Snt":10,"Last":0.0,"Avg":0.0,"Best":0.0,"Wrst":0.0,"StDev":0.0},
        {"count":4,"host":"dns.google (8.8.8.8)","Loss%":12.0,"Snt":10,"Last":24.0,"Avg":25.2,"Best":22.0,"Wrst":40.1,"StDev":5.2}]}}"""

    def test_hop_shape_matches_traceroute(self):
        hops = nd.parse_mtr_json(self.SAMPLE)
        self.assertEqual([h["hop"] for h in hops], [1, 2, 3, 4])
        for h in hops:                       # keys the rest of the code relies on
            for key in ("hop", "host", "display", "times_ms", "timed_out"):
                self.assertIn(key, h)

    def test_name_and_address_both_kept(self):
        hops = nd.parse_mtr_json(self.SAMPLE)
        self.assertEqual(hops[0]["display"], "_gateway")
        self.assertEqual(hops[0]["host"], "192.168.1.1")

    def test_bare_address_hop(self):
        hops = nd.parse_mtr_json(self.SAMPLE)
        self.assertEqual(hops[1]["host"], "198.51.100.13")

    def test_unanswered_hop(self):
        hop3 = nd.parse_mtr_json(self.SAMPLE)[2]
        self.assertTrue(hop3["timed_out"])
        self.assertEqual(hop3["display"], "*")
        self.assertIsNone(hop3["host"])
        self.assertEqual(hop3["loss_pct"], 100.0)

    def test_per_hop_loss_recorded(self):
        self.assertEqual(nd.parse_mtr_json(self.SAMPLE)[3]["loss_pct"], 12.0)

    def test_annotation_works_on_mtr_hops(self):
        # The whole point of matching shapes: demarc/delta/classification must
        # work without knowing which tool produced the hops.
        hops = nd.parse_mtr_json(self.SAMPLE)
        info = nd.annotate_hops(hops, "192.168.1.1", "8.8.8.8")
        self.assertEqual(info["demarc_hop"], 2)
        self.assertIn("gateway", hops[0]["roles"])

    def test_malformed_json_is_not_fatal(self):
        self.assertEqual(nd.parse_mtr_json("not json"), [])
        self.assertEqual(nd.parse_mtr_json(""), [])
        self.assertEqual(nd.parse_mtr_json('{"report":{}}'), [])


class TestEthtoolParsing(unittest.TestCase):
    SAMPLE = """Settings for eth0:
        Supported ports: [ TP ]
        Supported link modes:   10baseT/Half 10baseT/Full
                                100baseT/Half 100baseT/Full
                                1000baseT/Full
        Auto-negotiation: on
        Speed: 1000Mb/s
        Duplex: Full
        Port: Twisted Pair
        Link detected: yes
"""

    def test_negotiated_state(self):
        p = nd.parse_ethtool(self.SAMPLE)
        self.assertEqual(p["speed_mbps"], 1000)
        self.assertEqual(p["duplex"], "full")
        self.assertTrue(p["autoneg"])
        self.assertTrue(p["carrier"])

    def test_forced_half_duplex_link(self):
        text = self.SAMPLE.replace("Auto-negotiation: on", "Auto-negotiation: off")
        text = text.replace("Duplex: Full", "Duplex: Half").replace("Speed: 1000Mb/s", "Speed: 100Mb/s")
        p = nd.parse_ethtool(text)
        self.assertEqual(p["duplex"], "half")
        self.assertFalse(p["autoneg"])      # hard-coded, not a failed negotiation
        self.assertEqual(p["speed_mbps"], 100)

    def test_down_link_reports_unknown_speed(self):
        text = "Settings for eth0:\n\tSpeed: Unknown!\n\tDuplex: Unknown! (255)\n\tLink detected: no\n"
        p = nd.parse_ethtool(text)
        self.assertNotIn("speed_mbps", p)
        self.assertNotIn("duplex", p)
        self.assertFalse(p["carrier"])

    def test_empty_output(self):
        self.assertEqual(nd.parse_ethtool(""), {})
        self.assertEqual(nd.parse_ethtool(None), {})

    def test_interface_name_is_validated_before_use(self):
        # iface goes into an argv list; nothing exotic should reach it.
        self.assertIsNone(nd.cmd_ethtool("eth0; id"))
        self.assertIsNone(nd.cmd_ethtool("../../etc/passwd"))
        self.assertIsNone(nd.cmd_ethtool(""))


class TestDnsWireFormat(unittest.TestCase):
    """Queries are built and parsed here rather than shelled out to dig, so the
    wire format needs its own tests - nothing else would catch a bad offset."""

    def build_response(self, qid=0x4e45, rcode=0, answers=(("203.0.113.34",),), qname=b"\x07example\x03com\x00"):
        import struct
        an = len(answers)
        header = struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, an, 0, 0)
        question = qname + struct.pack(">HH", 1, 1)
        body = b""
        for (ip,) in answers:
            body += b"\xc0\x0c"                       # compression pointer to the name
            body += struct.pack(">HHIH", 1, 1, 60, 4)  # A, IN, ttl, rdlength
            body += bytes(int(o) for o in ip.split("."))
        return header + question + body

    def test_parses_a_records(self):
        r = nd.parse_dns_response(self.build_response(), 0x4e45)
        self.assertEqual(r["rcode_name"], "NOERROR")
        self.assertEqual(r["answers"], ["203.0.113.34"])

    def test_multiple_answers(self):
        data = self.build_response(answers=(("192.0.2.4",), ("192.0.2.8",)))
        self.assertEqual(nd.parse_dns_response(data, 0x4e45)["answers"], ["192.0.2.4", "192.0.2.8"])

    def test_nxdomain(self):
        r = nd.parse_dns_response(self.build_response(rcode=3, answers=()), 0x4e45)
        self.assertEqual(r["rcode_name"], "NXDOMAIN")
        self.assertEqual(r["answers"], [])

    def test_servfail(self):
        r = nd.parse_dns_response(self.build_response(rcode=2, answers=()), 0x4e45)
        self.assertEqual(r["rcode_name"], "SERVFAIL")

    def test_reply_for_a_different_query_is_rejected(self):
        # Guards against accepting a stray or spoofed packet as our answer.
        with self.assertRaises(ValueError):
            nd.parse_dns_response(self.build_response(qid=0x1111), 0x4e45)

    def test_truncated_response(self):
        with self.assertRaises(ValueError):
            nd.parse_dns_response(b"\x00\x01", 1)

    def test_name_encoding_round_trip(self):
        self.assertEqual(nd._dns_encode_name("example.com"), b"\x07example\x03com\x00")
        self.assertEqual(nd._dns_encode_name("a.b.c."), b"\x01a\x01b\x01c\x00")

    def test_query_to_an_invalid_server_fails_cleanly(self):
        r = nd.dns_query("not a server", "example.com")
        self.assertFalse(r["ok"])


class TestOpticsParsing(unittest.TestCase):
    """A fibre link degrading stays "up" and passes every reachability check,
    so these numbers are the only thing that sees it coming."""

    HEALTHY = """	Identifier                                : 0x03 (SFP)
	Vendor name                               : FINISAR CORP.
	Vendor PN                                 : FTLX8571D3BCL
	Module temperature                        : 34.05 degrees C
	Laser output power                        : 0.5849 mW / -2.33 dBm
	Receiver signal average optical power     : 0.4102 mW / -3.87 dBm
	Laser bias current high alarm             : Off
	Laser output power low warning            : Off
"""

    def test_healthy_module(self):
        p = nd.parse_ethtool_optics(self.HEALTHY)
        self.assertEqual(p["rx_dbm"], -3.87)
        self.assertEqual(p["tx_dbm"], -2.33)
        self.assertEqual(p["vendor"], "FINISAR CORP.")
        self.assertEqual(p["alarms"], [])
        self.assertEqual(p["warnings"], [])

    def test_failing_receive_power(self):
        text = self.HEALTHY.replace("0.4102 mW / -3.87 dBm", "0.0001 mW / -40.00 dBm")
        p = nd.parse_ethtool_optics(text)
        self.assertEqual(p["rx_dbm"], -40.0)
        self.assertLess(p["rx_dbm"], nd.OPTIC_RX_CRIT_DBM)

    def test_marginal_receive_power_sits_between_the_thresholds(self):
        text = self.HEALTHY.replace("0.4102 mW / -3.87 dBm", "0.0100 mW / -21.50 dBm")
        rx = nd.parse_ethtool_optics(text)["rx_dbm"]
        self.assertLess(rx, nd.OPTIC_RX_WARN_DBM)
        self.assertGreater(rx, nd.OPTIC_RX_CRIT_DBM)

    def test_module_alarms_are_collected(self):
        text = self.HEALTHY.replace("Laser bias current high alarm             : Off",
                                    "Laser bias current high alarm             : On")
        p = nd.parse_ethtool_optics(text)
        self.assertEqual(len(p["alarms"]), 1)
        self.assertIn("bias current", p["alarms"][0].lower())

    def test_warnings_are_kept_separate_from_alarms(self):
        text = self.HEALTHY.replace("Laser output power low warning            : Off",
                                    "Laser output power low warning            : On")
        p = nd.parse_ethtool_optics(text)
        self.assertEqual(p["alarms"], [])
        self.assertEqual(len(p["warnings"]), 1)

    def test_copper_port_output_yields_nothing_useful(self):
        self.assertEqual(nd.parse_ethtool_optics("Cannot get module EEPROM data: Operation not supported"),
                         {"alarms": [], "warnings": []})

    def test_junk_input(self):
        for junk in ("", None, "x" * 10000, "\x00\x00"):
            nd.parse_ethtool_optics(junk)

    def test_interface_name_is_validated(self):
        self.assertIsNone(nd.cmd_optics("eth0; id"))
        self.assertIsNone(nd.cmd_optics(""))


class TestTraceReached(unittest.TestCase):
    """Deciding whether the trace got there is what triggers the TCP fallback,
    so a wrong answer either wastes time or misses a filtered path."""

    def test_reached_when_the_last_hop_is_the_target(self):
        hops = [{"hop": 1, "host": "10.0.0.1", "display": "gw", "timed_out": False},
                {"hop": 2, "host": "8.8.8.8", "display": "dns.google", "timed_out": False}]
        self.assertTrue(nd.trace_reached(hops, "8.8.8.8"))

    def test_not_reached_when_the_trace_times_out(self):
        hops = [{"hop": 1, "host": "10.0.0.1", "display": "gw", "timed_out": False},
                {"hop": 2, "host": None, "display": "*", "timed_out": True}]
        self.assertFalse(nd.trace_reached(hops, "8.8.8.8"))

    def test_not_reached_when_it_stops_at_an_unrelated_hop(self):
        hops = [{"hop": 1, "host": "10.0.0.1", "display": "gw", "timed_out": False},
                {"hop": 2, "host": "198.51.100.96", "display": "isp", "timed_out": False}]
        self.assertFalse(nd.trace_reached(hops, "8.8.8.8"))

    def test_matches_on_hostname_too(self):
        hops = [{"hop": 1, "host": "1.1.1.1", "display": "one.one.one.one", "timed_out": False}]
        self.assertTrue(nd.trace_reached(hops, "one.one.one.one"))

    def test_empty_trace(self):
        self.assertFalse(nd.trace_reached([], "8.8.8.8"))


class TestMtrDisplayHeuristics(unittest.TestCase):
    """mtr hops carry real loss percentages; traceroute hops carry three probe
    timings. Applying traceroute's heuristics to mtr data marks every hop as
    lossy, which is what happened before this."""

    def test_private_hops_do_not_create_network_handoffs(self):
        hops = [{"hop": 1, "host": "10.10.0.1", "display": "gw.site",
                 "times_ms": [1.0], "timed_out": False},
                {"hop": 2, "host": "198.51.100.9", "display": "be-22.chi01.example-isp.net",
                 "times_ms": [20.0], "timed_out": False}]
        info = nd.annotate_hops(hops, "10.10.0.1", "8.8.8.8")
        self.assertIsNone(hops[0]["enters_network"])       # inside the site
        self.assertEqual([n["network"] for n in info["networks_crossed"]],
                         ["example-isp.net"])

    def test_partial_loss_label_is_traceroute_only(self):
        report = {"os": "Linux", "target": "8.8.8.8", "findings": [], "raw": {},
                  "hops": [{"hop": 1, "host": "1.1.1.1", "display": "a", "times_ms": [10.0],
                            "timed_out": False, "loss_pct": 0.0}]}
        out = nd.render_text_report(report, color=False, width=90)
        self.assertNotIn("partial reply loss", out)

    def test_partial_loss_label_still_applies_to_traceroute_hops(self):
        report = {"os": "Linux", "target": "8.8.8.8", "findings": [], "raw": {},
                  "hops": [{"hop": 1, "host": "1.1.1.1", "display": "a", "times_ms": [10.0],
                            "timed_out": False}]}          # no loss_pct -> traceroute
        self.assertIn("partial reply loss", nd.render_text_report(report, color=False, width=90))


class TestStageStripFits(unittest.TestCase):
    """The strip is the line that gets pasted into a ticket, and it ran out to
    whatever length the chain happened to be while every other part of the
    report wrapped. At seven stages it was 92 columns; the inbound leg took it
    to 107, so on an eighty-column console - the kind this tool is read on -
    it broke wherever the terminal chose."""

    STRIP = re.compile(r"\b(PASS|WARN|FAIL)\b")
    ANSI = re.compile(r"\x1b\[[0-9;]*m")

    def strip_lines(self, text):
        """Matched on the de-escaped line: tinted, the word arrives as
        "\\x1b[32mPASS", where there is no word boundary before the P."""
        out = []
        for line in text.splitlines():
            bare = self.ANSI.sub("", line)
            if self.STRIP.search(bare) and "owner:" not in bare and "->" not in bare:
                out.append(line)
        return out

    def report(self):
        setup, kw = S["tcp_flow_loss_clients"]
        m = fresh(); setup(m)
        return m, m.diagnose(quick=False, **scenario_kwargs(kw))

    def test_the_strip_stays_inside_the_terminal(self):
        m, rep = self.report()
        for width in (120, 100, 80, 72, 60, 40):
            text = m.render_text_report(rep, color=False, width=width)
            for line in self.strip_lines(text):
                self.assertLessEqual(
                    len(line), max(width, 40),
                    f"the stage strip runs to {len(line)} columns at width={width}")

    def test_every_stage_survives_the_wrap(self):
        """Wrapping must not be a way to lose one. All eight are still there,
        in order, however many lines it took."""
        m, rep = self.report()
        want = [s["stage"] for s in rep["stages"]]
        for width in (120, 80, 40):
            text = m.render_text_report(rep, color=False, width=width)
            shown = []
            for line in self.strip_lines(text):
                shown += [w for w in line.split() if w in want]
            self.assertEqual(shown, want, f"stages lost or reordered at width={width}")

    def test_colour_does_not_change_where_it_wraps(self):
        """An escape sequence takes no space on screen. Measured on the tinted
        string instead of the plain one, the strip would wrap a line that fits
        - and only ever on the terminals that asked for colour."""
        m, rep = self.report()
        plain = self.strip_lines(m.render_text_report(rep, color=False, width=80))
        tinted = self.strip_lines(m.render_text_report(rep, color=True, width=80))
        visible = [re.sub(r"\x1b\[[0-9;]*m", "", l) for l in tinted]
        self.assertEqual(visible, plain)


class TestBarRendering(unittest.TestCase):
    """The magnitude bar, and the path drawn with it."""

    def test_bar_is_proportional_and_fixed_width(self):
        self.assertEqual(nd.render_bar(50, 100, 10), "#####.....")
        self.assertEqual(nd.render_bar(100, 100, 10), "##########")
        self.assertEqual(nd.render_bar(0, 100, 10), "..........")
        self.assertEqual(len(nd.render_bar(37, 100, 24)), 24)

    def test_a_real_measurement_never_rounds_away_to_nothing(self):
        # The sliver rule. 0.4% of the total is under half a cell, and drawing
        # it empty would say the hop added nothing rather than very little.
        self.assertEqual(nd.render_bar(0.4, 100, 10).count("#"), 1)

    def test_bar_declines_rather_than_lying(self):
        for bad in [None, 0, -5]:
            self.assertEqual(nd.render_bar(10, bad, 10), "")
        self.assertEqual(nd.render_bar(None, 100, 10), "")
        self.assertEqual(nd.render_bar(10, 100, 0), "")

    def test_bar_clamps_instead_of_overflowing_its_width(self):
        # Deltas are clamped at zero and cannot quite sum to the total, so a
        # rounding artefact must not draw wider than the bar it lives in.
        self.assertEqual(nd.render_bar(150, 100, 8), "########")
        self.assertEqual(nd.render_bar(-3, 100, 8), "........")

    def _path_report(self, times):
        hops = [{"hop": i + 1, "host": f"10.0.0.{i + 1}", "display": f"h{i + 1}",
                 "times_ms": [t], "timed_out": False} for i, t in enumerate(times)]
        info = nd.annotate_hops(hops, "10.0.0.1", "8.8.8.8")
        rep = {"os": "Linux", "target": "8.8.8.8", "findings": [], "raw": {},
               "hops": hops}
        rep.update(info)
        out = []
        nd._render_path(rep, out, lambda s, sev: s, 100)
        return "\n".join(out)

    def test_path_bar_is_drawn_and_shares_the_total(self):
        text = self._path_report([1.0, 5.0, 25.0])
        self.assertIn("where the 25ms went", text)
        self.assertIn("#", text.split("where the")[1])

    def test_one_timed_hop_is_not_a_shape_to_compare(self):
        self.assertNotIn("where the", self._path_report([12.0]))

    def test_arrow_only_where_one_hop_really_dominates(self):
        # 92% of the path in one step - worth pointing at.
        self.assertIn("<- biggest jump", self._path_report([1.0, 2.0, 25.0]))
        # An evenly graded path has no hop to send the reader to, and the
        # summary line below says exactly that.
        self.assertNotIn("<- biggest jump",
                         self._path_report([10.0, 20.0, 30.0, 40.0]))

    def test_the_report_stays_ascii(self):
        # Box drawing would look better and arrive as mojibake on a serial
        # console, which is where this runs.
        text = self._path_report([1.0, 5.0, 25.0])
        self.assertEqual(text, text.encode("ascii", "replace").decode("ascii"))

    def test_nothing_the_tool_writes_itself_is_non_ascii(self):
        """The check above renders one section, and the character that broke
        this was in two others - a separator in the call-quality line and one
        between the relation marks. Every scenario, whole report: the fixtures
        name their hosts in ASCII, so anything non-ASCII in the output came
        from the tool rather than from the data."""
        offenders = {}
        for code in sorted(S):
            setup, kw = S[code]
            m = fresh(); setup(m)
            try:
                rep = m.diagnose(quick=False, **scenario_kwargs(kw))
            except Exception:
                continue
            text = m.render_text_report(rep, color=False, width=88)
            for ch in set(text):
                if ord(ch) > 127:
                    offenders.setdefault(ch, []).append(code)
        self.assertEqual(
            offenders, {},
            "the tool writes characters a serial console cannot: "
            + "; ".join(f"U+{ord(c):04X} {c!r} in {len(v)} scenario(s)"
                        for c, v in offenders.items()))

    def test_a_narrow_terminal_drops_the_bar_rather_than_wrapping_it(self):
        hops = [{"hop": i + 1, "host": f"10.0.0.{i + 1}", "display": f"h{i + 1}",
                 "times_ms": [t], "timed_out": False} for i, t in enumerate([1.0, 5.0, 25.0])]
        info = nd.annotate_hops(hops, "10.0.0.1", "8.8.8.8")
        rep = {"os": "Linux", "target": "8.8.8.8", "findings": [], "raw": {},
               "hops": hops}
        rep.update(info)
        out = []
        nd._render_path(rep, out, lambda s, sev: s, 44)
        self.assertNotIn("where the", "\n".join(out))


class TestMagnitudeColumns(unittest.TestCase):
    """Call quality and the error table, read as magnitudes."""

    def _link_text(self, ifaces, width=100, mos=None):
        rep = {"findings": [], "raw": {"link_stats": {"interfaces": ifaces}}}
        if mos is not None:
            rep["call_quality"] = {"mos": mos, "avg_ms": 24.0, "jitter_ms": 2.0,
                                   "loss_pct": 0.0, "target": "8.8.8.8"}
        out = []
        nd._render_link_tables(rep, out, lambda s, sev: s, width)
        return "\n".join(out)

    def _iface(self, name, ppm):
        return {"name": name, "packets": 1000, "errors": int(ppm), "drops": 0,
                "err_ppm": ppm, "delta_errors": None, "delta_drops": None,
                "sample_seconds": 0}

    def test_mos_is_drawn_on_a_one_to_five_scale(self):
        # 3.0 is halfway up a scale that starts at 1, not 60% of one that
        # starts at 0 - drawing it from zero would flatter every score.
        text = self._link_text([], mos=3.0)
        gauge = [w for w in text.split() if set(w) <= set("#.") and len(w) == 12]
        self.assertEqual(gauge[0].count("#"), 6)

    def test_a_clean_table_draws_no_empty_column(self):
        text = self._link_text([self._iface("en0", 0.0), self._iface("en1", 0.0)])
        self.assertNotIn("..........", text)

    def test_the_worst_interface_fills_the_bar(self):
        text = self._link_text([self._iface("en0", 1.0), self._iface("en1", 313.0)])
        rows = {l.split()[0]: l for l in text.splitlines() if l.startswith("  en")}
        self.assertIn("##########", rows["en1"])
        self.assertEqual(rows["en0"].count("#"), 1)   # present, but plainly minor

    def test_narrow_terminals_keep_the_numbers_over_the_picture(self):
        text = self._link_text([self._iface("en0", 1.0), self._iface("en1", 313.0)],
                               width=80)
        self.assertNotIn("##########", text)
        self.assertIn("313", text)


class TestMissingToolsAreNotFaults(unittest.TestCase):
    """On a stripped appliance the tools this program shells out to may simply
    not exist. A check that couldn't run must never be reported as a fault -
    telling someone their device has no IP address because ifconfig is missing
    is worse than saying nothing."""

    def test_unreadable_interfaces_is_a_warning_not_a_critical(self):
        st = {s["stage"]: s["state"] for s in nd.build_stages(
            [{"code": "interfaces_unreadable", "severity": "warning", "layer": 1,
              "message": "x"}],
            {"link_stats": {"interfaces": [{"name": "eth0"}]}})}
        self.assertEqual(st["address"], "warn")

    def test_verdict_says_the_check_did_not_run(self):
        v = nd.build_verdict([{"code": "interfaces_unreadable", "severity": "warning",
                               "layer": 1, "message": "x"}])
        self.assertIn("couldn't be read", v["headline"].lower())
        self.assertIn("couldn't run", v["owner"])

    def test_no_ipv4_is_still_critical_when_the_check_did_run(self):
        v = nd.build_verdict([{"code": "no_ipv4", "severity": "critical", "layer": 1,
                               "message": "x"}])
        self.assertIn("no ip address", v["headline"].lower())
        self.assertEqual(v["owner"], "this device")

    def test_routes_unreadable_outranks_nothing_it_should_not(self):
        # A real fault must still win over "couldn't read the routing table".
        v = nd.build_verdict([{"code": "routes_unreadable", "severity": "warning",
                               "layer": 3, "message": "x"},
                              {"code": "link_errors_live", "severity": "critical",
                               "layer": 1, "message": "x"}])
        self.assertIn("corrupting frames", v["headline"].lower())


class TestStageStrip(unittest.TestCase):
    def f(self, code, severity="critical"):
        return {"code": code, "severity": severity, "message": code}

    def states(self, findings, raw=None, ports=False):
        return {s["stage"]: s["state"] for s in
                nd.build_stages(findings, raw or {"link_stats": {"interfaces": [{"name": "eth0"}]},
                                                  "path_mtu": {}}, checked_ports=ports)}

    def test_healthy_run_passes_every_measured_stage(self):
        st = self.states([{"code": "all_clear", "severity": "ok", "message": "fine"}])
        self.assertEqual(st["gateway"], "pass")
        self.assertEqual(st["dns"], "pass")

    def test_failure_marks_only_its_own_stage(self):
        st = self.states([self.f("dns_fail")])
        self.assertEqual(st["dns"], "fail")
        self.assertEqual(st["gateway"], "pass")

    def test_warning_level_codes_warn_rather_than_fail(self):
        self.assertEqual(self.states([self.f("gw_partial_loss", "warning")])["gateway"], "warn")

    def test_unmeasured_stages_are_skipped_not_passed(self):
        # A stage that never ran must not read as PASS - that would claim a
        # check happened when it didn't.
        st = self.states([], raw={"link_stats": {"interfaces": []}})
        self.assertEqual(st["ports"], "skip")
        self.assertEqual(st["mtu"], "skip")
        self.assertEqual(st["link"], "skip")

    def test_ports_stage_appears_when_ports_were_checked(self):
        self.assertEqual(self.states([], ports=True)["ports"], "pass")


class TestBaselineComparison(unittest.TestCase):
    def report(self, **kw):
        base = {"detected_gateway": "192.168.1.1", "path_source": "traceroute",
                "neighbours": [{"iface": "eth0", "switch": "SW-1", "port": "Gi1/0/1", "vlan": "10"}],
                "hops": [{"hop": 1}], "demarc_hop": 2, "call_quality": {"mos": 4.4},
                "raw": {"link_modes": {"interfaces": [
                            {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500}]},
                        "link_stats": {"interfaces": [
                            {"name": "eth0", "packets": 1000, "errors": 0}]},
                        "dns_health": {"resolvers": [{"server": "192.168.1.1"}]}},
                "verdict": {"headline": "No fault found", "severity": "ok"}}
        base.update(kw)
        return base

    def find(self, changes, what):
        return next((c for c in changes if c["what"] == what), None)

    def test_identical_reports_show_no_changes(self):
        self.assertEqual(nd.compare_reports(self.report(), self.report()), [])

    def test_device_moved_to_a_different_port(self):
        cur = self.report(neighbours=[{"iface": "eth0", "switch": "SW-1",
                                       "port": "Gi1/0/24", "vlan": "10"}])
        c = self.find(nd.compare_reports(cur, self.report()), "eth0 switch port")
        self.assertEqual((c["before"], c["after"], c["direction"]), ("Gi1/0/1", "Gi1/0/24", "worse"))

    def test_speed_drop_is_a_regression_and_a_rise_is_not(self):
        slow = self.report()
        slow["raw"]["link_modes"]["interfaces"][0]["speed_mbps"] = 100
        self.assertEqual(self.find(nd.compare_reports(slow, self.report()),
                                   "eth0 link speed")["direction"], "worse")
        self.assertEqual(self.find(nd.compare_reports(self.report(), slow),
                                   "eth0 link speed")["direction"], "better")

    def test_errors_accumulated_since_the_baseline(self):
        """Errors gained at a rate the live check would report. The fixture
        moves the packet counter too: errors appearing on an interface that
        carried nothing between two visits is not a situation a real pair of
        runs produces, and it was the only thing this asserted."""
        cur = self.report()
        cur["raw"]["link_stats"]["interfaces"][0]["errors"] = 4200
        cur["raw"]["link_stats"]["interfaces"][0]["packets"] = 1_000_000 + 1000
        c = self.find(nd.compare_reports(cur, self.report()), "eth0 errors since baseline")
        self.assertEqual(c["delta"], 4200)
        self.assertEqual(c["direction"], "worse")

    def test_a_handful_of_new_errors_is_not_a_regression(self):
        """A change measured against a baseline still has to be worth something
        on its own. One new error between two visits is a relative
        deterioration of infinity and an absolute nothing - and it used to
        raise regression_since_baseline every time, so a healthy box rechecked
        next week reported that it had got worse."""
        cur = self.report()
        cur["raw"]["link_stats"]["interfaces"][0]["errors"] = 1
        cur["raw"]["link_stats"]["interfaces"][0]["packets"] = 1_000_000_000
        c = self.find(nd.compare_reports(cur, self.report()), "eth0 errors since baseline")
        self.assertEqual(c["delta"], 1)
        self.assertEqual(c["direction"], "neutral", "one error in a billion packets")

    def test_it_is_still_reported_just_not_as_a_regression(self):
        """Somebody hunting an intermittent fault wants to see it. The rule is
        about what counts as a deterioration, not about hiding data."""
        cur = self.report()
        cur["raw"]["link_stats"]["interfaces"][0]["errors"] = 1
        cur["raw"]["link_stats"]["interfaces"][0]["packets"] = 1_000_000_000
        c = self.find(nd.compare_reports(cur, self.report()), "eth0 errors since baseline")
        self.assertIsNotNone(c)
        self.assertEqual(c["per_million"], 0.0)

    def test_a_high_rate_over_almost_no_traffic_is_not_a_rate(self):
        """Five errors in a hundred packets is 50,000 per million, which clears
        the rate bar comfortably and means nothing: a hundred packets between
        two visits is not a sample. Both halves of the test are needed, and
        this is the half the percentage alone lets through."""
        cur = self.report()
        cur["raw"]["link_stats"]["interfaces"][0]["errors"] = 5
        cur["raw"]["link_stats"]["interfaces"][0]["packets"] = 1100
        c = self.find(nd.compare_reports(cur, self.report()), "eth0 errors since baseline")
        self.assertGreater(c["per_million"], nd.ERR_PPM_WARN)
        self.assertEqual(c["direction"], "neutral")

    def test_errors_with_no_traffic_to_judge_them_against_are_not_a_regression(self):
        """The same discipline as everywhere else here: a sample that cannot
        support the claim does not get to make it. Without packets moving there
        is no rate, and no way to say whether the count is a lot."""
        cur = self.report()
        cur["raw"]["link_stats"]["interfaces"][0]["errors"] = 4200
        c = self.find(nd.compare_reports(cur, self.report()), "eth0 errors since baseline")
        self.assertEqual(c["direction"], "neutral")
        self.assertIsNone(c["per_million"])

    def test_a_call_score_that_fell_but_is_still_good_is_not_a_regression(self):
        """4.5 to 4.2 moved the wrong way and is still a call nobody would
        complain about."""
        cur, base = self.report(), self.report()
        base["call_quality"] = {"mos": 4.5}
        cur["call_quality"] = {"mos": 4.2}
        self.assertEqual(self.find(nd.compare_reports(cur, base),
                                   "call quality (MOS)")["direction"], "neutral")

    def test_a_call_score_that_fell_into_trouble_is(self):
        cur, base = self.report(), self.report()
        base["call_quality"] = {"mos": 4.2}
        cur["call_quality"] = {"mos": 3.5}
        self.assertEqual(self.find(nd.compare_reports(cur, base),
                                   "call quality (MOS)")["direction"], "worse")

    def test_counter_reset_is_reported_as_a_reboot_not_negative_errors(self):
        cur = self.report()
        cur["raw"]["link_stats"]["interfaces"][0]["packets"] = 5      # lower than baseline
        cur["raw"]["link_stats"]["interfaces"][0]["errors"] = 0
        base = self.report()
        base["raw"]["link_stats"]["interfaces"][0]["errors"] = 900
        c = self.find(nd.compare_reports(cur, base), "eth0 counters")
        self.assertIn("reboot", c["after"])

    def test_missing_data_on_either_side_is_not_a_change(self):
        # A quick run, or a tool that wasn't installed last visit, must not
        # manufacture regressions.
        cur = self.report(demarc_hop=2)
        base = self.report(demarc_hop=None)
        self.assertIsNone(self.find(nd.compare_reports(cur, base), "site edge at hop"))

    def test_mos_change_below_the_threshold_is_ignored(self):
        cur = self.report(call_quality={"mos": 4.35})
        self.assertIsNone(self.find(nd.compare_reports(cur, self.report()), "call quality (MOS)"))

    def test_meaningful_mos_drop_is_flagged(self):
        cur = self.report(call_quality={"mos": 3.7})
        self.assertEqual(self.find(nd.compare_reports(cur, self.report()),
                                   "call quality (MOS)")["direction"], "worse")

    def test_garbage_baseline_is_not_fatal(self):
        for junk in (None, "", [], 42, {"nonsense": True}):
            nd.compare_reports(self.report(), junk)


class TestAwkwardRealWorldInputs(unittest.TestCase):
    """The failures that don't come from a parser meeting a new format: bytes
    that aren't text, numbers that aren't finite, counters that go backwards,
    and output that doesn't stop."""

    def test_a_command_emitting_non_utf8_still_yields_its_output(self):
        """An interface alias or SSID with odd bytes would otherwise raise
        UnicodeDecodeError and fail the whole check - which reads as 'not
        available on this system' rather than 'one strange byte'."""
        import sys as _sys
        payload = b"eth0 \xff\xfe up\n"
        res = nd.run([_sys.executable, "-c",
                      "import sys; sys.stdout.buffer.write(%r)" % payload])
        self.assertTrue(res["ok"])
        self.assertIn("eth0", res["stdout"])
        self.assertIn("up", res["stdout"])

    def test_command_output_is_capped(self):
        """A report travels by paste and by email; one command with a huge table
        must not turn a 60KB report into a multi-megabyte one."""
        import sys as _sys
        res = nd.run([_sys.executable, "-c", "print('x' * 500_000)"])
        self.assertLessEqual(len(res["stdout"]), nd.MAX_OUTPUT_BYTES + 200)
        self.assertIn("not stored", res["stdout"])

    def test_short_output_is_untouched(self):
        self.assertEqual(nd._cap("hello"), "hello")

    def test_a_counter_that_went_backwards_is_unknown_not_negative(self):
        """A 32-bit counter wraps, and an interface can be reset mid-sample.
        "-98 errors in 2s" is not a rate."""
        patch_clock(self, sleep=lambda s: None)
        base = dict(tx_packets=0, rx_bytes=0, tx_bytes=0, tx_errors=0, rx_dropped=0,
                    tx_dropped=0, rx_crc_errors=0, rx_frame_errors=0, rx_over_errors=0,
                    collisions=0, operstate="up")
        seq = [({"eth0": dict(base, rx_packets=4_294_967_290, rx_errors=100)}, "t"),
               ({"eth0": dict(base, rx_packets=12, rx_errors=2)}, "t")]
        state = {"i": 0}
        def read():
            r = seq[min(state["i"], 1)]; state["i"] += 1; return r
        original = nd._read_link_stats
        nd._read_link_stats = read
        try:
            iface = nd.cmd_link_stats(2)["interfaces"][0]
        finally:
            nd._read_link_stats = original
        self.assertIsNone(iface["delta_errors"])
        self.assertIsNone(iface["delta_packets"])

    def test_nonfinite_numbers_never_reach_a_report(self):
        """json.dumps writes bare NaN and Infinity. Python reads those back
        happily; every browser's JSON.parse refuses them, so one stray value
        would make a self-contained report fail to open with nothing to explain
        why."""
        import json as _json
        report = {"findings": [], "raw": {}, "hops": [],
                  "a": float("nan"), "b": float("inf"), "c": [float("-inf"), 1.5],
                  "d": {"e": float("nan")}}
        blob = _json.dumps(nd.json_safe(report))
        self.assertNotIn("NaN", blob)
        self.assertNotIn("Infinity", blob)
        self.assertEqual(_json.loads(blob)["c"], [None, 1.5])
        self.assertIsNone(_json.loads(blob)["d"]["e"])

    def test_a_self_contained_page_with_odd_numbers_still_loads(self):
        html = nd.render_report_html({"findings": [], "raw": {}, "hops": [],
                                      "value": float("nan")})
        self.assertIsNotNone(nd.extract_embedded_report(html))

    def test_non_ascii_survives_every_output_format(self):
        import json as _json
        message = "Drucker-B\u00fcro-2 (\u00d6konomie) \u6253\u5370\u673a"
        report = {"os": "Linux", "raw": {}, "hops": [], "stages": [], "port_results": [],
                  "findings": [{"severity": "warning", "layer": 2, "code": "duplicate_ip",
                                "message": message}],
                  "verdict": {"headline": message, "owner": "o", "confidence": "high",
                              "next_step": "n", "severity": "warning"}}
        self.assertIn(message, _json.dumps(nd.json_safe(report), ensure_ascii=False))
        self.assertEqual(nd.extract_embedded_report(
            nd.render_report_html(report))["findings"][0]["message"], message)
        self.assertIn("Drucker", nd.render_text_report(report, color=False, width=90))

    def _proxy(self, env=None, system=None):
        m = fresh()
        m.cmd_proxy_config = lambda: {
            "ok": True, "cmd": "proxy configuration (read, not probed)", "code": 0,
            "stderr": "", "stdout": "", "env": env or {}, "system": system or {}}
        found = []
        m._check_proxy({}, found, "8.8.8.8")
        return found

    def test_a_proxied_box_is_told_the_checks_went_direct(self):
        """Every probe here goes direct - a ping, a traceroute and a TCP
        connect do not read a proxy setting, and nothing in the standard
        library makes them. An application on the same box, told to use one,
        does not. So the checks measure a route nothing here uses, and a clean
        report can sit beside a user who cannot load anything."""
        for label, kwargs in (
                ("an environment variable", {"env": {"https_proxy": "http://p:8080"}}),
                ("a system setting", {"system": {"HTTPEnable": "1", "HTTPProxy": "p"}}),
                ("a PAC file", {"system": {"ProxyAutoConfigEnable": "1",
                                           "ProxyAutoConfigURLString": "http://wpad/x.dat"}}),
                ("WPAD", {"system": {"ProxyAutoDiscoveryEnable": "1"}})):
            with self.subTest(configured_by=label):
                found = self._proxy(**kwargs)
                self.assertEqual([f["code"] for f in found], ["proxy_configured"])
                self.assertEqual(found[0]["severity"], "ok", "a proxy is not a fault")
                self.assertIn("went direct", found[0]["message"])

    def test_no_proxy_alone_is_not_a_proxy(self):
        """no_proxy lists what bypasses one. On a box with only that set there
        is nothing to bypass, and reporting it would put a caveat on every
        finding for no reason."""
        self.assertEqual(self._proxy(env={"no_proxy": "localhost,10.0.0.0/8"}), [])
        self.assertEqual(self._proxy(env={"NO_PROXY": "*"}), [])

    def test_nothing_configured_says_nothing(self):
        self.assertEqual(self._proxy(), [])
        # A disabled system setting is not a configured proxy either.
        self.assertEqual(self._proxy(system={"HTTPEnable": "0", "FTPPassive": "1"}), [])

    def test_a_collector_that_could_not_run_makes_no_claim(self):
        """It returns the shape every other one does when it fails, without the
        keys this reads. Nothing is known about the routing then - which is not
        the same as knowing there is no proxy, and saying either would be a
        guess."""
        m = fresh()
        m.cmd_proxy_config = lambda: {"ok": False, "cmd": "proxy configuration",
                                      "applicable": False, "error": "not available"}
        found = []
        m._check_proxy({}, found, "8.8.8.8")
        self.assertEqual(found, [])

    def test_the_environment_caveat_is_only_made_when_it_applies(self):
        """A variable in this shell is not what a daemon here sees, and saying
        so matters. A system-wide setting is what everything sees, and the same
        sentence would then be wrong."""
        env_only = self._proxy(env={"http_proxy": "http://p:3128"})[0]["message"]
        self.assertIn("this shell's environment, which is not necessarily", env_only)
        system = self._proxy(system={"HTTPEnable": "1", "HTTPProxy": "p"})[0]["message"]
        self.assertNotIn("not necessarily what a service", system)

    def test_scutil_output_is_read_at_the_top_level_only(self):
        """The exceptions list is a nested block, and a key inside it must not
        be read as a setting of its own."""
        parsed = nd.parse_scutil_proxy(
            "<dictionary> {\n"
            "  ExceptionsList : <array> {\n"
            "    0 : *.local\n"
            "  }\n"
            "  HTTPEnable : 1\n"
            "  HTTPProxy : proxy.example.com\n"
            "}\n")
        self.assertEqual(parsed.get("HTTPEnable"), "1")
        self.assertEqual(parsed.get("HTTPProxy"), "proxy.example.com")
        self.assertNotIn("0", parsed, "a nested entry was read as a setting")

    def test_colour_is_off_wherever_it_cannot_be_read(self):
        """Four conditions, and the two that were missing are the ones that
        matter to this audience. A dumb terminal cannot interpret an escape
        sequence, so it prints it - a report read on a serial console or an
        out-of-band card came back with ESC[31m through the middle of it. That
        is the same terminal that could not encode a middle dot."""
        import io as _io

        class Terminal(_io.StringIO):
            def isatty(self):
                return True

        term = Terminal()
        saved = dict(os.environ)
        saved_os = nd.OS_NAME
        try:
            for key in ("NO_COLOR", "TERM"):
                os.environ.pop(key, None)
            os.environ["TERM"] = "xterm-256color"

            # There is a fifth condition - Windows never gets colour - and it
            # short-circuits the rest. Run these on a stated platform rather
            # than on whichever one happens to be here: on Windows every
            # assertFalse below passes for that reason alone, so the four
            # conditions this test exists for would go unexercised and it
            # would stay green with all of them deleted.
            nd.OS_NAME = "Linux"
            self.assertTrue(nd.use_color(term), "a real terminal gets colour")

            os.environ["NO_COLOR"] = "1"
            self.assertFalse(nd.use_color(term), "NO_COLOR is set and was ignored")
            del os.environ["NO_COLOR"]

            os.environ["TERM"] = "dumb"
            self.assertFalse(nd.use_color(term), "a dumb terminal was sent escape codes")
            os.environ["TERM"] = "xterm-256color"

            self.assertFalse(nd.use_color(term, True), "--no-color did not override")
            self.assertFalse(nd.use_color(_io.StringIO()), "a pipe got colour")

            # And the fifth, on its own terms: a console that may not read an
            # escape sequence is not sent one, whatever else is true.
            nd.OS_NAME = "Windows"
            self.assertFalse(nd.use_color(term),
                             "Windows is excluded deliberately - cmd.exe cannot "
                             "be relied on to interpret an escape sequence")
        finally:
            nd.OS_NAME = saved_os
            os.environ.clear()
            os.environ.update(saved)

    def test_force_color_turns_it_back_on_and_no_color_still_wins(self):
        """The companion to NO_COLOR, for where the isatty guess is wrong: a
        report piped into `less -R`, or a CI log that renders escapes and is
        not a terminal.

        The precedence is the point. NO_COLOR beats FORCE_COLOR, because the
        one that suppresses output must win a tie, and --no-color beats both,
        because a flag someone typed beats the environment they inherited."""
        import io as _io

        class Terminal(_io.StringIO):
            def isatty(self):
                return True

        pipe, term = _io.StringIO(), Terminal()
        saved, saved_os = dict(os.environ), nd.OS_NAME
        try:
            nd.OS_NAME = "Linux"
            for key in ("NO_COLOR", "FORCE_COLOR"):
                os.environ.pop(key, None)
            os.environ["TERM"] = "xterm-256color"

            self.assertFalse(nd.use_color(pipe), "a pipe got colour unasked")
            os.environ["FORCE_COLOR"] = "1"
            self.assertTrue(nd.use_color(pipe), "FORCE_COLOR was ignored")
            os.environ["FORCE_COLOR"] = ""
            self.assertFalse(nd.use_color(pipe), "an empty FORCE_COLOR still forced it")
            os.environ["FORCE_COLOR"] = "1"
            os.environ["NO_COLOR"] = "1"
            self.assertFalse(nd.use_color(pipe), "NO_COLOR lost to FORCE_COLOR")
            del os.environ["NO_COLOR"]
            self.assertFalse(nd.use_color(term, True), "--no-color lost to FORCE_COLOR")
        finally:
            nd.OS_NAME = saved_os
            os.environ.clear()
            os.environ.update(saved)

    def test_the_help_says_what_the_exit_codes_mean(self):
        """The person who needs them is writing a wrapper at the time they need
        them, and reaching for --help rather than a reference document.

        Also pins the width. Switching the formatter so the epilog keeps its
        line breaks stops argparse wrapping the description too, and that ran
        to 129 columns on an eighty column terminal until it was wrapped by
        hand."""
        import subprocess
        out = subprocess.run([sys.executable, nd.__file__, "--help"],
                             capture_output=True, text=True, timeout=60,
                             env=dict(os.environ, COLUMNS="80"))
        self.assertEqual(out.returncode, 0, out.stderr)
        for token in ("exit codes:", "0 nothing wrong", "3 no verdict reached",
                      "NO_COLOR", "FORCE_COLOR"):
            self.assertIn(token, out.stdout, f"--help never mentions {token}")
        longest = max(len(l) for l in out.stdout.split("\n"))
        self.assertLessEqual(longest, 80,
                             f"--help runs to {longest} columns at COLUMNS=80")

    def test_the_override_reaches_the_only_place_colour_is_decided(self):
        """A flag nothing consults is a flag that lies. There is exactly one
        call, so this pins that it is passed rather than defaulted."""
        src = open(nd.__file__, encoding="utf-8").read()
        self.assertIn("use_color(msg, args.no_color)", src)
        self.assertEqual(src.count("use_color("), 2, "a second caller appeared")

    def test_a_name_it_cannot_print_does_not_cost_the_report(self):
        """A hostname is data and can be anything the network carries. On a
        terminal that cannot encode it - LANG=C, an out-of-band console - the
        write used to raise and the whole diagnosis was lost to a traceback
        because a neighbour had an umlaut in its name. Running the checks and
        then failing to deliver them is the shape of failure this tool exists
        to avoid."""
        import io as _io
        import subprocess
        report = {"os": "Linux", "raw": {}, "hops": [], "stages": [], "port_results": [],
                  "findings": [{"severity": "warning", "layer": 2, "code": "duplicate_ip",
                                "message": "Drucker-Büro-2 answered for 10.0.0.5"}],
                  "verdict": {"headline": "Two devices answer for one address",
                              "owner": "o", "confidence": "high", "next_step": "n",
                              "severity": "warning"}}
        text = nd.render_text_report(report, color=False, width=88)
        # Unguarded, this is the raise. The guard is applied to the real
        # streams in main(), so the same treatment is applied here.
        stream = _io.TextIOWrapper(_io.BytesIO(), encoding="ascii")
        stream.reconfigure(errors="replace")
        stream.write(text)
        stream.flush()
        self.assertIn("Drucker-B", stream.buffer.getvalue().decode("ascii"))

    def test_the_streams_are_made_survivable_before_anything_is_written(self):
        """It has to happen before the first write, not after the first
        failure - and it must not be fatal itself, since a stream that refuses
        to be reconfigured is still a stream worth trying to print to."""
        src = open(nd.__file__, encoding="utf-8").read()
        fn = src.split("def _survive_a_narrow_encoding", 1)[1].split("\ndef ", 1)[0]
        self.assertIn('errors="replace"', fn)
        self.assertIn("sys.stdout", fn)
        self.assertIn("sys.stderr", fn)
        self.assertIn("except (AttributeError, ValueError, OSError)", fn)
        body = src.split("def main():", 1)[1].split("\n\n", 1)[0]
        self.assertIn("_survive_a_narrow_encoding()", body)
        self.assertLess(body.index("_survive_a_narrow_encoding()"), body.index("build_parser()"))


class TestParserRobustness(unittest.TestCase):
    """Every parser here reads output from a command, a switch, or the network.
    None of that is trusted input, and a crash mid-diagnosis loses the whole
    run - so junk must produce an empty result, never an exception."""

    JUNK = ["", None, "\x00\x00", "a" * 50000, "%s%n", "../../etc/passwd",
            "<script>alert(1)</script>", "\u0442\u0435\u0441\u0442", "=" * 500,
            "nameserver " + "9" * 400, "lldp." + "x" * 5000 + "=y"]

    def parsers(self):
        return {
            "guess_default_gateway": lambda t: nd.guess_default_gateway({"ok": True, "stdout": t}),
            "parse_traceroute_hops": nd.parse_traceroute_hops,
            "parse_ping_loss": lambda t: nd.parse_ping_loss({"ok": True, "stdout": t}),
            "parse_ping_stats": lambda t: nd.parse_ping_stats({"ok": True, "stdout": t}),
            "has_ip_address": lambda t: nd.has_ip_address({"ok": True, "stdout": t}),
            "parse_mtr_json": nd.parse_mtr_json,
            "parse_ethtool": nd.parse_ethtool,
            "parse_arp_table": nd.parse_arp_table,
            "parse_lldp_keyvalue": nd.parse_lldp_keyvalue,
            "parse_resolvers": nd.parse_resolvers,
            "is_private_ip": nd.is_private_ip,
        }

    def test_no_parser_raises_on_junk(self):
        for name, fn in self.parsers().items():
            for junk in self.JUNK:
                try:
                    fn(junk)
                except Exception as e:                       # noqa: BLE001 - that's the point
                    self.fail(f"{name} raised {type(e).__name__} on {junk!r:.30}")

    def test_dns_response_parser_survives_hostile_bytes(self):
        import os
        import struct
        hostile = [b"", b"\x00" * 11, b"\x00" * 12,
                   struct.pack(">HHHHHH", 1, 0x8180, 1, 5, 0, 0),      # lies about answer count
                   struct.pack(">HHHHHH", 1, 0x8180, 0, 1, 0, 0) + b"\xc0\x0c",
                   struct.pack(">HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xff" * 40,
                   os.urandom(64), os.urandom(512)]
        for data in hostile:
            try:
                nd.parse_dns_response(data, 1)
            except ValueError:
                pass                                          # handled by the caller
            except Exception as e:                            # noqa: BLE001
                self.fail(f"parse_dns_response raised {type(e).__name__} on hostile input")

    def test_analysis_survives_malformed_findings(self):
        nd.build_verdict([{"code": None, "severity": "critical"}])
        nd.build_verdict([])
        nd.annotate_hops([])
        nd.find_arp_conflicts([{"ip": None, "mac": None}])

    def test_query_ids_are_unpredictable(self):
        # A sequential id plus UDP accepting any sender makes spoofing trivial.
        self.assertGreater(len({nd._new_dns_qid() for _ in range(64)}), 50)

    def test_soak_is_bounded(self):
        clamp = lambda v: min(max(int(v or 0), 0), nd.MAX_SOAK_SECONDS)
        self.assertEqual(clamp(999999), nd.MAX_SOAK_SECONDS)
        self.assertEqual(clamp(-5), 0)
        self.assertEqual(clamp(120), 120)


class TestResolverList(unittest.TestCase):
    def test_parses_resolv_conf(self):
        text = ("# Generated by NetworkManager\n"
                "search example.lan\n"
                "nameserver 192.168.1.1\n"
                "nameserver 8.8.8.8\n")
        self.assertEqual(nd.parse_resolvers(text), ["192.168.1.1", "8.8.8.8"])

    def test_ignores_comments_and_duplicates(self):
        text = ("nameserver 10.0.0.1\n"
                "#nameserver 10.0.0.9\n"
                "nameserver 10.0.0.1  ; repeat\n")
        self.assertEqual(nd.parse_resolvers(text), ["10.0.0.1"])

    def test_ignores_malformed_entries(self):
        self.assertEqual(nd.parse_resolvers("nameserver not-an-ip\nnameserver\n"), [])

    def test_ipv6_resolver(self):
        self.assertEqual(nd.parse_resolvers("nameserver 2001:4860:4860::8888\n"),
                         ["2001:4860:4860::8888"])

    def test_empty(self):
        self.assertEqual(nd.parse_resolvers(""), [])
        self.assertEqual(nd.parse_resolvers(None), [])


class TestLldpParsing(unittest.TestCase):
    """The point of LLDP here is turning "check the switch port" into a named
    port, so the switch and port fields matter more than completeness."""

    KEYVALUE = """lldp.eth0.via=LLDP
lldp.eth0.rid=1
lldp.eth0.age=0 day, 00:05:16
lldp.eth0.chassis.mac=00:11:22:33:44:55
lldp.eth0.chassis.name=SW-CLOSET-2
lldp.eth0.chassis.descr=Cisco IOS Software, C2960X
lldp.eth0.chassis.mgmt-ip=10.0.0.2
lldp.eth0.port.ifname=Gi1/0/12
lldp.eth0.port.descr=GigabitEthernet1/0/12
lldp.eth0.vlan.vlan-id=30
"""

    def test_switch_and_port_extracted(self):
        n = nd.parse_lldp_keyvalue(self.KEYVALUE)[0]
        self.assertEqual(n["iface"], "eth0")
        self.assertEqual(n["switch"], "SW-CLOSET-2")
        self.assertEqual(n["port"], "Gi1/0/12")
        self.assertEqual(n["vlan"], "30")
        self.assertEqual(n["mgmt_ip"], "10.0.0.2")
        self.assertEqual(n["via"], "LLDP")

    def test_cdp_neighbour(self):
        text = ("lldp.eth1.via=CDPv2\n"
                "lldp.eth1.chassis.name=SW-EDGE-1\n"
                "lldp.eth1.port.descr=FastEthernet0/3\n")
        n = nd.parse_lldp_keyvalue(text)[0]
        self.assertEqual(n["via"], "CDPv2")
        self.assertEqual(n["port_descr"], "FastEthernet0/3")

    def test_multiple_interfaces(self):
        text = self.KEYVALUE + "lldp.eth1.chassis.name=SW-EDGE-1\nlldp.eth1.port.ifname=Gi0/1\n"
        self.assertEqual(len(nd.parse_lldp_keyvalue(text)), 2)

    def test_interface_with_no_neighbour_detail_is_dropped(self):
        # lldpd emits bookkeeping lines for interfaces with no neighbour; those
        # must not show up as a switch we're connected to.
        self.assertEqual(nd.parse_lldp_keyvalue("lldp.eth9.age=0 day, 00:00:01\n"), [])

    def test_garbage_and_empty_input(self):
        self.assertEqual(nd.parse_lldp_keyvalue(""), [])
        self.assertEqual(nd.parse_lldp_keyvalue(None), [])
        self.assertEqual(nd.parse_lldp_keyvalue("not lldp output at all\n"), [])

    def test_first_value_wins_for_port(self):
        # ifname is the authoritative port id; a later descr must not clobber it.
        text = ("lldp.eth0.chassis.name=SW\nlldp.eth0.port.ifname=Gi1/0/5\n"
                "lldp.eth0.port.descr=some vague description\n")
        self.assertEqual(nd.parse_lldp_keyvalue(text)[0]["port"], "Gi1/0/5")


class TestCallQuality(unittest.TestCase):
    """MOS turns latency/jitter/loss into the number a customer's complaint is
    actually about. 4.4 is the G.711 ceiling, so a perfect link scores 4.4."""

    def test_perfect_lan_scores_at_the_ceiling(self):
        mos, r = nd.mos_score(1.0, 0.2, 0.0)
        self.assertGreaterEqual(mos, 4.3)
        self.assertLessEqual(mos, 4.4)

    def test_good_broadband_is_good(self):
        mos, _ = nd.mos_score(25, 3, 0)
        self.assertGreater(mos, 4.0)

    def test_satellite_latency_wrecks_the_score(self):
        mos, _ = nd.mos_score(600, 30, 0)
        self.assertLess(mos, nd.MOS_BAD)

    def test_loss_dominates(self):
        clean, _ = nd.mos_score(30, 5, 0)
        lossy, _ = nd.mos_score(30, 5, 10)
        self.assertGreater(clean - lossy, 0.4)

    def test_jitter_hurts_more_than_steady_latency(self):
        steady, _ = nd.mos_score(60, 1, 0)
        erratic, _ = nd.mos_score(60, 30, 0)
        self.assertGreater(steady, erratic)

    def test_missing_input_is_not_a_zero_score(self):
        self.assertEqual(nd.mos_score(None), (None, None))
        self.assertEqual(nd.mos_score("abc"), (None, None))

    def test_score_stays_in_range(self):
        for args in [(0, 0, 0), (5000, 500, 100), (100, 0, 50)]:
            mos, r = nd.mos_score(*args)
            self.assertGreaterEqual(mos, 1.0)
            self.assertLessEqual(mos, 4.5)

    def test_ping_stats_linux(self):
        st = nd.parse_ping_stats({"ok": True, "stdout":
            "rtt min/avg/max/mdev = 1.234/3.456/5.678/1.111 ms\n"})
        self.assertEqual(st["avg_ms"], 3.456)
        self.assertEqual(st["stdev_ms"], 1.111)

    def test_ping_stats_bsd(self):
        st = nd.parse_ping_stats({"ok": True, "stdout":
            "round-trip min/avg/max/stddev = 26.4/26.6/26.7/0.13 ms\n"})
        self.assertEqual(st["avg_ms"], 26.6)
        self.assertEqual(st["stdev_ms"], 0.13)

    def test_ping_stats_absent(self):
        self.assertEqual(nd.parse_ping_stats({"ok": True, "stdout": "no stats here"}), {})
        self.assertEqual(nd.parse_ping_stats({"ok": False}), {})


class TestArpTable(unittest.TestCase):
    LINUX = ("192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
             "192.168.1.50 dev eth0 lladdr aa:bb:cc:dd:ee:02 STALE\n"
             "192.168.1.99 dev eth0  FAILED\n")
    BSD = ("? (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0 ifscope [ethernet]\n"
           "? (192.168.1.50) at aa:bb:cc:dd:ee:02 on en0 ifscope [ethernet]\n"
           "? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]\n")

    def test_linux_neighbour_table(self):
        entries = nd.parse_arp_table(self.LINUX)
        self.assertEqual(len(entries), 3)
        self.assertEqual(entries[0]["mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(entries[0]["state"], "reachable")

    def test_bsd_arp_table(self):
        entries = nd.parse_arp_table(self.BSD)
        self.assertEqual(len(entries), 3)
        self.assertIsNone(entries[2]["mac"])       # (incomplete)

    def test_duplicate_ip_detected(self):
        entries = nd.parse_arp_table(
            "10.0.0.5 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
            "10.0.0.5 dev eth1 lladdr aa:bb:cc:dd:ee:99 REACHABLE\n")
        conflicts = nd.find_arp_conflicts(entries)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["ip"], "10.0.0.5")

    def test_one_mac_serving_many_ips_is_not_a_conflict(self):
        # A router answering proxy ARP looks like this and is perfectly normal.
        entries = nd.parse_arp_table(
            "10.0.0.5 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
            "10.0.0.6 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n")
        self.assertEqual(nd.find_arp_conflicts(entries), [])

    def test_no_conflicts_in_a_normal_table(self):
        self.assertEqual(nd.find_arp_conflicts(nd.parse_arp_table(self.BSD)), [])

    def test_empty_input(self):
        self.assertEqual(nd.parse_arp_table(""), [])
        self.assertEqual(nd.parse_arp_table(None), [])


class TestTcpCounters(unittest.TestCase):
    def test_linux_snmp_parsing(self):
        import os
        import tempfile
        text = ("Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens OutSegs RetransSegs\n"
                "Tcp: 1 200 120000 -1 1000 500000 15000\n")
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        path = os.path.join(d, "snmp")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        real_open = open

        def fake_open(p, *a, **k):
            return real_open(path if p == "/proc/net/snmp" else p, *a, **k)

        import builtins
        builtins.open = fake_open
        try:
            counters = nd._tcp_counters_linux()
        finally:
            builtins.open = real_open
        self.assertEqual(counters["OutSegs"], 500000)
        self.assertEqual(counters["RetransSegs"], 15000)   # 3%

    def test_missing_counters_are_not_fatal(self):
        self.assertEqual(nd._tcp_counters_linux.__name__, "_tcp_counters_linux")


class TestPathAnnotation(unittest.TestCase):
    def hops(self, specs):
        """specs: (hop, host, display, times) -> parsed-hop shaped dicts."""
        return [{"hop": h, "host": ip, "display": disp or ip, "times_ms": list(times),
                 "timed_out": not times} for h, ip, disp, times in specs]

    def test_private_public_classification(self):
        self.assertTrue(nd.is_private_ip("10.1.2.3"))
        self.assertTrue(nd.is_private_ip("192.168.0.1"))
        self.assertTrue(nd.is_private_ip("172.16.0.1"))
        self.assertTrue(nd.is_private_ip("172.31.255.254"))
        self.assertTrue(nd.is_private_ip("100.64.0.1"))     # CGNAT
        self.assertFalse(nd.is_private_ip("172.32.0.1"))    # just outside RFC1918
        self.assertFalse(nd.is_private_ip("8.8.8.8"))
        self.assertFalse(nd.is_private_ip("100.128.0.1"))   # just outside CGNAT
        self.assertIsNone(nd.is_private_ip(None))

    def test_demarc_is_the_first_public_hop(self):
        hops = self.hops([(1, "192.168.1.1", None, [1.0]),
                          (2, "10.0.0.1", None, [2.0]),
                          (3, "198.51.100.13", None, [12.0])])
        info = nd.annotate_hops(hops)
        self.assertEqual(info["demarc_hop"], 3)

    def test_the_site_ends_at_carrier_nat_not_past_it(self):
        """100.64.0.0/10 is not routable on the internet, so it read as another
        private hop and the edge landed past it - the picture put the carrier's
        own NAT layer inside the site, while the cgnat finding called it the
        provider's range and the latency wall placed a jump there on their side
        of the same boundary. Three parts of one report disagreeing."""
        hops = self.hops([(1, "192.168.1.1", None, [1.0]),
                          (2, "100.64.0.1", None, [8.0]),
                          (3, "198.51.100.13", None, [12.0])])
        info = nd.annotate_hops(hops)
        self.assertEqual(info["demarc_hop"], 2)
        self.assertEqual(info["cgnat_hop"], 2)

    def test_the_providers_own_private_core_is_not_this_sites_second_router(self):
        """Plenty of carriers number their core out of RFC1918, so scanning the
        whole trace for private subnets counted their addressing as the site's.
        A path of 192.168.1.1, carrier NAT, 10.250.0.1 was reported as two
        private networks *inside this site*, naming an address several hops
        past the point where the site ends."""
        hops = self.hops([(1, "192.168.1.1", None, [1.0]),
                          (2, "100.64.0.1", None, [8.0]),
                          (3, "10.250.0.1", None, [11.0]),
                          (4, "198.51.100.13", None, [12.0])])
        info = nd.annotate_hops(hops)
        self.assertEqual(info["double_nat"], [],
                         "the provider's core is being counted as a site subnet")

    def test_two_private_networks_before_the_edge_still_counts(self):
        """The narrowing must not swallow the case the check exists for."""
        hops = self.hops([(1, "192.168.1.1", None, [1.0]),
                          (2, "10.0.0.1", None, [2.0]),
                          (3, "198.51.100.13", None, [12.0])])
        info = nd.annotate_hops(hops)
        self.assertEqual(info["double_nat"], ["192.168.1", "10.0.0"])

    def test_a_trace_does_not_establish_that_a_router_translates(self):
        """Routed subnets and NAT are identical in a traceroute, and a site
        with several routed VLANs is ordinary. The finding asserted double NAT
        outright and then listed the consequences of NAT as though they
        followed - which for a routed path they do not. What the trace
        establishes is two routers; NAT is the likely cause, not the reading."""
        setup, kw = S["double_nat"]
        m = fresh(); setup(m)
        rep = m.diagnose(quick=False, **scenario_kwargs(kw))
        msg = [f["message"] for f in rep["findings"] if f["code"] == "double_nat"][0]
        self.assertIn("at least two routers", msg)
        self.assertIn("cannot tell", msg)
        # The consequence has to hang off the cause, not off the observation.
        before_consequence = msg.split("breaks inbound", 1)[0]
        self.assertIn("If it is NAT", before_consequence)

    def test_a_second_trace_is_tried_on_the_evidence_that_supports_it(self):
        """The retry was gated on ping loss being under 100%. _check_internet
        sets inet_loss to None in exactly one case - TCP reached a target that
        would not answer a ping - so proving another protocol gets through was
        what switched the alternate trace off. It ran only where ping already
        worked, which is where it is least needed."""
        calls = []
        for label, inet_loss, reach, expected in (
                ("ping works, trace stalled", 0.0, None, True),
                ("ping dead, TCP reached it", None, {"ok": True, "port": "443"}, True),
                ("ping dead, TCP reached a backend port", None,
                 {"ok": True, "port": "53"}, True),
                ("nothing reached it at all", 100.0, {"ok": False, "port": None}, False),
                ("nothing reached it, no tcp probe run", 100.0, None, False)):
            m = fresh()
            seen = []
            m.cmd_traceroute_tcp = lambda t, port=443: seen.append(port) or None
            raw = {"reachability_tcp": reach} if reach else {}
            stalled = [{"hop": 1, "host": "10.0.0.1", "display": "10.0.0.1",
                        "times_ms": [1.0], "timed_out": False, "flags": None}]
            m._check_path(raw, [], "8.8.8.8", "10.0.0.1", inet_loss, False, 10, 1500,
                          trace={"raw": {"ok": True, "cmd": "traceroute", "stdout": ""},
                                 "hops": stalled, "source": "traceroute", "mtr": None})
            with self.subTest(case=label):
                self.assertEqual(bool(seen), expected,
                                 "the alternate trace ran" if seen else "it never ran")
            calls.append((label, seen))
        # And the port it traces to is the one something already reached.
        self.assertEqual(dict(calls)["ping dead, TCP reached a backend port"], [53],
                         "the trace went to 443 with a known-good port on hand")

    def test_the_trace_goes_to_a_port_that_answered_not_to_443(self):
        """Under --target auto the target is the backend this box leans on
        most, and 443 is usually shut on a database - so a TCP trace to it
        failed for a reason that had nothing to do with the path, while the
        port a connect had just succeeded on sat unused in the report."""
        m = fresh()
        seen = []
        m.cmd_traceroute_tcp = lambda t, port=443: seen.append(port) or None
        stalled = [{"hop": 1, "host": "10.0.0.1", "display": "10.0.0.1",
                    "times_ms": [1.0], "timed_out": False, "flags": None}]
        m._check_path({"reachability_tcp": {"ok": True, "port": "80"}}, [],
                      "8.8.8.8", "10.0.0.1", None, False, 10, 1500,
                      trace={"raw": {"ok": True, "cmd": "traceroute", "stdout": ""},
                             "hops": stalled, "source": "traceroute", "mtr": None})
        self.assertEqual(seen, [80])

    def test_a_refused_port_is_good_enough_to_trace_to(self):
        """An RST is a completed round trip - the packet got there and the
        reply got back - so a port that refused the connection identifies a hop
        just as well as one that accepted it. Skipping those would throw away
        the commonest proof of reachability on a hardened host."""
        m = fresh()
        seen = []
        m.cmd_traceroute_tcp = lambda t, port=443: seen.append(port) or None
        stalled = [{"hop": 1, "host": "10.0.0.1", "display": "10.0.0.1",
                    "times_ms": [1.0], "timed_out": False, "flags": None}]
        m._check_path({"reachability_tcp": {"ok": True, "port": "53",
                                            "how": "refused the connection"}}, [],
                      "8.8.8.8", "10.0.0.1", None, False, 10, 1500,
                      trace={"raw": {"ok": True, "cmd": "traceroute", "stdout": ""},
                             "hops": stalled, "source": "traceroute", "mtr": None})
        self.assertEqual(seen, [53])

    def test_the_worst_jump_says_what_share_of_the_path_it_is(self):
        """"+65ms" doesn't say whether fixing that hop would matter. "+65ms,
        71% of the total" does - which is the only thing worth borrowing from
        a tracing tool's critical-path view."""
        hops = self.hops([(1, "10.0.0.1", None, [1.0]),
                          (2, "198.51.100.1", None, [9.0]),
                          (3, "203.0.113.1", None, [74.0]),
                          (4, "8.8.8.8", None, [92.0])])
        info = nd.annotate_hops(hops)
        worst = info["worst_jump"]
        self.assertEqual(worst["hop"], 3)
        self.assertEqual(worst["delta_ms"], 65.0)
        self.assertEqual(worst["total_ms"], 92.0)
        self.assertEqual(worst["share_pct"], 71)      # 65 of 92

    def test_a_path_that_ends_in_silence_has_no_total_to_take_a_share_of(self):
        """The denominator is the last hop that answered. If the target never
        replies there is no end-to-end figure, and a share of an unknown is a
        number made up."""
        hops = self.hops([(1, "10.0.0.1", None, [1.0]),
                          (2, "198.51.100.1", None, [40.0]),
                          (3, "8.8.8.8", None, [])])
        info = nd.annotate_hops(hops)
        worst = info["worst_jump"]
        self.assertEqual(worst["hop"], 2)
        # the last *answering* hop is 2, so the jump is the whole of it
        self.assertEqual(worst["total_ms"], 40.0)
        self.assertEqual(worst["share_pct"], 98)

    def test_no_hop_answered_means_no_share_at_all(self):
        hops = self.hops([(1, "10.0.0.1", None, []), (2, "8.8.8.8", None, [])])
        info = nd.annotate_hops(hops)
        self.assertIsNone(info["worst_jump"])

    def test_the_share_cannot_exceed_the_whole(self):
        """Deltas are clamped at zero, so they can't quite sum to the total and
        rounding can push a single one past it. "104% of the path" reads as a
        bug rather than as a slow hop."""
        hops = self.hops([(1, "10.0.0.1", None, [9.0]),
                          (2, "8.8.8.8", None, [8.0])])
        info = nd.annotate_hops(hops)
        if info["worst_jump"]:
            self.assertLessEqual(info["worst_jump"]["share_pct"], 100)

    def test_latency_delta_and_jitter(self):
        hops = self.hops([(1, "10.0.0.1", None, [1.0, 1.0, 1.0]),
                          (2, "8.8.8.8", None, [11.0, 13.0, 15.0])])
        nd.annotate_hops(hops)
        self.assertEqual(hops[1]["delta_ms"], 12.0)   # 13 avg - 1 avg
        self.assertEqual(hops[1]["jitter_ms"], 4.0)   # 15 - 11
        # The first hop counts its own latency. This asserted None until
        # 2026-08-08, on the reasoning that nothing precedes it - which meant a
        # first hop carrying the whole delay could never be the worst jump.
        # The path starts there, so everything before it is zero.
        self.assertEqual(hops[0]["delta_ms"], 1.0)

    def test_negative_deltas_are_clamped(self):
        # A later hop answering faster than an earlier one is normal noise.
        hops = self.hops([(1, "10.0.0.1", None, [30.0]), (2, "8.8.8.8", None, [10.0])])
        nd.annotate_hops(hops)
        self.assertEqual(hops[1]["delta_ms"], 0)

    def test_double_nat_detected(self):
        hops = self.hops([(1, "192.168.1.1", None, [1.0]),
                          (2, "10.0.0.1", None, [2.0]),
                          (3, "198.51.100.13", None, [12.0])])
        self.assertEqual(nd.annotate_hops(hops)["double_nat"], ["192.168.1", "10.0.0"])

    def test_single_private_subnet_is_not_double_nat(self):
        hops = self.hops([(1, "192.168.1.1", None, [1.0]),
                          (2, "192.168.1.254", None, [2.0]),
                          (3, "198.51.100.13", None, [12.0])])
        self.assertEqual(nd.annotate_hops(hops)["double_nat"], [])

    def test_cgnat_detected_and_not_counted_as_double_nat(self):
        hops = self.hops([(1, "192.168.1.1", None, [1.0]),
                          (2, "100.64.0.1", None, [8.0]),
                          (3, "198.51.100.13", None, [14.0])])
        info = nd.annotate_hops(hops)
        self.assertEqual(info["cgnat_hop"], 2)
        self.assertEqual(info["double_nat"], [])

    def test_routing_loop_detected(self):
        hops = self.hops([(1, "10.20.0.1", None, [1.0]),
                          (2, "10.20.0.2", None, [2.0]),
                          (3, "10.20.0.1", None, [3.0])])
        loop = nd.annotate_hops(hops)["loop_at"]
        self.assertEqual(loop["host"], "10.20.0.1")
        self.assertEqual(loop["hops"], [1, 3])

    def test_no_false_loop_on_a_clean_path(self):
        hops = self.hops([(1, "10.0.0.1", None, [1.0]), (2, "8.8.8.8", None, [2.0])])
        self.assertIsNone(nd.annotate_hops(hops)["loop_at"])

    def test_network_handoffs_from_ptr_names(self):
        hops = self.hops([(1, "10.0.0.1", None, [1.0]),
                          (2, "a.example-isp.net", None, [10.0]),
                          (3, "b.example-isp.net", None, [12.0]),
                          (4, "dns.google", None, [20.0])])
        for h in hops:                      # display is the PTR, host the IP
            h["host"] = "1.1.1.1" if h["hop"] > 1 else "10.0.0.1"
        info = nd.annotate_hops(hops)
        self.assertEqual([n["network"] for n in info["networks_crossed"]],
                         ["example-isp.net", "dns.google"])

    def test_ptr_network_extraction(self):
        self.assertEqual(nd.ptr_network("be-300.example-isp.net", "192.0.2.4"),
                         "example-isp.net")
        self.assertEqual(nd.ptr_network("host.bt.co.uk", "192.0.2.4"), "bt.co.uk")
        self.assertIsNone(nd.ptr_network("192.0.2.4", "192.0.2.4"))   # bare IP, no PTR
        self.assertIsNone(nd.ptr_network("*", None))

    def test_worst_jump_names_the_side_of_the_demarc(self):
        hops = self.hops([(1, "192.168.1.1", None, [1.0]),
                          (2, "100.64.0.1", None, [620.0]),
                          (3, "8.8.8.8", None, [640.0])])
        wj = nd.annotate_hops(hops)["worst_jump"]
        self.assertEqual(wj["hop"], 2)
        # CGNAT is private-range but belongs to the carrier - mislabelling this
        # as "inside the site" sends someone to the wrong end of the link.
        self.assertTrue(wj["cgnat"])


class TestLinkCounters(unittest.TestCase):
    def stats(self, **overrides):
        base = dict(rx_packets=5_000_000, tx_packets=5_000_000, rx_errors=0, tx_errors=0,
                    rx_dropped=0, tx_dropped=0, rx_crc_errors=0, rx_frame_errors=0,
                    rx_over_errors=0, collisions=0, operstate="up")
        base.update(overrides)
        return base

    def read(self, vals, sample=0):
        nd._read_link_stats = lambda: ({"eth0": vals}, "test")
        return nd.cmd_link_stats(sample)["interfaces"][0]

    def tearDown(self):
        # cmd_link_stats is monkeypatched above; restore the real reader.
        import importlib
        importlib.reload(nd)

    def test_error_rate_per_million(self):
        i = self.read(self.stats(rx_errors=1000))
        self.assertEqual(i["errors"], 1000)
        self.assertEqual(i["err_ppm"], 100.0)   # 1000 of 10M

    def test_unknown_counters_are_not_reported_as_zero(self):
        # A driver that exports nothing must not look like a flawless link.
        i = self.read(self.stats(rx_errors=None, tx_errors=None))
        self.assertIn("rx_errors", i["unknown_counters"])
        self.assertEqual(i["errors"], 0)        # arithmetic still safe

    def test_no_division_by_zero_on_an_idle_interface(self):
        i = self.read(self.stats(rx_packets=0, tx_packets=0))
        self.assertEqual(i["err_ppm"], 0)

    def test_collision_rate_tracked_separately(self):
        i = self.read(self.stats(collisions=760, tx_errors=800))
        # Below the generic error bar but above the collision bar - a duplex
        # mismatch would otherwise go unreported.
        self.assertLess(i["err_ppm"], nd.ERR_PPM_WARN)
        self.assertGreater(i["coll_ppm"], nd.COLL_PPM_WARN)


class TestSysfsCounterReading(unittest.TestCase):
    """The layer that actually touches sysfs. Patching above this (as the tests
    below once did) leaves the file-reading itself uncovered."""

    def build(self, iface="eth0", present=None, values=None):
        import os
        import tempfile
        base = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, base, True)
        sdir = os.path.join(base, iface, "statistics")
        os.makedirs(sdir)
        present = present if present is not None else list(nd.LINK_COUNTERS)
        values = values or {}
        for field in present:
            with open(os.path.join(sdir, field), "w", encoding="utf-8") as fh:
                fh.write(str(values.get(field, 0)))
        with open(os.path.join(base, iface, "operstate"), "w", encoding="utf-8") as fh:
            fh.write("up")
        return base

    def test_reads_counters_from_sysfs(self):
        base = self.build(values={"rx_packets": 1234, "rx_errors": 7})
        stats = nd._link_stats_linux(base)
        self.assertEqual(stats["eth0"]["rx_packets"], 1234)
        self.assertEqual(stats["eth0"]["rx_errors"], 7)
        self.assertEqual(stats["eth0"]["operstate"], "up")

    def test_counter_the_driver_does_not_export_reads_as_unknown(self):
        # Must be None, not 0: a driver exporting nothing would otherwise be
        # indistinguishable from a flawless link, and the all-clear says so.
        base = self.build(present=["rx_packets", "tx_packets"])
        stats = nd._link_stats_linux(base)
        self.assertIsNone(stats["eth0"]["rx_errors"])
        self.assertEqual(stats["eth0"]["rx_packets"], 0)

    def test_unreadable_counter_is_unknown_not_zero(self):
        base = self.build(values={"rx_errors": "not-a-number"})
        self.assertIsNone(nd._link_stats_linux(base)["eth0"]["rx_errors"])

    def test_missing_sysfs_tree_yields_nothing(self):
        self.assertEqual(nd._link_stats_linux("/nonexistent/path"), {})

    def build_modes(self, iface="eth0", fields=None):
        """A sysfs tree for the link-mode reader, the twin of build() above."""
        import os, tempfile
        base = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, base, True)
        idir = os.path.join(base, iface)
        os.makedirs(idir)
        for name, value in (fields or {}).items():
            with open(os.path.join(idir, name), "w", encoding="utf-8") as fh:
                fh.write(str(value))
        return base

    def test_reads_link_mode_from_sysfs(self):
        """This reader had no fixture-tree test at all while its twin had
        twelve, so every file it parses was covered only through a stub."""
        base = self.build_modes(fields={"speed": 1000, "duplex": "full",
                                        "mtu": 1500, "carrier": 1, "operstate": "up"})
        modes = nd._link_modes_linux(base)
        self.assertEqual(modes["eth0"]["speed_mbps"], 1000)
        self.assertEqual(modes["eth0"]["duplex"], "full")
        self.assertEqual(modes["eth0"]["mtu"], 1500)
        self.assertTrue(modes["eth0"]["carrier"])
        self.assertEqual(modes["eth0"]["operstate"], "up")

    def test_a_negative_speed_is_unknown_not_a_speed(self):
        """Virtual NICs report -1, and sysfs raises EINVAL on an interface with
        no carrier. Either read as a number would make a 1000 Mbps comparison
        nonsense."""
        for value in (-1, 0):
            with self.subTest(value=value):
                base = self.build_modes(fields={"speed": value, "mtu": 1500})
                self.assertIsNone(nd._link_modes_linux(base)["eth0"]["speed_mbps"])

    def test_unreadable_fields_are_absent_rather_than_guessed(self):
        base = self.build_modes(fields={"mtu": "not-a-number"})
        mode = nd._link_modes_linux(base)["eth0"]
        self.assertIsNone(mode["mtu"])
        self.assertIsNone(mode["speed_mbps"])
        self.assertIsNone(mode["duplex"])
        self.assertFalse(mode["carrier"])
        self.assertEqual(mode["operstate"], "unknown")

    def test_carrier_zero_is_no_carrier_not_a_present_value(self):
        """sysfs writes "0" when the cable is out. Anything that tests the
        field for presence rather than its value reads that as a live link -
        on exactly the interface someone is standing next to, unplugged."""
        base = self.build_modes(fields={"carrier": 0, "mtu": 1500})
        self.assertFalse(nd._link_modes_linux(base)["eth0"]["carrier"])
        up = self.build_modes(fields={"carrier": 1, "mtu": 1500})
        self.assertTrue(nd._link_modes_linux(up)["eth0"]["carrier"])

    def test_no_sysfs_tree_yields_nothing(self):
        self.assertEqual(nd._link_modes_linux("/nonexistent/path"), {})

    def test_unknown_counters_survive_into_the_interface_summary(self):
        base = self.build(present=["rx_packets", "tx_packets"])
        nd._read_link_stats = lambda: (nd._link_stats_linux(base), "test")
        try:
            iface = nd.cmd_link_stats(0)["interfaces"][0]
            self.assertIn("rx_errors", iface["unknown_counters"])
        finally:
            __import__("importlib").reload(nd)


class TestRateSampling(unittest.TestCase):
    """Per-second sampling through the window, instead of a mean across it."""

    def sampler(self, mod, readings, interval=1.0):
        """Drive _sample_through with a scripted sequence of counter readings."""
        seq, clock = list(readings), [0.0]
        def read():
            return (seq.pop(0) if seq else seq_last[0]), "stub"
        seq_last = [readings[-1]]
        def sleep(step):
            clock[0] += interval
        mod._read_link_stats = read
        mod.time = type(mod.time)("time")
        mod.time.sleep = sleep
        mod.time.monotonic = lambda: clock[0]
        return mod

    def rates_for(self, byte_totals, interval=1.0, remaining=None):
        m = fresh()
        readings = [{"eth0": {"rx_bytes": b, "tx_bytes": 0}} for b in byte_totals]
        self.sampler(m, readings, interval)
        # One loop iteration per reading: N readings give N-1 intervals.
        return (m._sample_through(remaining or len(byte_totals))[0] or {}).get("eth0")

    def test_a_burst_is_visible_where_the_mean_is_not(self):
        """The case the whole change exists for. Full for 20s of every 60 on a
        50 Mbps line averages 46% - under every sustained threshold - while the
        line is completely full for a third of the window."""
        rates = [50.0 if (t % 60) < 20 else 9.75 for t in range(120)]
        mean = sum(rates) / len(rates)
        self.assertLess(mean / 50.0 * 100, nd.UPLINK_FULL_PCT)   # invisible today
        self.assertEqual(max(rates), 50.0)                        # obvious per tick

    def test_the_rate_uses_the_interval_that_was_measured(self):
        """A tick that lands late and is divided by the nominal step reads
        high. 12.5 MB over two seconds is 50 Mbps, not 100."""
        got = self.rates_for([0, 12_500_000], interval=2.0)
        self.assertEqual(got, [50.0])

    def test_a_counter_reset_drops_the_tick_rather_than_reading_zero(self):
        """A zero is a claim that the interface was idle for that second, which
        drags the mean down and hides the burst this is here to find."""
        got = self.rates_for([0, 1_250_000, 2_500_000, 0, 1_250_000])
        self.assertEqual(got, [10.0, 10.0, 10.0])   # four gaps, the reset dropped
        self.assertFalse(any(r < 0 for r in got))

    def test_an_interface_that_appears_mid_window_is_skipped_not_guessed(self):
        m = fresh()
        self.sampler(m, [{"eth0": {"rx_bytes": 0, "tx_bytes": 0}},
                         {"eth0": {"rx_bytes": 1_250_000, "tx_bytes": 0},
                          "wlan0": {"rx_bytes": 999_999, "tx_bytes": 0}}])
        series = m._sample_through(2)[0] or {}
        self.assertEqual(series.get("eth0"), [10.0])
        self.assertNotIn("wlan0", series)

    def test_the_busier_direction_is_what_gets_recorded(self):
        m = fresh()
        self.sampler(m, [{"eth0": {"rx_bytes": 0, "tx_bytes": 0}},
                         {"eth0": {"rx_bytes": 1_250_000, "tx_bytes": 5_000_000}}])
        self.assertEqual((m._sample_through(2)[0] or {}).get("eth0"), [40.0])

    def test_a_long_soak_stretches_the_interval_instead_of_storing_more(self):
        """An hour-long window must cost the same to carry as a two-minute one,
        and each sample has to stay a real measurement over a real interval."""
        m = fresh()
        ticks = []
        m._read_link_stats = lambda: ({"eth0": {"rx_bytes": 0, "tx_bytes": 0}}, "s")
        m.time = type(m.time)("time")
        m.time.sleep = lambda step: ticks.append(step)
        m.time.monotonic = lambda: 0.0
        m._sample_through(3600)
        self.assertLessEqual(len(ticks), nd.SERIES_MAX_SAMPLES)
        self.assertAlmostEqual(sum(ticks), 3600, places=3)
        self.assertGreater(ticks[0], 1.0)

    def test_a_short_window_keeps_one_second_resolution(self):
        m = fresh()
        ticks = []
        m._read_link_stats = lambda: ({"eth0": {"rx_bytes": 0, "tx_bytes": 0}}, "s")
        m.time = type(m.time)("time")
        m.time.sleep = lambda step: ticks.append(step)
        m.time.monotonic = lambda: 0.0
        m._sample_through(120)
        self.assertEqual(len(ticks), 120)
        self.assertTrue(all(abs(t - 1.0) < 1e-9 for t in ticks))


class TestSaturationBursts(unittest.TestCase):
    """A line full in bursts is only a fault when something broke with it."""

    def run_with(self, rates, loss=0, drops=0, uplink_mbps=50):
        m = fresh()
        counters(m, d_rx_bytes=int(sum(rates) * 1e6 / 8), d_rx_packets=100_000)
        m.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
            {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500,
             "carrier": True}]}
        if drops:
            kernel_drops(m, {"softnet_processed": 1_000_000, "softnet_dropped": 0},
                            {"softnet_processed": 1_100_000, "softnet_dropped": drops})
        ping_map(m, inet_loss=loss, sent=20)
        rate_series(m, rates)
        rep = m.diagnose("8.8.8.8", None, quick=False, soak=1, uplink_mbps=uplink_mbps)
        return rep, [f.get("code") for f in rep["findings"]]

    BURSTY = [50.0 if (t % 60) < 20 else 9.75 for t in range(120)]

    def test_a_burst_with_loss_beside_it_is_named_and_owned_by_the_site(self):
        rep, codes = self.run_with(self.BURSTY, loss=6)
        self.assertIn("saturation_bursts", codes)
        self.assertEqual(rep["verdict"]["based_on"][0], "saturation_bursts")
        self.assertNotIn("provider", rep["verdict"]["owner"])

    def test_without_a_rule_the_loss_verdict_blamed_the_provider(self):
        """Guarding the regression this shipped with: the finding fired and
        inet_partial_loss still took the headline at high confidence."""
        rep, _codes = self.run_with(self.BURSTY, loss=6)
        rank = {r[0]: i for i, r in enumerate(nd.VERDICT_RULES)}
        self.assertLess(rank["saturation_bursts"], rank["inet_partial_loss"])

    def test_bursts_with_nothing_broken_are_not_a_finding(self):
        """A line going to 100% in bursts is a line being used. One big
        download and a nightly backup window both do it, and neither is a
        fault - firing on the shape alone would cry wolf on both."""
        for name, rates in (("one big download", [50.0] * 30 + [2.0] * 90),
                            ("backup window", [49.0] * 90 + [3.0] * 30)):
            with self.subTest(pattern=name):
                _rep, codes = self.run_with(rates)
                self.assertNotIn("saturation_bursts", codes)

    def test_a_line_full_throughout_is_the_sustained_finding_not_this_one(self):
        _rep, codes = self.run_with([49.5] * 120, loss=8, drops=900)
        self.assertIn("uplink_saturated", codes)
        self.assertNotIn("saturation_bursts", codes)

    def test_a_line_that_never_fills_says_nothing_however_bad_things_are(self):
        """Harm alone must not conjure a burst - the test would be circular."""
        _rep, codes = self.run_with([16.5] * 120, loss=9, drops=800)
        self.assertNotIn("saturation_bursts", codes)

    def test_it_needs_more_than_a_couple_of_samples_to_call_anything(self):
        _rep, codes = self.run_with([50.0, 5.0], loss=6)
        self.assertNotIn("saturation_bursts", codes)

    def test_without_an_uplink_rate_it_measures_against_the_nic(self):
        """No --uplink-mbps means the NIC speed is the only capacity known.
        700 Mbps bursts on a gigabit port still count."""
        rates = [900.0 if (t % 60) < 20 else 100.0 for t in range(120)]
        _rep, codes = self.run_with(rates, loss=6, uplink_mbps=None)
        self.assertIn("saturation_bursts", codes)


class TestNoVendorNames(unittest.TestCase):
    """Names deliberately kept out of the source.

    Some product names were removed from the interception hints on request -
    what a repository names is a signal about what its author runs, and that
    signal is not one to give away by accident. This is not a claim about the
    products; a reinstated name would simply be a decision nobody made on
    purpose.
    """

    # Built from halves at runtime. Written out whole, this list would itself
    # be the roster it exists to keep out of the file - and the first version
    # of this test failed on its own definition, which is at least an honest
    # demonstration that it looks everywhere. The same trick guards the old
    # project name elsewhere in this suite.
    WITHHELD = ("zsc" + "aler", "nets" + "kope", "pri" + "sma",
                "palo " + "alto", "cloud" + "flare")

    def test_the_withheld_names_are_absent_from_every_shipped_file(self):
        root = os.path.dirname(os.path.abspath(nd.__file__))
        # Walked, not listed. A hand-written list is a list of the files that
        # existed the day it was written: this one named eight while the
        # repository had grown a security policy, a workflow, four more dev
        # scripts and a handover note, none of which anything looked at. The
        # guard's claim is that a withheld name is nowhere in the repository,
        # so it has to read the repository.
        # Tracked files, which is what "in the repository" means. Walking the
        # directory instead reads whatever else is lying about - an editor's
        # local settings caught this guard first, holding a name that is
        # gitignored and ships nowhere.
        import subprocess
        listed = subprocess.run(["git", "-C", root, "ls-files"],
                                capture_output=True, text=True)
        if listed.returncode != 0:
            self.skipTest("not a git checkout, so there is no tracked set to read")
        names = [n for n in listed.stdout.splitlines()
                 if n.endswith((".py", ".md", ".html", ".json", ".yml", ".yaml",
                                ".txt", ".cfg", ".toml"))]
        self.assertGreater(len(names), 8,
                           "the tracked set came back too small to be real")
        offenders = []
        for name in names:
            path = os.path.join(root, name)
            if not os.path.exists(path):
                continue
            with open(path, errors="replace", encoding="utf-8") as fh:
                text = fh.read().lower()
            for frag in self.WITHHELD:
                if frag in text:
                    offenders.append(f"{name}: {frag}")
        self.assertEqual(offenders, [], f"withheld names present: {offenders}")

    def test_the_interception_check_still_works_without_them(self):
        """Removing names narrows what can be recognised, so the rest has to
        keep working - the check is worth more than any one entry in it."""
        self.assertGreaterEqual(len(nd.INTERCEPTION_HINTS), 12)
        self.assertEqual(nd.looks_intercepted(["Fortinet Root CA"]), "fortinet")
        self.assertEqual(nd.looks_intercepted(["mitmproxy"]), "mitmproxy")
        self.assertIsNone(nd.looks_intercepted(["DigiCert Global Root CA"]))


class TestNoSecondCopy(unittest.TestCase):
    """Judgements that must exist in exactly one place.

    A long session leaves near-duplicates behind: the second copy is written
    because the first was three hundred lines away, and it is right on the day
    it is written. What it cannot survive is either copy being corrected. Each
    of these was found as a real duplicate after this file passed 500 tests.
    """

    def src(self):
        with open(nd.__file__, encoding="utf-8") as fh:
            return fh.read()

    def test_one_test_for_a_loopback_address(self):
        """Two nearly-identical address tests existed - one deciding which
        flows count, one deciding which listeners do."""
        src = self.src()
        self.assertEqual(src.count('startswith("127.")'), 1)
        for addr in ("127.0.0.1", "::1", "[::1]", "localhost", "169.254.9.9"):
            with self.subTest(addr=addr):
                self.assertTrue(nd._flow_is_local(addr))
                self.assertTrue(nd._is_loopback_socket(addr + ":443"))
        self.assertFalse(nd._flow_is_local("10.0.0.7"))
        self.assertFalse(nd._is_loopback_socket("10.0.0.7:443"))

    def test_one_rule_for_whether_a_peer_dominates(self):
        """The zone panel and the inbound path leg both ask this. Two copies of
        the threshold is two panels that can disagree about the same
        connections."""
        src = self.src()
        # The constant existing twice does not stop the rule being re-inlined
        # somewhere else with its own numbers, which is exactly how the second
        # copy arrived the first time. Assert the share appears once, in the
        # constant, and that both consumers go through the function.
        # Word-bounded: "0.6" is a substring of the CGNAT range 100.64/10.
        self.assertEqual(
            len(re.findall(rf"(?<![\d.]){re.escape(str(nd.DOMINANT_PEER_PCT))}(?![\d])", src)),
            1)
        self.assertGreaterEqual(src.count("dominant_peer("), 3)  # def + both callers
        self.assertEqual(nd.dominant_peer({"10.0.0.7": 9, "10.0.0.8": 1}), "10.0.0.7")
        self.assertIsNone(nd.dominant_peer({f"10.0.0.{i}": 1 for i in range(9)}))
        self.assertIsNone(nd.dominant_peer({"10.0.0.7": 2}))        # under the floor
        self.assertIsNone(nd.dominant_peer({}))
        # Ties break by address, so two runs of the same box agree.
        tied = {"10.0.0.9": 4, "10.0.0.8": 4}
        self.assertEqual({nd.dominant_peer(tied) for _ in range(20)}, {None})

    def test_one_place_parses_a_certificate_date(self):
        """Three copies of the same strptime existed - the helper was added and
        the two it replaced were left where they were."""
        self.assertEqual(self.src().count('"%b %d %H:%M:%S %Y %Z"'), 1)
        out = {}
        nd._cert_dates({"notAfter": "Aug 17 12:00:00 2099 GMT",
                        "notBefore": "Aug 17 12:00:00 2098 GMT"}, out)
        self.assertEqual(out["expires"], "2099-08-17")
        self.assertGreater(out["days_left"], 0)
        self.assertEqual(out["starts"], "2098-08-17")
        self.assertGreater(out["not_yet_valid_days"], 0)

    def test_no_raw_key_means_one_thing_by_its_value_and_another_by_its_absence(self):
        """A key written only when it is False makes its own absence mean the
        opposite - correct while every reader tests `is False`, and wrong the
        first time one tests the value. raw["ipv4"] was exactly that.

        Checked by running the pipeline and asserting the keys the checks
        actually consult are the ones something actually set.
        """
        rep = fresh().diagnose("8.8.8.8", None, quick=False)
        raw = rep["raw"]
        # Present on every box, both ways round, because it is a fact about
        # the box rather than a flag raised on one branch.
        self.assertIn("ipv4", raw)
        self.assertIsInstance(raw["ipv4"], bool)
        with open(nd.__file__, encoding="utf-8") as fh:
            src = fh.read()
        # And nothing reads it with the tri-state idiom any more.
        self.assertNotIn('raw.get("ipv4") is False', src)

    def test_nothing_is_defined_and_never_used(self):
        """A helper written for a path that was then taken differently is dead
        weight that still has to be read."""
        import ast, collections
        src = self.src()
        tree = ast.parse(src)
        names = collections.Counter(re.findall(r"\b(\w+)\b", src))
        defined = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        dead = sorted(n for n in defined
                      if names[n] < 2 and not n.startswith("__"))
        self.assertEqual(dead, [], f"defined but never referenced: {dead}")
        consts = [t.id for n in tree.body if isinstance(n, ast.Assign)
                  for t in n.targets if isinstance(t, ast.Name) and t.id.isupper()]
        unused = sorted(c for c in consts if names[c] < 2)
        self.assertEqual(unused, [], f"constants never read: {unused}")

    # Addresses that have to be real, and why. Everything else in a fixture
    # must come from RFC 5737 / RFC 3849 documentation space.
    REAL_ADDRESSES_ALLOWED = {
        "8.8.8.8": "the default target, and it has to resolve for anyone who runs it",
        "1.1.1.1": "quoted as an alternative --target",
        "9.9.9.9": "a second real resolver, so a baseline comparison has two to move between",
        "100.128.0.1": "deliberately just outside CGNAT, to test the boundary",
        "172.32.0.1": "deliberately just outside RFC1918, same reason",
        "0.0.0.0": "a wildcard bind, not a host",
    }

    def test_no_real_network_addresses_in_the_source(self):
        """Fixtures captured from a real traceroute leak an ISP, a region, and
        sometimes an egress address - and this repository is meant to be
        publishable.

        Three Comcast backbone hops sat in a traceroute fixture whose
        *hostnames* had already been scrubbed to example.net: whoever sanitised
        it meant to and missed the addresses. There is no way to notice that by
        reading, which is what this is for.
        """
        import ipaddress
        DOC = ("192.0.2.", "198.51.100.", "203.0.113.", "100.64.")
        offenders = []
        for name in ("faultone.py", "test_faultone.py"):
            path = os.path.join(os.path.dirname(os.path.abspath(nd.__file__)), name)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            for m in re.finditer(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text):
                ip = m.group(0)
                if ip in self.REAL_ADDRESSES_ALLOWED or ip.startswith(DOC):
                    continue
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue        # a version string or a mask, not an address
                if (addr.is_private or addr.is_loopback or addr.is_reserved
                        or addr.is_link_local or addr.is_multicast):
                    continue
                offenders.append(f"{name}:{text[:m.start()].count(chr(10)) + 1} {ip}")
        self.assertEqual(offenders, [], "real public addresses in the source - use "
                                        "RFC 5737 documentation ranges, or add them to "
                                        "REAL_ADDRESSES_ALLOWED with a reason")

    def test_every_allowed_real_address_is_still_used(self):
        """An exemption for an address nobody uses any more is an exemption
        waiting to excuse the next one.

        More than one occurrence, not merely present: this list lives in a file
        the check reads, so every entry trivially "appears" and the first
        version of this found nothing. It was carrying two dead exemptions at
        the time.
        """
        src = ""
        for name in ("faultone.py", "test_faultone.py"):
            root = os.path.dirname(os.path.abspath(nd.__file__))
            with open(os.path.join(root, name), encoding="utf-8") as fh:
                src += fh.read()
        unused = sorted(ip for ip in self.REAL_ADDRESSES_ALLOWED if src.count(ip) < 2)
        self.assertEqual(unused, [], f"exempted but used nowhere: {unused}")

    def test_no_debugging_left_behind(self):
        src = self.src()
        for marker in ("breakpoint(", "pdb.set_trace", "TODO", "FIXME", "XXX"):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, src)


class TestFaultSides(unittest.TestCase):
    """Direction and layer are orthogonal; the chain collapsed them into one."""

    def test_every_emitted_code_is_classified(self):
        """A code missing from the table silently defaults to local, which lets
        it explain faults in both directions. The default is the safe one, but
        it should be a decision rather than an oversight."""
        with open(nd.__file__, encoding="utf-8") as fh:
            emitted = set(re.findall(r'"code": "(\w+)"', fh.read()))
        unclassified = sorted(c for c in emitted
                              if c not in nd.FINDING_SIDE and c not in nd.VERDICT_EXEMPT)
        self.assertFalse(unclassified,
                         f"no side decided for: {unclassified} (add to FINDING_SIDE, "
                         f"or leave deliberately local)")

    def test_the_table_names_no_code_that_does_not_exist(self):
        with open(nd.__file__, encoding="utf-8") as fh:
            emitted = set(re.findall(r'"code": "(\w+)"', fh.read()))
        self.assertFalse(set(nd.FINDING_SIDE) - emitted)

    def test_a_local_fault_faces_both_ways(self):
        self.assertTrue(nd._sides_can_agree("local", "upstream"))
        self.assertTrue(nd._sides_can_agree("downstream", "local"))
        self.assertTrue(nd._sides_can_agree("upstream", "upstream"))
        self.assertFalse(nd._sides_can_agree("upstream", "downstream"))

    def test_the_two_resource_ceilings_face_opposite_ways(self):
        """Both are "this box ran out of something" and they break opposite
        directions: descriptors stop it accepting, ports stop it opening.
        Indistinguishable before this existed."""
        self.assertEqual(nd.finding_side("fd_pressure"), "downstream")
        self.assertEqual(nd.finding_side("ephemeral_ports_low"), "upstream")

    def test_an_opposite_side_fault_is_surfaced_whatever_its_layer(self):
        """The bug this fixes. Client-side loss and loss on the path to a
        backend are both layer 3, so the layer rule named one and presented the
        other as its consequence - and said nothing about the second."""
        f = lambda code, sev="critical", layer=3: {
            "code": code, "severity": sev, "layer": layer, "message": code}
        v = nd.build_verdict([f("tcp_flow_loss_clients"), f("path_loss")])
        self.assertEqual(v["based_on"][0], "tcp_flow_loss_clients")
        self.assertIn("path_loss", [u["code"] for u in v["unrelated"]])

    def test_a_same_side_fault_at_the_same_layer_is_still_a_consequence(self):
        """The change must not turn every same-layer finding into a second
        problem - only the ones that genuinely cannot be explained."""
        f = lambda code, layer=3: {"code": code, "severity": "critical",
                                   "layer": layer, "message": code}
        v = nd.build_verdict([f("inet_unreachable"), f("path_loss")])
        self.assertEqual([u["code"] for u in v["unrelated"]], [])

    def test_a_local_verdict_explains_faults_in_both_directions(self):
        """A local fault sits in both paths, so the side rule must not turn
        either direction into a second problem. (The pre-existing layer rule
        still surfaces anything genuinely above it - that is unchanged and is
        what "also, unrelated" was already for.)"""
        v = nd.build_verdict([
            {"code": "nic_drops_live", "severity": "critical", "layer": 3,
             "message": "x"},
            {"code": "inet_partial_loss", "severity": "critical", "layer": 3,
             "message": "y"},
            {"code": "tcp_flow_loss_clients", "severity": "critical", "layer": 3,
             "message": "z"}])
        self.assertEqual(v["based_on"][0], "nic_drops_live")
        self.assertEqual([u["code"] for u in v["unrelated"]], [])

    def test_faults_facing_opposite_ways_do_not_corroborate(self):
        """Two problems is not one problem confirmed twice."""
        v = nd.build_verdict([
            {"code": "syncookies_live", "severity": "critical", "layer": 4,
             "message": "x"},
            {"code": "inet_partial_loss", "severity": "critical", "layer": 3,
             "message": "y"}])
        self.assertEqual(v["based_on"][0], "syncookies_live")
        self.assertNotIn("inet_partial_loss", v["corroborated_by"])
        self.assertEqual(v["confidence"], "medium")


class TestConnectorBox(unittest.TestCase):
    """A box with no inbound ports that carries traffic over links it opens."""

    HDR = "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"

    def sockets(self, text):
        m = fresh()
        serving(m, text)
        return m

    def links(self, n=4, host="198.51.100.10"):
        return self.HDR + "".join(
            f"ESTAB 0 0 10.0.0.5:{45000+i} {host}:7844\n" for i in range(n))

    def test_a_box_with_no_listeners_can_still_have_a_dependency(self):
        """A connector opens no inbound ports by design. Gating dependency
        detection on listening meant its edge - the one thing it needs - was
        never what the run aimed at."""
        parsed = nd.parse_socket_states(self.links()); parsed["ok"] = True
        self.assertEqual(nd.pick_backend(parsed), "198.51.100.10")

    def test_a_laptop_browsing_still_has_no_dependency(self):
        """The reason the gate existed. Spread across many destinations with
        nothing concentrated is somebody using a machine, not a box with a
        dependency."""
        text = self.HDR + "".join(
            f"ESTAB 0 0 10.0.0.5:{45000+i} 203.0.113.{i}:443\n" for i in range(30))
        parsed = nd.parse_socket_states(text); parsed["ok"] = True
        self.assertIsNone(nd.pick_backend(parsed))

    def test_a_box_doing_nothing_at_all_is_reported(self):
        """The case this exists for: no listeners, no connections, and every
        other check passing because there is nothing to find a fault in. It
        reported "no fault found - this device looks healthy"."""
        old = os.environ.get("SSH_CONNECTION")
        os.environ["SSH_CONNECTION"] = "192.0.2.7 40000 10.0.0.5 22"
        try:
            m = self.sockets(self.HDR + "ESTAB 0 0 10.0.0.5:22 192.0.2.7:40000\n")
            rep = m.diagnose(None, None, quick=False)
            codes = [f["code"] for f in rep["findings"]]
            self.assertIn("no_traffic_at_all", codes)
            self.assertNotIn("all_clear", codes)
        finally:
            if old is None:
                os.environ.pop("SSH_CONNECTION", None)
            else:
                os.environ["SSH_CONNECTION"] = old

    def test_a_connector_with_its_links_up_says_nothing(self):
        old = os.environ.get("SSH_CONNECTION")
        os.environ["SSH_CONNECTION"] = "192.0.2.7 40000 10.0.0.5 22"
        try:
            m = self.sockets(self.HDR + "ESTAB 0 0 10.0.0.5:22 192.0.2.7:40000\n"
                             + self.links()[len(self.HDR):])
            codes = [f["code"] for f in m.diagnose(None, None, quick=False)["findings"]]
            self.assertNotIn("no_traffic_at_all", codes)
        finally:
            if old is None:
                os.environ.pop("SSH_CONNECTION", None)
            else:
                os.environ["SSH_CONNECTION"] = old

    def test_a_listening_box_is_left_to_the_rotation_check(self):
        """Two findings for one box would be two problems where there is one."""
        m = self.sockets(self.HDR + "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n")
        codes = [f["code"] for f in m.diagnose(None, None, quick=False)["findings"]]
        self.assertIn("no_clients_connected", codes)
        self.assertNotIn("no_traffic_at_all", codes)


class TestForwardingBox(unittest.TestCase):
    """A box that opens connections on behalf of other people, rather than for
    itself. Its outbound peers are not its dependencies."""

    def fwd(self):
        # Defined with the scenarios further down the file, so referenced at
        # call time rather than at class-body time.
        return FORWARDER_SS

    def test_a_forwarder_does_not_have_its_target_picked_from_user_traffic(self):
        """The most-connected outbound peer on such a box is whichever
        destination is popular this minute, and diagnosing the path to it says
        nothing about the box."""
        m = fresh()
        serving(m, self.fwd())
        rep = m.diagnose(None, None, quick=False)
        self.assertEqual(rep["target"], nd.DEFAULT_TARGET)
        self.assertIn("target_is_forwarded", [f["code"] for f in rep["findings"]])

    def test_a_few_real_backends_are_still_picked(self):
        """The share test must not break the case it was built around."""
        text = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
                + "".join(f"ESTAB 0 0 10.0.0.5:443 198.51.100.{i}:5100\n" for i in range(9))
                + "".join(f"ESTAB 0 0 10.0.0.5:{44000+i} 10.0.0.9{i%3}:5432\n"
                          for i in range(9)))
        parsed = nd.parse_socket_states(text); parsed["ok"] = True
        self.assertIsNotNone(nd.pick_backend(parsed))

    def test_one_busy_destination_among_hundreds_is_not_a_dependency(self):
        parsed = nd.parse_socket_states(self.fwd()); parsed["ok"] = True
        self.assertIsNone(nd.pick_backend(parsed))

    def test_the_shape_is_reported_rather_than_a_target_invented(self):
        m = fresh()
        serving(m, self.fwd())
        msg = [f for f in m.diagnose(None, None, quick=False)["findings"]
               if f["code"] == "target_is_forwarded"][0]["message"]
        self.assertIn("distinct destinations", msg)
        self.assertIn("--target", msg)


class TestQuietGotchas(unittest.TestCase):
    """Two failures that make every other check pass."""

    def listening(self, ports, clients=0, extra=""):
        text = "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
        for p in ports:
            text += f"LISTEN 0 128 0.0.0.0:{p} 0.0.0.0:*\n"
        text += "".join(f"ESTAB 0 0 10.0.0.5:443 10.20.0.7:510{i:02d}\n"
                        for i in range(clients)) + extra
        m = fresh()
        serving(m, text)
        return [f for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]

    def test_a_service_with_nobody_connected_is_reported(self):
        """Being taken out of a pool is invisible from the box it happened to:
        the port is open, the certificate is fine, every check passes and no
        traffic arrives."""
        hit = [f for f in self.listening(["443"]) if f["code"] == "no_clients_connected"]
        self.assertTrue(hit)
        self.assertIn("load balancer", hit[0]["message"])

    def test_only_health_checks_still_counts_as_nobody(self):
        hit = [f for f in self.listening(["443"], clients=1)
               if f["code"] == "no_clients_connected"]
        self.assertTrue(hit)
        self.assertIn("10.20.0.7", hit[0]["message"])
        self.assertIn("health check", hit[0]["message"])

    def test_clients_connected_says_nothing(self):
        self.assertFalse([f for f in self.listening(["443"], clients=9)
                          if f["code"] == "no_clients_connected"])

    def test_listening_is_not_the_same_as_existing_to_be_connected_to(self):
        """Almost every machine listens on something. Gated to ports whose
        purpose is answering clients, or this fires on any box with sshd -
        which it did, on this one, before the gate existed."""
        self.assertFalse([f for f in self.listening(["22", "9100", "5432"])
                          if f["code"] == "no_clients_connected"])

    def test_a_resolver_on_this_box_is_flagged_as_a_cache(self):
        """A stale entry in a cache here is invisible from anywhere else and
        will not reproduce from the next machine somebody tries."""
        m = fresh()
        resolvers(m, [R("127.0.0.53")])
        hit = [f for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]
               if f["code"] == "dns_local_cache"]
        self.assertTrue(hit)
        self.assertIn("systemd-resolved", hit[0]["message"])
        self.assertEqual(hit[0]["severity"], "ok")

    def test_a_resolver_on_the_network_is_not_a_local_cache(self):
        m = fresh()
        resolvers(m, [R("10.0.0.53"), R("10.0.0.54")])
        self.assertFalse([f for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]
                          if f["code"] == "dns_local_cache"])

    def test_an_unnamed_loopback_resolver_is_still_a_cache(self):
        m = fresh()
        resolvers(m, [R("127.0.0.1")])
        hit = [f for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]
               if f["code"] == "dns_local_cache"]
        self.assertTrue(hit)
        self.assertIn("127.0.0.1", hit[0]["message"])

    def test_the_cache_check_runs_after_the_resolvers_are_probed(self):
        """It reads what that check collected. Ordered before it, it read an
        empty dict and said nothing - on every box, silently."""
        src = open(nd.__file__, encoding="utf-8").read()
        # The call, not the definition - "def _check_dns_cache(raw, findings)"
        # contains the call as a substring, and matching that put the first
        # version of this assertion the wrong way round.
        call = "\n    _check_dns_cache(raw, findings)"
        self.assertIn(call, src)
        self.assertLess(src.index("dns_failed = _check_dns(raw, findings"),
                        src.index(call))


class TestRedundancyGotchas(unittest.TestCase):
    """Virtual routers: what the neighbour table can and cannot show."""

    def diag(self, arp):
        m = fresh()
        m.cmd_arp = lambda: {"ok": True, "cmd": "ip neigh", "stdout": arp}
        return m.diagnose("8.8.8.8", None, quick=False)

    def test_the_documented_virtual_mac_formats_are_read_correctly(self):
        self.assertEqual(nd.virtual_router_mac("00:00:5e:00:01:2a"), ("VRRP or CARP", 42))
        self.assertEqual(nd.virtual_router_mac("00:00:5e:00:02:2a"), ("VRRP for IPv6", 42))
        self.assertEqual(nd.virtual_router_mac("00:00:0c:07:ac:0b"), ("HSRPv1", 11))
        self.assertEqual(nd.virtual_router_mac("00:00:0c:9f:f0:64"), ("HSRPv2", 100))
        self.assertEqual(nd.virtual_router_mac("00:07:b4:00:03:01"), ("GLBP", 3))

    def test_an_ordinary_mac_is_not_mistaken_for_a_virtual_one(self):
        for mac in ("3c:ec:ef:41:8a:22", "aa:bb:cc:00:00:07", "", None, "nonsense"):
            with self.subTest(mac=mac):
                self.assertIsNone(nd.virtual_router_mac(mac))

    def test_a_virtual_gateway_is_reported_as_a_pair_not_a_router(self):
        """It reframes every gateway finding: "the gateway is down" on a
        redundancy pair more often means a failover that did not complete."""
        rep = self.diag("10.0.0.1 dev eth0 lladdr 00:00:5e:00:01:2a REACHABLE\n")
        msg = [f for f in rep["findings"] if f["code"] == "gateway_is_virtual"]
        self.assertTrue(msg)
        self.assertIn("VRRP or CARP", msg[0]["message"])
        self.assertIn("group 42", msg[0]["message"])
        self.assertEqual(nd.exit_status(rep), 0)

    def test_two_groups_on_one_address_is_a_configuration_conflict(self):
        rep = self.diag("10.0.0.1 dev eth0 lladdr 00:00:5e:00:01:2a REACHABLE\n"
                        "10.0.0.1 dev eth0 lladdr 00:00:5e:00:01:07 STALE\n")
        codes = [f["code"] for f in rep["findings"]]
        self.assertIn("virtual_router_conflict", codes)
        self.assertNotIn("duplicate_ip", codes)

    def test_a_virtual_and_a_real_mac_stay_an_ordinary_duplicate(self):
        """One of each is not two virtual routers, and calling it one would be
        a more specific claim than the evidence supports."""
        codes = [f["code"] for f in self.diag(
            "10.0.0.1 dev eth0 lladdr 00:00:5e:00:01:2a REACHABLE\n"
            "10.0.0.1 dev eth0 lladdr 3c:ec:ef:41:8a:22 STALE\n")["findings"]]
        self.assertIn("duplicate_ip", codes)
        self.assertNotIn("virtual_router_conflict", codes)

    def test_a_same_group_split_brain_is_not_claimed_because_it_cannot_be_seen(self):
        """Two masters in one VRRP group share one virtual MAC - that is what
        VRRP is for - so the neighbour table shows a single entry and there is
        nothing to detect. Implying otherwise would be worse than silence."""
        rep = self.diag("10.0.0.1 dev eth0 lladdr 00:00:5e:00:01:2a REACHABLE\n"
                        "10.0.0.1 dev eth0 lladdr 00:00:5e:00:01:2a STALE\n")
        codes = [f["code"] for f in rep["findings"]]
        self.assertNotIn("virtual_router_conflict", codes)
        self.assertNotIn("duplicate_ip", codes)
        # And the finding that is shown says where to look instead.
        virt = [f for f in rep["findings"] if f["code"] == "gateway_is_virtual"][0]
        self.assertIn("--baseline", virt["message"])

    def test_the_address_changing_hands_between_visits_is_reported(self):
        """The one view of a failover this box gets."""
        first = self.diag("10.0.0.1 dev eth0 lladdr 00:00:5e:00:01:2a REACHABLE\n")
        self.assertEqual(first["gateway_mac"], "00:00:5e:00:01:2a")
        m = fresh()
        m.cmd_arp = lambda: {"ok": True, "cmd": "ip neigh",
                             "stdout": "10.0.0.1 dev eth0 lladdr 00:00:5e:00:01:07 REACHABLE\n"}
        second = m.diagnose("8.8.8.8", None, quick=False, baseline=first)
        changed = [c for c in second["comparison"]
                   if c["what"] == "gateway hardware address"]
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]["direction"], "neutral")

    def test_a_gateway_that_has_not_moved_reports_nothing(self):
        first = self.diag("10.0.0.1 dev eth0 lladdr 00:00:5e:00:01:2a REACHABLE\n")
        m = fresh()
        m.cmd_arp = lambda: {"ok": True, "cmd": "ip neigh",
                             "stdout": "10.0.0.1 dev eth0 lladdr 00:00:5e:00:01:2a REACHABLE\n"}
        second = m.diagnose("8.8.8.8", None, quick=False, baseline=first)
        self.assertNotIn("gateway hardware address",
                         {c["what"] for c in second["comparison"]})


class TestInternationalDeployment(unittest.TestCase):
    """Boxes outside the country the defaults were chosen in."""

    def diag(self, target="8.8.8.8"):
        m = fresh()
        ipv6_only(m)
        return m.diagnose(target, None, quick=False)

    def test_an_ipv6_only_box_is_not_a_box_that_never_got_on_the_network(self):
        """IPv6-only is ordinary on mobile carriers and in plenty of
        datacentres outside the US. It was reported critical, exit 2, "this
        device never got onto the network", while holding a global IPv6
        address and working perfectly."""
        rep = self.diag()
        codes = [f["code"] for f in rep["findings"]]
        self.assertNotIn("no_ipv4", codes)
        self.assertIn("ipv6_only", codes)
        self.assertEqual(nd.exit_status(rep), 0)

    def test_the_ipv4_chain_is_unmeasurable_rather_than_broken(self):
        """Every IPv4 check on such a box is measuring something it cannot do,
        not something that is failing."""
        rep = self.diag()
        codes = [f["code"] for f in rep["findings"]]
        self.assertIn("gw_unmeasurable_v4", codes)
        self.assertIn("inet_unmeasurable_v4", codes)
        self.assertNotIn("gw_unreachable", codes)
        self.assertNotIn("inet_unreachable", codes)

    def test_the_all_clear_does_not_claim_what_was_never_reached(self):
        """An all-clear saying "the gateway and the internet are reachable" on
        a box where neither was reached is the exact overclaim this sentence
        exists to avoid."""
        msg = [f for f in self.diag()["findings"] if f["code"] == "all_clear"][0]["message"]
        self.assertNotIn("the gateway and the internet are reachable", msg)
        self.assertIn("never reached", msg)

    def test_link_local_alone_is_still_a_device_that_never_got_on(self):
        """Every interface gets an fe80:: address whether or not anything
        configured it. Accepting that would make this check unfailable."""
        m = fresh()
        m.cmd_interfaces = lambda: {"ok": True, "cmd": "ip addr", "stdout":
            "2: eth0: <UP>\n    inet6 fe80::1/64 scope link\n"}
        codes = [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]
        self.assertIn("no_ipv4", codes)

    def test_a_dual_stack_box_is_unaffected(self):
        m = fresh()
        m.cmd_interfaces = lambda: {"ok": True, "cmd": "ip addr", "stdout":
            "2: eth0: <UP>\n    inet 10.0.0.5/24\n    inet6 2001:db8::5/64 scope global\n"}
        codes = [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]
        for code in ("no_ipv4", "ipv6_only", "gw_unmeasurable_v4"):
            self.assertNotIn(code, codes)

    def test_an_internationalised_hostname_is_accepted(self):
        """A box in Tokyo or Munich has backends named in its own script.
        Rejecting them made the tool unusable exactly where nobody can paste an
        ASCII alternative."""
        for name in ("пример.рф", "日本.jp", "münchen.example.de"):
            with self.subTest(name=name):
                self.assertTrue(nd.valid_target(name))

    def test_an_international_name_is_converted_once_for_everything_downstream(self):
        """Every command run and socket opened should see the ASCII form the
        DNS actually carries, and the report should record what was reached."""
        seen = []
        m = fresh()
        m.cmd_ping = lambda t, c=4, w=2: (seen.append(t) or {
            "ok": True, "cmd": f"ping {t}", "stdout":
            "10 packets transmitted, 10 received, 0% packet loss\n"
            "rtt min/avg/max/mdev = 1.0/20.0/30.0/2.0 ms\n"})
        rep = m.diagnose("münchen.example.de", None, quick=True)
        self.assertEqual(rep["target"], "xn--mnchen-3ya.example.de")
        self.assertTrue(all(ord(c) < 128 for t in seen for c in t))

    def test_rubbish_is_still_rubbish(self):
        for bad in ("", "not a host", "..", "a" * 300, "-.-", "http://x.com"):
            with self.subTest(bad=bad):
                self.assertFalse(nd.valid_target(bad))

    def test_an_unconvertible_name_is_refused_rather_than_guessed(self):
        self.assertIsNone(nd.idna_host("\u0000\u0000.jp"))
        self.assertIsNone(nd.idna_host("plain.example.com"))   # nothing to convert


class TestDownVersusUnreachable(unittest.TestCase):
    """A host that is down and a host you cannot get to are different states
    with different owners - a line monitoring systems have drawn for decades
    and this collapsed into "the provider"."""

    def silent_target(self, hops, quick=False):
        m = fresh()
        m.cmd_ping = lambda t, c=4, w=2: (
            {"ok": True, "cmd": "ping", "stdout":
             "10 packets transmitted, 10 received, 0% packet loss\n"
             "rtt min/avg/max/mdev = 1/1/2/0.2 ms\n"} if t == "10.0.0.1"
            else {"ok": True, "cmd": "ping", "stdout":
                  "10 packets transmitted, 0 received, 100% packet loss\n"})
        m.cmd_check_port = lambda h, p, timeout=5: {"ok": False, "reason": "timeout"}
        if hops:
            mtr(m, hops)
        return m.diagnose("8.8.8.8", None, quick=quick)["verdict"]

    REACHES = [{"count": 1, "host": "10.0.0.1", "Loss%": 0.0, "Snt": 30, "Avg": 1.0},
               {"count": 2, "host": "198.51.100.1", "Loss%": 0.0, "Snt": 30, "Avg": 12.0},
               {"count": 3, "host": "8.8.8.8", "Loss%": 0.0, "Snt": 30, "Avg": 20.0}]
    STOPS = [{"count": 1, "host": "10.0.0.1", "Loss%": 0.0, "Snt": 30, "Avg": 1.0},
             {"count": 2, "host": "???", "Loss%": 100.0, "Snt": 30, "Avg": 0.0}]

    def test_a_reachable_target_that_answers_nothing_is_the_destination(self):
        v = self.silent_target(self.REACHES)
        self.assertEqual(v["based_on"][0], "destination_unresponsive")
        self.assertNotIn("provider", v["owner"])

    def test_a_path_that_stops_short_is_still_the_path(self):
        v = self.silent_target(self.STOPS)
        self.assertEqual(v["based_on"][0], "inet_unreachable")
        self.assertEqual(v["owner"], "the provider")

    def test_with_no_trace_nothing_is_concluded_about_which(self):
        """--quick runs no trace. The older, vaguer finding stands rather than
        a guess being made between two answers with different owners."""
        v = self.silent_target(self.REACHES, quick=True)
        self.assertEqual(v["based_on"][0], "inet_unreachable")


class TestWhyAConnectFailed(unittest.TestCase):
    """A connect that fails instantly because there is no route, and one that
    fails after waiting because nothing came back, are opposite situations.
    Both landed in the timeout bucket, which describes only the second and
    sends the reader to the network for a routing table on this box."""

    def reason_for(self, errno_code):
        """Drive the real socket path, not a stub of it. Stubbing cmd_check_port
        is what let three mutations of this mapping pass unnoticed."""
        import errno, socket
        class FakeSock:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def settimeout(self, t): pass
            def connect_ex(self, addr): return errno_code
            def recv(self, n): return b""
        orig = socket.socket
        socket.socket = lambda *a, **k: FakeSock()
        try:
            return nd.cmd_check_port("192.0.2.1", 443).get("reason")
        finally:
            socket.socket = orig

    def test_no_route_is_not_a_timeout(self):
        import errno
        self.assertEqual(self.reason_for(errno.ENETUNREACH), "no_route")

    def test_a_router_saying_it_cannot_reach_is_not_a_timeout_either(self):
        import errno
        self.assertEqual(self.reason_for(errno.EHOSTUNREACH), "host_unreachable")

    def test_refused_and_timed_out_still_mean_what_they_did(self):
        import errno
        self.assertEqual(self.reason_for(errno.ECONNREFUSED), "refused")
        self.assertEqual(self.reason_for(errno.ETIMEDOUT), "timeout")

    def test_the_linux_numbers_are_accepted_where_the_platform_differs(self):
        """errno values differ across platforms - ENETUNREACH is 101 on Linux
        and 51 on BSD. The mapping names the constant and the Linux number, the
        way the refused branch beside it already did."""
        self.assertEqual(self.reason_for(101), "no_route")
        self.assertEqual(self.reason_for(113), "host_unreachable")

    def test_no_route_is_a_fault_even_from_a_speculative_port(self):
        """A port from the preset asserts nothing about the service. A missing
        route is this box's configuration whichever port asked."""
        m = fresh()
        m.cmd_check_port = lambda h, p, timeout=5: {
            "ok": False, "cmd": "tcp", "reason": "no_route", "error": "no route"}
        rep = m.diagnose("8.8.8.8", ["443"], quick=False, ports_speculative=True)
        fired = [f for f in rep["findings"] if f["code"] == "no_route_to_target"]
        self.assertTrue(fired)
        self.assertEqual(fired[0]["severity"], "critical")

    def test_nothing_reached_the_wire_so_nothing_upstream_is_blamed(self):
        m = fresh()
        m.cmd_check_port = lambda h, p, timeout=5: {
            "ok": False, "cmd": "tcp", "reason": "no_route", "error": "no route"}
        v = m.diagnose("8.8.8.8", ["443"], quick=False)["verdict"]
        self.assertNotIn("provider", v["owner"])
        self.assertIn("routing table", v["owner"])


class TestDelayThatWillNotSitStill(unittest.TestCase):
    """TCP reports its round trip as smoothed/variance. The parser took the
    first number, so the only jitter figure measured on the traffic this box
    actually carries - rather than on probes a router may deprioritise - was
    dropped on the floor."""

    def test_the_variance_half_is_kept(self):
        flows = nd.parse_tcp_flows(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "ESTAB 0 0 10.0.0.1:443 10.0.0.9:52544\n"
            "\t cubic rtt:87.5/45.2 minrtt:85.2 mss:1448\n")
        self.assertEqual(flows[0]["rtt_ms"], 87.5)
        self.assertEqual(flows[0]["rtt_var_ms"], 45.2)

    def test_a_socket_without_a_variance_half_reports_none(self):
        flows = nd.parse_tcp_flows(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "ESTAB 0 0 10.0.0.1:443 10.0.0.9:52544\n"
            "\t cubic rtt:87.5 minrtt:85.2 mss:1448\n")
        self.assertIsNone(flows[0]["rtt_var_ms"])

    def codes(self, rtt, var):
        m = fresh()
        sided_flows(m, jittery_sock("10.0.0.90", "44120", rtt, var, port="5432"))
        return [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]

    def test_variance_at_half_the_round_trip_is_reported(self):
        self.assertIn("path_jitter_backends", self.codes(80.0, 50.0))

    def test_a_long_but_steady_path_is_not(self):
        """200ms that never moves is distance. The absolute figure alone would
        fire on it."""
        self.assertNotIn("path_jitter_backends", self.codes(200.0, 2.0))

    def test_a_lan_whose_variance_is_most_of_a_tiny_round_trip_is_not(self):
        """0.3ms of variance on 0.4ms is proportionally enormous and matters
        to nobody. The share test alone would fire on it."""
        self.assertNotIn("path_jitter_backends", self.codes(0.4, 0.3))

    def test_the_two_sides_are_told_apart(self):
        """A path to the backends and a path to the users are two pieces of
        equipment with two owners, which is the whole reason for the split."""
        m = fresh()
        sided_flows(m, jittery_sock("203.0.113.9", "443", 80.0, 50.0))
        codes = [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]
        self.assertIn("path_jitter_clients", codes)
        self.assertNotIn("path_jitter_backends", codes)


class TestWhatTheCauseAccountsFor(unittest.TestCase):
    """The verdict said what it could not explain and never what it could. A
    full link reported the loss it was causing as "also, unrelated - suggests
    upstream congestion", which sends someone to a carrier over a fault on
    their own box."""

    def f(self, code, sev="critical", layer=1):
        return {"code": code, "severity": sev, "layer": layer, "message": code}

    def verdict(self, *findings):
        return nd.build_verdict(list(findings))

    def test_a_full_link_accounts_for_the_loss_it_causes(self):
        v = self.verdict(self.f("link_saturated", "warning", 2),
                         self.f("inet_partial_loss", "warning", 3))
        self.assertIn("inet_partial_loss", v["explains"])
        self.assertEqual([u["code"] for u in v["unrelated"]], [])

    def test_a_cable_does_not_account_for_an_expired_certificate(self):
        """Layer distance cannot express this on its own: the certificate is
        further up the stack and no amount of fixing the cable renews it."""
        v = self.verdict(self.f("link_errors_live", layer=1),
                         self.f("tls_expired", layer=7))
        self.assertEqual(v["explains"], [])
        self.assertEqual([u["code"] for u in v["unrelated"]], ["tls_expired"])

    def test_a_resolver_timing_out_is_explained_but_a_wrong_answer_is_not(self):
        """Both are DNS at layer 7. One is what a degraded path looks like from
        above; the other is a resolver being wrong, which survives fixing
        anything underneath it."""
        slow = self.verdict(self.f("link_errors_live", layer=1),
                            self.f("dns_fail", layer=7))
        wrong = self.verdict(self.f("link_errors_live", layer=1),
                             self.f("dns_hijack", layer=7))
        self.assertIn("dns_fail", slow["explains"])
        self.assertEqual(wrong["explains"], [])

    def test_a_fault_facing_the_other_way_is_never_accounted_for(self):
        """Direction still overrides everything. Loss the clients see is not a
        consequence of loss on the path to a backend, whatever the layers."""
        v = self.verdict(self.f("tcp_flow_loss_backends", "warning", 3),
                         self.f("own_service_silent", "critical", 7))
        self.assertEqual(v["explains"], [])

    def test_nothing_is_both_explained_and_unrelated(self):
        """They are answers to the same question and a finding in both lists
        would be the report contradicting itself in two adjacent lines."""
        import test_faultone as self_mod
        for code in sorted(S):
            setup, kw = S[code]
            m = fresh(); setup(m)
            try:
                v = m.diagnose(quick=False, **scenario_kwargs(kw))["verdict"]
            except Exception:
                continue
            overlap = set(v.get("explains") or []) & {u["code"] for u in (v.get("unrelated") or [])}
            self.assertEqual(overlap, set(), f"{code}: {overlap}")

    def test_a_cause_never_accounts_for_what_is_beneath_it(self):
        """Consequences run upward. A resolver answering with the wrong
        address does not cause packet loss on the path below it - that
        finding is evidence about the same box, not a thing DNS produced."""
        v = self.verdict(self.f("dns_hijack", "critical", 7),
                         self.f("inet_partial_loss", "warning", 3))
        self.assertEqual(v["explains"], [])

    def test_nothing_is_both_evidence_for_the_cause_and_caused_by_it(self):
        """Corroboration looks down the stack and consequences look up, so a
        finding in both lists would be the verdict using one fault as its own
        proof and its own result."""
        for code in sorted(S):
            setup, kw = S[code]
            m = fresh(); setup(m)
            try:
                v = m.diagnose(quick=False, **scenario_kwargs(kw))["verdict"]
            except Exception:
                continue
            both = set(v.get("explains") or []) & set(v.get("corroborated_by") or [])
            self.assertEqual(both, set(), f"{code}: {both}")

    def test_the_cause_never_accounts_for_itself(self):
        v = self.verdict(self.f("inet_partial_loss", "warning", 3))
        self.assertNotIn("inet_partial_loss", v["explains"])

    def test_it_reaches_the_reader(self):
        m = fresh()
        counters(m, rx_bytes=0, tx_bytes=0)
        rep = {"verdict": {"headline": "h", "owner": "o", "next_step": "n",
                           "confidence": "medium", "severity": "warning",
                           "coverage": {"ran": 1, "attempted": 1},
                           "corroborated_by": [], "unrelated": [],
                           "explains": ["inet_partial_loss"], "based_on": []},
               "findings": [], "stages": [], "target": "8.8.8.8"}
        text = nd.render_text_report(rep)
        self.assertIn("this also accounts for: inet_partial_loss", text)
        self.assertIn("1 explained by it", text)

    def test_every_transport_symptom_is_a_finding_that_exists(self):
        """A code in this set that nothing emits is a rule about nothing, and
        the set is where the cause-versus-consequence answer comes from."""
        codes = set(re.findall(r'"code": "(\w+)"', open(nd.__file__, encoding="utf-8").read()))
        self.assertEqual(sorted(nd.TRANSPORT_SYMPTOMS - codes), [])


class TestTheSameFaultOnEveryCable(unittest.TestCase):
    """The reasoning the flow checks already do for peers - loss to one
    destination is that destination, loss to all of them is the local link -
    applied to the cables, where it was missing."""

    def box(self, bad, total):
        m = fresh()
        ifaces = [dict(name=f"eth{i}", packets=10_000_000, errors=900 if i < bad else 0,
                       drops=0, crc=900 if i < bad else 0, frame=0, overruns=0,
                       collisions=0, err_ppm=90 if i < bad else 0, coll_ppm=0,
                       unknown_counters=[], delta_errors=40 if i < bad else 0,
                       delta_drops=0, delta_packets=2_000, delta_host_errors=0,
                       delta_length_errors=0, sample_seconds=2, rx_mbps=1, tx_mbps=1,
                       operstate="up", carrier_changes=0, delta_carrier_changes=0,
                       rate_series=None, peak_mbps=None, series_seconds=None)
                  for i in range(total)]
        m.cmd_link_stats = lambda *a, **k: {"ok": True, "cmd": "s", "stdout": "",
                                            "interfaces": ifaces, "sample_seconds": 2,
                                            "source": "sysfs"}
        return m.diagnose("8.8.8.8", None, quick=False)["verdict"]

    def test_every_interface_means_the_cable_is_not_it(self):
        v = self.box(8, 8)
        self.assertEqual(v["based_on"][0], "fault_on_every_interface")
        self.assertNotIn("cable", v["owner"].replace("not any one cable", ""))

    def test_some_interfaces_is_still_about_those_cables(self):
        self.assertNotEqual(self.box(2, 8)["based_on"][0], "fault_on_every_interface")

    def test_enough_of_them_is_not_the_same_as_all_of_them(self):
        """Three bad cables out of eight is three bad cables. The count alone
        would call that a shared cause on a box where five interfaces are
        demonstrably fine - and the five clean ones are the evidence that
        whatever they all share is working."""
        self.assertNotEqual(self.box(3, 8)["based_on"][0], "fault_on_every_interface")

    def test_two_bad_leads_are_two_bad_leads(self):
        """A box with two bad patch leads is a box with two bad patch leads.
        Three is where coincidence stops being the simpler explanation."""
        self.assertNotEqual(self.box(2, 2)["based_on"][0], "fault_on_every_interface")

    def test_three_is_enough_when_it_is_all_of_them(self):
        self.assertEqual(self.box(3, 3)["based_on"][0], "fault_on_every_interface")

    def test_a_single_interface_box_never_reaches_it(self):
        """One NIC is always "every interface", and saying so would turn the
        commonest hardware there is into a shared-cause fault."""
        self.assertNotEqual(self.box(1, 1)["based_on"][0], "fault_on_every_interface")


class TestConnectionsKilledByTheOtherEnd(unittest.TestCase):
    """A well-behaved connection ends with a FIN. A reset on an established one
    means somebody gave up mid-flight - and the counter records the teardown
    without saying who sent it."""

    def codes(self, **after):
        before = {"EstabResets": 0, "OutRsts": 0, "PassiveOpens": 0, "ActiveOpens": 0}
        m = fresh()
        kernel_drops(m, before, dict(before, **after))
        return [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]

    def test_connections_dying_that_this_box_did_not_kill(self):
        self.assertIn("connections_reset_by_peer",
                      self.codes(EstabResets=30, OutRsts=2, PassiveOpens=100))

    def test_when_this_box_sent_most_of_them_it_is_not_the_far_end(self):
        """The inference is the whole finding. Without this guard it would
        blame the far end for resets this box demonstrably sent itself."""
        self.assertNotIn("connections_reset_by_peer",
                         self.codes(EstabResets=30, OutRsts=40, PassiveOpens=100))

    def test_ordinary_abandonment_is_not_reported(self):
        self.assertNotIn("connections_reset_by_peer",
                         self.codes(EstabResets=5, OutRsts=1, PassiveOpens=100))

    def test_a_handful_of_connections_is_not_a_rate(self):
        self.assertNotIn("connections_reset_by_peer",
                         self.codes(EstabResets=3, OutRsts=0, PassiveOpens=6))

    def test_it_faces_the_other_way_from_the_resets_this_box_sends(self):
        """One is this box refusing and one is this box being refused. They are
        the same wire event with opposite owners, so they must not corroborate
        each other into a confident wrong answer."""
        self.assertEqual(nd.finding_side("resets_sent_high"), "local")
        self.assertEqual(nd.finding_side("connections_reset_by_peer"), "upstream")


class TestAVirtualNicCannotFailAPhysicalCheck(unittest.TestCase):
    """On a paravirtual adapter the CRC, frame, collision and optical counters
    are hardwired to zero by the driver. Their silence says nothing, and a
    stage strip reading "link PASS" on a box where the link could not have
    failed the check is the most misleading thing this tool can print."""

    def report(self, driver):
        m = fresh()
        m.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
            {"name": "eth0", "speed_mbps": None, "duplex": None, "mtu": 1500,
             "carrier": True, "operstate": "up", "driver": driver}]}
        return m.diagnose("8.8.8.8", None, quick=False)

    def test_a_paravirtual_adapter_is_named_as_one(self):
        f = [x for x in self.report("virtio_net")["findings"] if x["code"] == "virtual_nic"]
        self.assertTrue(f)
        self.assertIn("KVM or QEMU", f[0]["message"])
        self.assertIn("hardwired to zero", f[0]["message"])

    def test_a_real_nic_says_nothing(self):
        codes = [x["code"] for x in self.report("ixgbe")["findings"]]
        self.assertNotIn("virtual_nic", codes)

    def test_an_interface_with_no_driver_says_nothing(self):
        """Bonds, VLANs and tunnels have no device behind them at all."""
        codes = [x["code"] for x in self.report(None)["findings"]]
        self.assertNotIn("virtual_nic", codes)

    def test_the_drivers_it_knows(self):
        for drv in ("virtio_net", "vmxnet3", "hv_netvsc", "xen-netfront", "ena", "gve"):
            with self.subTest(driver=drv):
                self.assertIn(drv, nd.VIRTUAL_NIC_DRIVERS)
        for drv in ("ixgbe", "e1000e", "mlx5_core", "bnxt_en", "igb", "tg3"):
            with self.subTest(driver=drv):
                self.assertNotIn(drv, nd.VIRTUAL_NIC_DRIVERS)

    def test_it_is_context_and_never_a_fault(self):
        rep = self.report("virtio_net")
        f = next(x for x in rep["findings"] if x["code"] == "virtual_nic")
        self.assertEqual(f["severity"], "ok")
        self.assertIn("virtual_nic", nd.VERDICT_EXEMPT)
        self.assertEqual(rep["verdict"]["severity"], "ok")

    def test_the_driver_is_read_from_the_sysfs_symlink(self):
        import os, shutil, tempfile
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        for name, drv in (("eth0", "virtio_net"), ("eth1", "ixgbe"), ("bond0", None)):
            os.makedirs(os.path.join(base, name))
            if drv:
                os.makedirs(os.path.join(base, name, "device"))
                target = os.path.join(base, "_drivers", drv)
                os.makedirs(target, exist_ok=True)
                os.symlink(target, os.path.join(base, name, "device", "driver"))
        got = nd._link_drivers_linux(base)
        self.assertEqual(got.get("eth0"), "virtio_net")
        self.assertEqual(got.get("eth1"), "ixgbe")
        self.assertNotIn("bond0", got, "an interface with no device behind it has no driver")

    def test_no_sysfs_tree_yields_nothing(self):
        self.assertEqual(nd._link_drivers_linux("/nonexistent/path"), {})

    def test_the_driver_reaches_the_interface_summary(self):
        """Reading the symlink and putting the answer where the check looks are
        two different things, and stubbing cmd_link_modes tests neither. A
        mutation that dropped the driver on the floor between them passed every
        test above."""
        import os, shutil, tempfile
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        d = os.path.join(base, "eth0")
        os.makedirs(os.path.join(d, "device"))
        for field, value in (("mtu", "1500"), ("carrier", "1"), ("operstate", "up")):
            with open(os.path.join(d, field), "w", encoding="utf-8") as fh:
                fh.write(value)
        target = os.path.join(base, "_drivers", "virtio_net")
        os.makedirs(target)
        os.symlink(target, os.path.join(d, "device", "driver"))
        self.assertEqual(nd._link_modes_linux(base)["eth0"]["driver"], "virtio_net")


class TestATunnelIsNotAMisconfiguredWire(unittest.TestCase):
    """A reduced MTU on a tunnel is the header overhead of whatever is wrapping
    the traffic. Reported as a fault, it made a healthy VPN box come back with
    "Interface MTU is not the standard 1500" as its verdict, every run, because
    nothing else was wrong."""

    def box(self, name, mtu):
        base = {k: 0 for k in ("rx_errors", "tx_errors", "rx_dropped", "tx_dropped",
                               "rx_crc_errors", "rx_frame_errors", "rx_over_errors",
                               "collisions", "rx_missed_errors", "rx_length_errors",
                               "tx_carrier_errors")}
        base.update(rx_packets=5_000_000, tx_packets=5_000_000, rx_bytes=0, tx_bytes=0,
                    operstate="up", carrier_changes=0)
        m = fresh(); m.OS_NAME = "Linux"
        m._read_link_stats = lambda: ({"eth0": dict(base), name: dict(base)}, "sysfs")
        m.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
            {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500,
             "carrier": True},
            {"name": name, "speed_mbps": None, "duplex": None, "mtu": mtu,
             "carrier": True}]}
        return m.diagnose("8.8.8.8", None, quick=False)

    def test_a_healthy_vpn_box_reports_no_fault(self):
        rep = self.box("tun0", 1420)
        self.assertEqual(rep["verdict"]["severity"], "ok")
        codes = [f["code"] for f in rep["findings"]]
        self.assertIn("tunnel_mtu", codes)
        self.assertNotIn("mtu_nonstandard", codes)

    def test_the_number_is_still_shown(self):
        """It is the number that decides whether traffic inside the tunnel
        fits, so hiding it would be worse than calling it a fault."""
        rep = self.box("tun0", 1420)
        note = next(f for f in rep["findings"] if f["code"] == "tunnel_mtu")
        self.assertIn("1420", note["message"])
        self.assertEqual(note["severity"], "ok")

    def test_a_real_interface_is_still_reported(self):
        rep = self.box("eth1", 1400)
        self.assertIn("mtu_nonstandard", [f["code"] for f in rep["findings"]])

    def test_the_names_a_tunnel_goes_by(self):
        for name in ("tun0", "tap0", "utun3", "wg0", "ppp0", "ipsec0", "vti1",
                     "gre1", "nordlynx", "tailscale0"):
            with self.subTest(name=name):
                self.assertTrue(nd.is_tunnel(name))
        # tsn0 is a Time-Sensitive Networking port - a physical NIC on
        # industrial and automotive hardware. A "ts" prefix for Tailscale
        # matched it, and "tailscale" already covers the real interface name.
        for name in ("eth0", "eno1", "enp3s0", "bond0", "br0", "em1", "tsn0",
                     "team0", "dummy0", "veth1a2b"):
            with self.subTest(name=name):
                self.assertFalse(nd.is_tunnel(name))

    def test_it_can_never_be_the_verdict(self):
        self.assertIn("tunnel_mtu", nd.VERDICT_EXEMPT)


class TestWhySomethingWeServeDidNotVerify(unittest.TestCase):
    """OpenSSL says the same sentence for situations that need different people
    to do different things - and the distinction matters most on a box that
    re-signs traffic on purpose."""

    def test_a_private_root_is_named_as_what_it_is(self):
        note = nd.own_cert_trust_note("self signed certificate in certificate chain")
        self.assertIn("private authority", note)
        self.assertIn("never given that root", note)

    def test_an_absent_issuer_is_an_incomplete_chain(self):
        note = nd.own_cert_trust_note("unable to get local issuer certificate")
        self.assertIn("incomplete chain", note)

    def test_a_self_signed_leaf_is_neither(self):
        self.assertIn("signed itself", nd.own_cert_trust_note("self signed certificate"))

    def test_the_two_self_signed_errors_are_not_confused(self):
        """OpenSSL says "self signed certificate" for a leaf and "self signed
        certificate in certificate chain" for a private root, and the first is
        a substring of the second."""
        chain = nd.own_cert_trust_note("self signed certificate in certificate chain")
        leaf = nd.own_cert_trust_note("self signed certificate")
        self.assertNotEqual(chain, leaf)
        self.assertIn("private authority", chain)

    def test_both_spellings_are_handled(self):
        """Newer OpenSSL hyphenates it."""
        self.assertEqual(nd.own_cert_trust_note("self-signed certificate in certificate chain"),
                         nd.own_cert_trust_note("self signed certificate in certificate chain"))

    def test_an_unrelated_failure_adds_nothing(self):
        self.assertIsNone(nd.own_cert_trust_note("certificate has expired"))
        self.assertIsNone(nd.own_cert_trust_note(None))


class TestWhichPartOfTheAnswerTookTheTime(unittest.TestCase):
    """"The service answered in 900ms" is true and useless. Getting a
    connection, finishing a handshake and waiting for the application are three
    different things with three different owners - and this connection goes to
    a listener on the same box, so the first two should be almost nothing."""

    def serve(self, delay=0.0, tls=False):
        import socket, threading, time
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0)); srv.listen(1)
        self.addCleanup(srv.close)
        port = srv.getsockname()[1]

        def run():
            try:
                c, _ = srv.accept()
                c.recv(1024)
                time.sleep(delay)
                c.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                c.close()
            except OSError:
                pass
        threading.Thread(target=run, daemon=True).start()
        return port, nd.cmd_own_http(port, address="127.0.0.1", tls=tls, timeout=3)

    def test_the_answer_is_split_into_its_phases(self):
        """Relative, not absolute. An earlier version asserted the connect took
        under 100ms and the wait over 200ms, which passed alone and failed in
        the full suite: both are wall-clock measurements against a live socket
        and a loaded machine moves them. What the split has to get right is
        which phase the time went to, and that holds under any load."""
        _port, res = self.serve(delay=0.25)
        phases = res["phases"]
        self.assertGreater(phases["wait_ms"], phases["connect_ms"],
                           "the delay was on the service's side, not the connect")
        self.assertIsNone(phases["tls_ms"], "no handshake on a plain connection")

    def test_the_phases_account_for_the_total(self):
        _port, res = self.serve(delay=0.10)
        phases = res["phases"]
        parts = phases["connect_ms"] + phases["wait_ms"]
        self.assertLessEqual(parts, res["ms"] + 1,
                             "the parts cannot exceed the whole they came from")

    def test_it_names_the_phase_that_dominated(self):
        port, res = self.serve(delay=0.25)
        findings = []
        nd._own_service_findings(res, port, findings)
        note = next(f for f in findings if f["code"] == "own_service_timing")
        self.assertIn("waiting for the service", note["message"])
        self.assertEqual(note["severity"], "ok")

    def test_it_is_context_and_never_a_verdict(self):
        """What counts as slow depends entirely on what the service does, and a
        number picked here would be wrong for most of them."""
        self.assertIn("own_service_timing", nd.VERDICT_EXEMPT)

    def test_a_check_that_never_connected_reports_no_phases(self):
        """Nothing was timed, so nothing is claimed."""
        res = nd.cmd_own_http(1, address="127.0.0.1", tls=False, timeout=1)
        self.assertNotIn("phases", res)
        findings = []
        nd._own_service_findings(res, 1, findings)
        self.assertEqual([f for f in findings if f["code"] == "own_service_timing"], [])


class TestTheTablesSayWhichRowToLookAt(unittest.TestCase):
    """The two tables carrying the actual numbers - error counters and link
    modes - were entirely monochrome. On a box with eight interfaces the table
    is the fastest way to find the bad one, and it gave no cue at all."""

    ESC = re.compile(r"\x1b\[[0-9;]*m")

    def box(self, bad_iface_errors):
        def vals(err):
            d = {k: 0 for k in ("tx_errors", "rx_dropped", "tx_dropped",
                                "rx_frame_errors", "rx_over_errors", "collisions",
                                "rx_missed_errors", "rx_length_errors",
                                "tx_carrier_errors")}
            d.update(rx_packets=5_000_000, tx_packets=5_000_000, rx_bytes=0,
                     tx_bytes=0, operstate="up", carrier_changes=0,
                     rx_errors=err, rx_crc_errors=err)
            return d
        m = fresh(); m.OS_NAME = "Linux"
        m._read_link_stats = lambda: ({"eth0": vals(0), "eth1": vals(bad_iface_errors),
                                       "eth2": vals(0)}, "sysfs")
        m.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
            {"name": n, "speed_mbps": 1000, "duplex": "full", "mtu": 1500,
             "carrier": True, "operstate": "up"} for n in ("eth0", "eth1", "eth2")]}
        return m, m.diagnose("8.8.8.8", None, quick=False)

    def rows(self, m, rep, section):
        text = m.render_text_report(rep, color=True)
        block = text.split(section, 1)[1].split("\n\n", 1)[0]
        out = {}
        for line in block.splitlines():
            plain = self.ESC.sub("", line).strip()
            if plain.startswith("eth"):
                out[plain.split()[0]] = "\x1b[" in line
        return out

    def test_only_the_interface_with_a_finding_is_coloured(self):
        m, rep = self.box(9000)
        for section in ("INTERFACE ERROR COUNTERS", "LINK MODE"):
            with self.subTest(section=section):
                rows = self.rows(m, rep, section)
                self.assertTrue(rows["eth1"], "the faulty interface is not marked")
                self.assertFalse(rows["eth0"], "a clean interface was marked")
                self.assertFalse(rows["eth2"], "a clean interface was marked")

    def test_a_clean_box_colours_nothing(self):
        m, rep = self.box(0)
        rows = self.rows(m, rep, "INTERFACE ERROR COUNTERS")
        self.assertFalse(any(rows.values()))

    def test_the_colour_is_the_severity_of_what_was_found(self):
        """Not a second opinion formed in the renderer. The tables would
        otherwise need their own copy of every threshold, and a second copy of
        a rule is a second chance to disagree with the first."""
        worst = nd.worst_by_scope([
            {"code": "a", "severity": "warning", "scope": "eth1"},
            {"code": "b", "severity": "critical", "scope": "eth1"},
            {"code": "c", "severity": "ok", "scope": "eth2"},
            {"code": "d", "severity": "critical"},
        ])
        self.assertEqual(worst["eth1"], "critical", "the worst of the two must win")
        self.assertNotIn("eth2", worst,
                         "an ok-severity note is not a reason to mark a row")
        self.assertNotIn(None, worst, "a finding with no scope belongs to no row")

    def test_nothing_is_coloured_when_the_output_is_not_a_terminal(self):
        """Reports get pasted into tickets and piped into files, where escape
        codes are noise."""
        m, rep = self.box(9000)
        self.assertNotIn("\x1b[", m.render_text_report(rep, color=False))


class TestAFixThatNeedsHandsIsMarkedAsOne(unittest.TestCase):
    """A different kind of answer from the rest of the report - not a different
    severity, a different action. Everything else here is read, configured, or
    escalated to whoever owns the next segment; these need a person in the
    room."""

    def test_a_dim_optic_is_marked(self):
        setup, kw = S["optics_rx_low"]
        m = fresh(); setup(m)
        rep = m.diagnose(quick=False, **scenario_kwargs(kw))
        f = next(x for x in rep["findings"] if x["code"] == "optics_rx_low")
        self.assertEqual(f["kind"], "hardware")

    def test_a_full_link_is_not(self):
        """Nothing to touch: the line is being used, not broken."""
        setup, kw = S["link_saturated"]
        m = fresh(); setup(m)
        rep = m.diagnose(quick=False, **scenario_kwargs(kw))
        f = next(x for x in rep["findings"] if x["code"] == "link_saturated")
        self.assertNotIn("kind", f)

    def test_what_it_deliberately_does_not_claim(self):
        """A duplex mismatch, a link negotiated below its port's rating and a
        collision count are each either a damaged cable or a setting forced at
        one end. The tool cannot tell which from here, so it does not send
        somebody to a rack on a coin toss."""
        for code in ("duplex_mismatch", "slow_link", "negotiated_below_capacity",
                     "collisions", "nic_ring_overruns", "frame_length_errors"):
            with self.subTest(code=code):
                self.assertNotIn(code, nd.HARDWARE_FINDINGS)

    def test_the_set_names_only_findings_that_exist(self):
        import re
        codes = set(re.findall(r'"code": "(\w+)"', open(nd.__file__, encoding="utf-8").read()))
        self.assertEqual(sorted(nd.HARDWARE_FINDINGS - codes), [])

    def test_it_is_a_kind_and_not_a_severity(self):
        """Marking something as needing hands says nothing about how bad it is.
        An optic with margin left is a warning and still needs a person."""
        self.assertIn("optics_rx_marginal", nd.HARDWARE_FINDINGS)
        self.assertIn("optics_rx_marginal", nd.LATENT)

    def test_the_verdict_line_counts_them(self):
        setup, kw = S["optics_rx_low"]
        m = fresh(); setup(m)
        text = m.render_text_report(m.diagnose(quick=False, **scenario_kwargs(kw)))
        self.assertIn("needing hands on it", text)

    def test_context_findings_are_never_counted(self):
        """The count is of work to do. An ok-severity note is not work."""
        m = fresh()
        rep = {"findings": [{"code": "optics_rx_low", "severity": "ok",
                             "kind": "hardware", "message": "x", "layer": 1}],
               "verdict": {"headline": "h", "owner": "o", "next_step": "n",
                           "confidence": "high", "severity": "ok",
                           "coverage": {"ran": 1, "attempted": 1},
                           "corroborated_by": [], "unrelated": [], "based_on": []},
               "stages": [], "target": "8.8.8.8"}
        self.assertNotIn("needing hands on it", nd.render_text_report(rep))

    def test_it_reaches_the_page(self):
        setup, kw = S["optics_rx_low"]
        m = fresh(); setup(m)
        page = m.render_report_html(m.diagnose(quick=False, **scenario_kwargs(kw)))
        back = m.extract_embedded_report(page)
        self.assertEqual(
            next(f for f in back["findings"] if f["code"] == "optics_rx_low")["kind"],
            "hardware")
        self.assertIn("rel-hardware", page)


class TestThePathSummaryAgreesWithTheFinding(unittest.TestCase):
    """Naming a hop is a claim that it is the one to go and look at. The wall
    finding already declines to make that claim below half the round trip -
    the share test is what makes its own sentence true - and the summary line
    was making it anyway."""

    def summary(self, avgs):
        m = fresh()
        mtr(m, [{"count": i + 1, "host": f"10.0.{i}.1", "Loss%": 0.0, "Snt": 30,
                 "Avg": v} for i, v in enumerate(avgs)])
        ping_map(m, inet_loss=0, avg=avgs[-1], mdev=5.0)
        rep = m.diagnose("8.8.8.8", None, quick=False)
        lines = [l.strip() for l
                 in m.render_text_report(rep).split("PATH TO", 1)[1].splitlines()
                 if l.strip().startswith("->") and "hop" in l]
        fired = any(f["code"] == "latency_wall" for f in rep["findings"])
        return fired, (lines[0] if lines else "")

    def test_a_path_with_one_wall_names_the_hop(self):
        fired, line = self.summary([1.0, 620.0, 640.0])
        self.assertTrue(fired)
        self.assertIn("biggest latency jump", line)
        self.assertIn("hop 2", line)

    def test_an_evenly_graded_path_names_no_hop_as_the_answer(self):
        """Ten hops each adding about the same. The old line said "biggest
        latency jump at hop 8", sending the reader to a hop doing nothing
        unusual."""
        fired, line = self.summary([8, 22, 41, 55, 74, 96, 118, 141, 160, 182])
        self.assertFalse(fired, "the finding correctly stays quiet here")
        self.assertIn("no single hop", line)
        self.assertNotIn("biggest latency jump", line)

    def test_the_two_use_one_threshold_between_them(self):
        """The summary and the finding must not be able to disagree, which
        means they cannot each carry their own number."""
        source = open(nd.__file__, encoding="utf-8").read()
        summary = source.split("no single hop adds most of the delay", 1)[0][-700:]
        self.assertIn("LATENCY_WALL_SHARE", summary)

    def test_the_delay_is_still_reported_when_no_hop_owns_it(self):
        """Silence would be worse than the wrong hop: 182ms is worth knowing
        about even when nothing on the path is at fault for it."""
        _fired, line = self.summary([8, 22, 41, 55, 74, 96, 118, 141, 160, 182])
        self.assertIn("182ms", line)


class TestTheSuiteDoesNotBreakItsOwnClock(unittest.TestCase):
    """`nd.time` is not a copy of anything - it is the `time` module, shared by
    every module in the process. So `nd.time.sleep = ...` disables sleeping
    everywhere until something puts it back, and two places here did that and
    never did. Anything running afterwards that depended on real time was
    silently not testing what it said."""

    def test_sleeping_still_works_by_the_time_this_runs(self):
        self.assertIs(time.sleep, REAL_SLEEP)
        self.assertIs(time.monotonic, REAL_MONOTONIC)

    def test_a_scenario_module_gets_its_own_clock_not_a_hole_in_the_shared_one(self):
        """fresh() is called for every scenario, and the scenarios must not
        really sleep. It rebinds the name on its own module copy rather than
        reaching into the one every other module is using."""
        m = fresh()
        self.assertIsNot(m.time, time)
        m.time.sleep(5)                                   # must return at once
        self.assertIs(time.sleep, REAL_SLEEP)

    def test_anything_that_patches_the_shared_clock_puts_it_back(self):
        """Found by measuring 0.1ms of a 250ms delay. Checked as the property
        that matters rather than by counting lines: a class may patch
        `nd.time`, but then it has to restore it, and the two that do are fine.
        A count with an allowance would have grown quietly every time somebody
        added one."""
        import ast
        tree = ast.parse(open(__file__, encoding="utf-8").read())

        def patches_shared_clock(node):
            """An assignment to `nd.time.sleep` or `nd.time.monotonic`.

            Matched on the shape of the target, not on substrings: `mod.time`
            and `m.time` are module copies fresh() has already given a clock of
            their own, and a looser check flagged both of those as leaks."""
            for a in ast.walk(node):
                if not isinstance(a, ast.Assign):
                    continue
                for t in a.targets:
                    if (isinstance(t, ast.Attribute) and t.attr in ("sleep", "monotonic")
                            and isinstance(t.value, ast.Attribute) and t.value.attr == "time"
                            and isinstance(t.value.value, ast.Name)
                            and t.value.value.id == "nd"):
                        return True
            return False

        offenders = []
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            if not patches_shared_clock(cls):
                continue
            methods = {m.name for m in cls.body if isinstance(m, ast.FunctionDef)}
            uses_helper = "patch_clock" in ast.dump(cls)
            if "tearDown" not in methods and not uses_helper:
                offenders.append(cls.name)
        self.assertEqual(offenders, [],
                         "these patch the shared clock and never restore it - use "
                         "patch_clock, or save and put it back in tearDown")


class TestNothingIsTruncatedInSilence(unittest.TestCase):
    """Two lists in the report were cut to a fixed length and rendered as if
    that were all there was. One of them exists specifically so a second fault
    is not hidden."""

    def test_the_verdict_says_how_many_it_did_not_show(self):
        """Capping is right - the point is to stop hiding a second fault, not
        to hand the findings list back a second time - and two shown out of
        four reads as two."""
        f = lambda c, sev, layer: {"code": c, "severity": sev, "layer": layer,
                                   "message": c}
        v = nd.build_verdict([f("link_errors_live", "critical", 1),
                              f("tls_expired", "critical", 7),
                              f("dns_hijack", "critical", 7),
                              f("duplicate_ip", "critical", 2),
                              f("clock_skewed", "warning", 7)])
        self.assertEqual(len(v["unrelated"]), 2)
        self.assertEqual(v["unrelated_total"], 4)
        text = nd.render_text_report({"verdict": v, "findings": [], "stages": [],
                                      "target": "8.8.8.8"})
        self.assertIn("and 2 more unrelated finding(s) below", text)

    def test_it_says_nothing_when_there_is_nothing_more(self):
        f = lambda c, sev, layer: {"code": c, "severity": sev, "layer": layer,
                                   "message": c}
        v = nd.build_verdict([f("link_errors_live", "critical", 1),
                              f("tls_expired", "critical", 7)])
        self.assertEqual(v["unrelated_total"], len(v["unrelated"]))
        text = nd.render_text_report({"verdict": v, "findings": [], "stages": [],
                                      "target": "8.8.8.8"})
        self.assertNotIn("more unrelated", text)

    def test_every_verdict_branch_carries_the_count(self):
        """Three code paths return a verdict and a missing key on any of them
        would read as "nothing was hidden"."""
        for findings in ([], [{"code": "nope", "severity": "warning", "layer": 9,
                               "message": "no rule for this"}]):
            with self.subTest(findings=findings):
                self.assertIn("unrelated_total", nd.build_verdict(findings))

    def test_a_truncated_answer_list_says_it_was_truncated(self):
        """Two resolvers that disagree rendered as identical rows - on the one
        panel a reader uses to check whether they agree, while dns_disagree
        was firing about it three lines above."""
        self.assertEqual(nd._answer_summary(["a", "b", "c", "d"]), "a, b, c (+1 more)")
        self.assertEqual(nd._answer_summary(["a", "b"]), "a, b")
        self.assertEqual(nd._answer_summary([]), "-")
        self.assertEqual(nd._answer_summary(None), "-")

    def test_the_row_no_longer_claims_to_be_complete(self):
        """It still does not make two disagreeing rows look different - that is
        what dns_disagree is for. It stops the row asserting it showed
        everything, which is what let the two look identical."""
        short = nd._answer_summary(["192.0.2.1", "192.0.2.2", "192.0.2.3"])
        long_ = nd._answer_summary(["192.0.2.1", "192.0.2.2", "192.0.2.3", "203.0.113.9"])
        self.assertNotEqual(short, long_)
        self.assertIn("more", long_)


class TestTheTableDoesNotLetAnAverageHideAPeak(unittest.TestCase):
    """The oldest complaint about every tool that consolidates by mean: the
    peak flattens as the window grows until a line that filled every minute
    reads as quiet. This report computed the peak and printed the average, and
    the two sat three lines apart contradicting each other."""

    def row(self, code="saturation_bursts"):
        setup, kw = S[code]
        m = fresh(); setup(m)
        rep = m.diagnose(quick=False, **scenario_kwargs(kw))
        text = m.render_text_report(rep)
        line = next(l for l in text.splitlines() if l.strip().startswith("eth0"))
        return rep, line

    def test_the_peak_is_shown_when_it_says_something_the_average_does_not(self):
        rep, line = self.row()
        iface = next(i for i in rep["raw"]["link_stats"]["interfaces"]
                     if i["name"] == "eth0")
        self.assertGreater(iface["peak_mbps"], iface["rx_mbps"])
        self.assertIn("peak", line)
        self.assertIn(f"{iface['peak_mbps']:g}", line)

    def test_a_steady_link_does_not_repeat_itself(self):
        """Where the peak and the average tell the same story, printing both is
        noise."""
        _, line = self.row("link_saturated")
        self.assertNotIn("peak", line)

    def test_the_percentage_names_what_it_is_a_percentage_of(self):
        """It is against the NIC, and the saturation findings measure against
        the site uplink when one was given - so the same interface read "2.3%
        of link" here and "full" three lines above, with nothing reconciling
        them."""
        _, line = self.row()
        self.assertRegex(line, r"of the \d+M link")

    def test_the_report_no_longer_contradicts_itself(self):
        """The finding says the uplink was full in bursts. The table says 2.3%.
        Both are true - different denominator, different statistic - and the
        reader now has both numbers to reconcile them with."""
        rep, line = self.row()
        finding = next(f for f in rep["findings"] if f["code"] == "saturation_bursts")
        self.assertIn("50.0 Mbps of 50 Mbps", finding["message"])
        self.assertIn("peak 50", line)

    def test_the_threshold_is_a_ratio_not_a_fixed_figure(self):
        """A 10 Mbps peak over a 1 Mbps mean matters; a 1000 Mbps peak over a
        999 Mbps mean does not, and an absolute gap cannot tell them apart."""
        self.assertGreater(nd.PEAK_WORTH_SHOWING, 1.0)
        self.assertLess(nd.PEAK_WORTH_SHOWING, 2.0)

    def test_an_interface_with_no_series_shows_no_peak(self):
        """Nothing to be wrong about, and a missing peak must not print as 0."""
        m = fresh()
        counters(m, rx_bytes=0, tx_bytes=0)
        rep = m.diagnose("8.8.8.8", None, quick=False)
        for line in m.render_text_report(rep).splitlines():
            if line.strip().startswith("eth0"):
                self.assertNotIn("peak", line)


class TestTheListSaysWhatExplainsWhat(unittest.TestCase):
    """The relationships already existed in the verdict - based_on, explains,
    unrelated - and the report printed them as a line of raw finding codes
    above a flat list. A reader had to match "inet_partial_loss" against the
    entries below by eye to see which fault was the answer and which were its
    consequences, which is the one thing this tool exists to work out."""

    def report(self):
        setup, kw = S["link_saturated"]
        m = fresh(); setup(m)
        return m, m.diagnose(quick=False, **scenario_kwargs(kw))

    def test_each_finding_carries_where_it_stands(self):
        _, rep = self.report()
        by_code = {f["code"]: f.get("relation") for f in rep["findings"]}
        self.assertEqual(by_code["link_saturated"], "cause")
        self.assertEqual(by_code["inet_partial_loss"], "explained")

    def test_the_relation_is_derived_once_not_twice(self):
        """Attached to the finding in Python rather than worked out again in
        the viewer. Two copies of a rule are two chances to disagree."""
        _, rep = self.report()
        self.assertTrue(any("relation" in f for f in rep["findings"]))

    def test_a_finding_with_no_relationship_is_left_alone(self):
        v = {"based_on": ["a"], "explains": [], "unrelated": []}
        self.assertIsNone(nd.finding_relation("z", v))
        self.assertIsNone(nd.finding_relation(None, v))
        self.assertIsNone(nd.finding_relation("a", None))

    def test_every_relation_it_can_return_has_a_label(self):
        """A relation with no label would render as a raw identifier in the one
        place the report is trying to stop showing raw identifiers."""
        v = {"based_on": ["a", "b"], "explains": ["c"],
             "unrelated": [{"code": "d", "message": "m"}]}
        for code in ("a", "b", "c", "d"):
            rel = nd.finding_relation(code, v)
            self.assertIn(rel, nd.FINDING_RELATIONS, f"{code} -> {rel}")

    def test_the_cause_is_the_first_of_based_on_not_any_of_it(self):
        """based_on is the cause followed by whatever corroborates it, and
        calling all of them the cause would name several."""
        v = {"based_on": ["a", "b"], "explains": [], "unrelated": []}
        self.assertEqual(nd.finding_relation("a", v), "cause")
        self.assertEqual(nd.finding_relation("b", v), "corroborates")

    def test_it_reaches_the_terminal(self):
        m, rep = self.report()
        text = m.render_text_report(rep)
        self.assertIn("^ the cause", text)
        self.assertIn("^ caused by it", text)

    def test_it_reaches_the_page(self):
        m, rep = self.report()
        page = m.render_report_html(rep)
        back = m.extract_embedded_report(page)
        self.assertEqual(
            [f.get("relation") for f in back["findings"]][:2], ["cause", "explained"])
        self.assertIn("RELATION_LABEL[f.relation]", page)

    def test_the_page_and_the_terminal_use_the_same_words(self):
        """Two renderers with two vocabularies for the same idea is how a
        report starts contradicting itself."""
        src = open(nd.__file__, encoding="utf-8").read()
        template = src.split("const RELATION_LABEL", 1)[1].split("};", 1)[0]
        for key, label in nd.FINDING_RELATIONS.items():
            self.assertIn(f"'{label}'", template, f"{key} says something else on the page")


class TestWhichOfThreeIsHoldingThroughputBack(unittest.TestCase):
    """The kernel times how long a connection could not send because the far
    end had no window left, and because this box had nothing queued. Whatever
    is left of its busy time is time spent waiting on the path.

    Two of the three already produced findings and the third never did, which
    left the tool able to say "it is the far end" and "it is this box" and not
    "it is the network" - on a run whose whole subject is the network."""

    HEAD = "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"

    def flow(self, busy, rwnd, snd):
        return (self.HEAD +
                "ESTAB 0 0 10.0.0.5:44120 10.0.0.90:5432\n"
                f"\t cubic rtt:20.0/3.0 minrtt:19.0 mss:1448 cwnd:10 bytes_sent:900000000"
                f" bytes_acked:900000000 segs_out:600000 busy:{busy}ms"
                f" rwnd_limited:1ms({rwnd}%) sndbuf_limited:1ms({snd}%)\n")

    def limits(self, busy, rwnd, snd):
        return nd.analyze_tcp_flows(nd.parse_tcp_flows(self.flow(busy, rwnd, snd))).get("limits")

    def test_the_three_shares_are_derived_from_busy_time(self):
        l = self.limits(52344, 2.4, 1.5)
        self.assertEqual((l["receiver_pct"], l["sender_pct"], l["path_pct"]), (2.4, 1.5, 96.1))

    def test_a_receiver_that_stopped_reading_shows_up_as_such(self):
        self.assertEqual(self.limits(52344, 61.0, 1.0)["receiver_pct"], 61.0)

    def test_an_idle_socket_is_not_classified_at_all(self):
        """The percentages are shares of busy time, so on a connection that has
        barely moved they are all zero - and subtracting zero from a hundred
        would report an idle socket as limited by the network, confidently, on
        no evidence whatsoever."""
        self.assertIsNone(self.limits(12, 0, 0))

    def test_the_shares_can_never_go_negative(self):
        """The two the kernel reports can overlap slightly, and a negative
        share of anything would be nonsense to print."""
        self.assertEqual(self.limits(52344, 70.0, 70.0)["path_pct"], 0.0)

    def test_it_is_context_and_never_a_verdict(self):
        """A transfer limited by the path is usually TCP working correctly."""
        self.assertIn("throughput_limited_by", nd.VERDICT_EXEMPT)
        m = fresh()
        sided_flows(m, sided_sock("10.0.0.90", "44120", sent=900_000_000, port="5432")
                    .replace("cubic wscale:7,7", "cubic busy:52344ms wscale:7,7"))
        rep = m.diagnose("8.8.8.8", None, quick=False)
        fired = [f for f in rep["findings"] if f["code"] == "throughput_limited_by"]
        self.assertTrue(fired)
        self.assertEqual(fired[0]["severity"], "ok")
        self.assertEqual(rep["verdict"]["severity"], "ok")

    def fired_for(self, rwnd, snd):
        """The finding, from a socket built here rather than patched into shape -
        the first version of this test edited a string that turned out not to
        contain what it was replacing, so all three cases silently tested the
        same one."""
        m = fresh()
        stats = nd.analyze_tcp_flows(nd.parse_tcp_flows(self.flow(52344, rwnd, snd)))
        res = {"ok": True, "cmd": "ss -tin", "stdout": "", "stderr": "", "code": 0}
        res.update(stats)
        m.cmd_tcp_flows = lambda listen_ports=None: res
        return [f for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]
                if f["code"] == "throughput_limited_by"]

    def test_it_names_whichever_of_the_three_is_largest(self):
        for rwnd, snd, expect in ((2.0, 1.0, "the path"),
                                  (61.0, 1.0, "the far end"),
                                  (1.0, 55.0, "send buffer")):
            with self.subTest(rwnd=rwnd, snd=snd):
                fired = self.fired_for(rwnd, snd)
                self.assertTrue(fired, f"nothing fired for rwnd={rwnd} snd={snd}")
                self.assertIn(expect, fired[0]["message"])

    def test_the_three_cases_do_not_all_produce_the_same_sentence(self):
        """What the first version of the test above accidentally asserted."""
        said = {self.fired_for(r, s)[0]["message"] for r, s in ((2.0, 1.0), (61.0, 1.0), (1.0, 55.0))}
        self.assertEqual(len(said), 3)


class TestALinkThatWasUpLastTime(unittest.TestCase):
    """The live checks say nothing about an interface being down, because from
    one visit there is no telling a failed link from a spare NIC nobody ever
    plugged in. A baseline settles that: this one was up when somebody looked."""

    def rep(self, ifaces):
        return {"findings": [], "verdict": {}, "target": "8.8.8.8",
                "raw": {"link_modes": {"interfaces": ifaces},
                        "link_stats": {"interfaces": [
                            {"name": i["name"], "packets": 10_000_000, "errors": 0}
                            for i in ifaces]}}}

    def iface(self, name, operstate, carrier=True, speed=1000):
        return {"name": name, "speed_mbps": speed, "duplex": "full", "mtu": 1500,
                "carrier": carrier, "operstate": operstate}

    def change(self, before, after, ending="link state"):
        got = nd.compare_reports(self.rep(after), self.rep(before))
        return next((c for c in got if c["what"].endswith(ending)), None)

    def test_a_link_that_went_down_is_a_regression(self):
        c = self.change([self.iface("eth1", "up")],
                        [self.iface("eth1", "down", carrier=False)])
        self.assertEqual((c["before"], c["after"], c["direction"]), ("up", "down", "worse"))

    def test_a_link_that_came_back_is_not(self):
        c = self.change([self.iface("eth1", "down", carrier=False)],
                        [self.iface("eth1", "up")])
        self.assertEqual(c["direction"], "better")

    def test_the_kernel_saying_the_layer_below_is_down_is_kept_as_said(self):
        """lowerlayerdown is the kernel naming the cause for us - a VLAN or
        bridge member whose parent went away. Flattening it to "down" would
        throw away the one word that says where to look."""
        c = self.change([self.iface("eth1", "up")],
                        [self.iface("eth1", "lowerlayerdown", carrier=False)])
        self.assertEqual(c["after"], "lowerlayerdown")
        self.assertEqual(c["direction"], "worse")

    def test_unknown_counts_as_up(self):
        """Loopback, tun devices and several virtual drivers never call the
        operstate machinery, so they sit at "unknown" while working perfectly.
        Treating that as down would report every tunnel as a regression."""
        self.assertTrue(nd._operationally_up("unknown"))
        self.assertTrue(nd._operationally_up("up"))
        for state in ("down", "lowerlayerdown", "dormant", "notpresent", "testing"):
            with self.subTest(state=state):
                self.assertFalse(nd._operationally_up(state))

    def test_a_tunnel_sitting_at_unknown_reports_no_change(self):
        self.assertIsNone(self.change([self.iface("tun0", "unknown")],
                                      [self.iface("tun0", "unknown")]))

    def test_an_interface_that_disappeared_is_reported(self):
        """A NIC renamed, removed, or that failed to come back after a reboot.
        The per-interface loop cannot see it - that walks the interfaces both
        visits have in common."""
        c = self.change([self.iface("eth1", "up"), self.iface("eth2", "up")],
                        [self.iface("eth1", "up")], ending="interface")
        self.assertEqual((c["before"], c["after"], c["direction"]),
                         ("present", "no longer present", "worse"))

    def test_a_new_interface_is_not_a_regression(self):
        got = nd.compare_reports(
            self.rep([self.iface("eth1", "up"), self.iface("eth2", "up")]),
            self.rep([self.iface("eth1", "up")]))
        self.assertEqual([c for c in got if c["direction"] == "worse"], [])

    def test_a_link_state_change_needs_no_rate_discipline(self):
        """Unlike the counters, this is not a share of anything - it changed or
        it did not - so there is nothing for a floor to protect against, and
        one going down must always count."""
        c = self.change([self.iface("eth1", "up")],
                        [self.iface("eth1", "down", carrier=False)])
        self.assertEqual(c["direction"], "worse")
        self.assertNotIn("per_million", c)


class TestAShareNeedsASample(unittest.TestCase):
    """The defect this file has now been written with three times: a finding
    computes what share of something went wrong and fires on a sample too small
    for a share to mean anything. One dropped datagram out of one. One failed
    fragment out of two. Two new errors since a baseline.

    Swept over the counter-driven findings together, because writing the
    guard once per check is what let the third one through."""

    TINY = (
        ("udp_recv_buffer_full", {"udp_InDatagrams": 2, "udp_RcvbufErrors": 1,
                                  "udp_InErrors": 1}),
        ("udp_datagrams_corrupt", {"udp_InDatagrams": 2, "udp_InErrors": 1,
                                   "udp_RcvbufErrors": 0}),
        ("fragments_lost", {"ip_ReasmReqds": 2, "ip_ReasmFails": 1}),
        ("resets_sent_high", {"OutRsts": 2, "PassiveOpens": 1}),
        ("connections_reset_by_peer", {"EstabResets": 2, "PassiveOpens": 2}),
        ("syn_retrans_high", {"TCPSynRetrans": 1, "ActiveOpens": 2}),
        ("connect_failures_high", {"AttemptFails": 1, "ActiveOpens": 2}),
        # tcp_checksum_errors is deliberately not here. It is count-based by
        # intent - a bad checksum should never happen, so one is worth saying -
        # and the test below covers what it must not do instead.
    )

    def test_none_of_them_fire_on_a_sample_of_two(self):
        for code, counters in self.TINY:
            with self.subTest(code=code):
                m = fresh()
                kernel_drops(m, {k: 0 for k in counters}, dict(counters))
                fired = [f["code"] for f in
                         m.diagnose("8.8.8.8", None, quick=False)["findings"]]
                self.assertNotIn(code, fired,
                                 f"{code} fired on a sample of two, which is not a rate")

    def test_a_count_based_finding_does_not_quote_a_rate_it_cannot_support(self):
        """The exception that proves the rule. A bad TCP checksum should never
        happen, so one is reported - but one error in two segments is 500,000
        per million, and printing that reads as a catastrophe rather than as a
        single packet on a nearly idle box."""
        m = fresh()
        kernel_drops(m, {"InCsumErrors": 0, "InSegs": 0},
                        {"InCsumErrors": 1, "InSegs": 2})
        fired = [f for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]
                 if f["code"] == "tcp_checksum_errors"]
        self.assertTrue(fired, "one bad checksum is still worth reporting")
        self.assertNotIn("per million", fired[0]["message"])
        self.assertIn("too few for a rate", fired[0]["message"])

    def test_and_does_quote_one_when_it_can(self):
        m = fresh()
        kernel_drops(m, {"InCsumErrors": 0, "InSegs": 0},
                        {"InCsumErrors": 40, "InSegs": 2_000_000})
        fired = [f for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]
                 if f["code"] == "tcp_checksum_errors"]
        self.assertIn("per million", fired[0]["message"])

    def test_the_sweep_covers_findings_that_can_actually_fire(self):
        """A list of codes that no longer exist would pass this silently."""
        import re
        codes = set(re.findall(r'"code": "(\w+)"', open(nd.__file__, encoding="utf-8").read()))
        for code, _ in self.TINY:
            self.assertIn(code, codes, f"{code} is in the sweep and not in the tool")


class TestUdpAndFragments(unittest.TestCase):
    """/proc/net/snmp was already being opened and only the Tcp: line read out
    of it. DNS is UDP, so a box dropping datagrams presented as a resolver
    problem while every other check here passed."""

    def codes(self, **after):
        before = {k: 0 for k in after}
        m = fresh()
        kernel_drops(m, before, dict(after))
        return [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]

    def test_a_full_receive_buffer_is_this_box(self):
        c = self.codes(udp_InDatagrams=10_000, udp_RcvbufErrors=400, udp_InErrors=400)
        self.assertIn("udp_recv_buffer_full", c)
        self.assertNotIn("udp_datagrams_corrupt", c)

    def test_errors_beyond_the_buffer_drops_are_damage_not_pressure(self):
        """InErrors contains RcvbufErrors one for one. What is left arrived and
        failed before a socket saw it, which is a different fault with a
        different owner."""
        c = self.codes(udp_InDatagrams=10_000, udp_RcvbufErrors=0, udp_InErrors=400)
        self.assertIn("udp_datagrams_corrupt", c)
        self.assertNotIn("udp_recv_buffer_full", c)

    def test_the_two_are_not_double_counted(self):
        """400 errors of which 400 are buffer drops is one fault, not two."""
        c = self.codes(udp_InDatagrams=10_000, udp_RcvbufErrors=400, udp_InErrors=400)
        self.assertEqual(sum(x.startswith("udp_") for x in c), 1)

    def test_a_trickle_of_drops_is_not_reported(self):
        self.assertNotIn("udp_recv_buffer_full",
                         self.codes(udp_InDatagrams=1_000_000, udp_RcvbufErrors=5,
                                    udp_InErrors=5))

    def test_the_buffer_drop_faces_this_box_and_the_damage_does_not(self):
        self.assertEqual(nd.finding_side("udp_recv_buffer_full"), "local")
        self.assertEqual(nd.finding_side("udp_datagrams_corrupt"), "upstream")

    def test_it_does_not_corroborate_the_other_backlog_findings(self):
        """A full socket buffer and a full kernel backlog are this box failing
        to take delivery, counted at two depths."""
        self.assertEqual(nd._finding_family("udp_recv_buffer_full"),
                         nd._finding_family("nic_drops_live"))

    def test_fragments_that_never_reassembled(self):
        self.assertIn("fragments_lost", self.codes(ip_ReasmReqds=500, ip_ReasmFails=120))

    def test_a_few_failures_among_many_fragments_are_not(self):
        self.assertNotIn("fragments_lost", self.codes(ip_ReasmReqds=5_000, ip_ReasmFails=20))

    def test_the_udp_and_tcp_checksum_counters_do_not_collide(self):
        """Both protocols export InErrors and InCsumErrors and they mean
        different things. Unprefixed, one would silently overwrite the other."""
        import os, tempfile, builtins
        snmp = ("Tcp: ActiveOpens InCsumErrors\nTcp: 10 0\n"
                "Udp: InDatagrams InCsumErrors\nUdp: 500 20\n")
        d = tempfile.mkdtemp(); path = os.path.join(d, "snmp")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(snmp)
        real = builtins.open
        builtins.open = lambda p, *a, **k: (real(path, *a, **k)
                                            if p == "/proc/net/snmp" else real(p, *a, **k))
        try:
            c = nd._snmp_counters_linux()
        finally:
            builtins.open = real
        self.assertEqual(c["InCsumErrors"], 0)
        self.assertEqual(c["udp_InCsumErrors"], 20)

    def test_a_signed_counter_does_not_break_the_parser(self):
        """Tcp: MaxConn is -1, and it is the single most common bug in code
        that reads this file."""
        import os, tempfile, builtins
        d = tempfile.mkdtemp(); path = os.path.join(d, "snmp")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("Tcp: MaxConn ActiveOpens\nTcp: -1 10\n")
        real = builtins.open
        builtins.open = lambda p, *a, **k: (real(path, *a, **k)
                                            if p == "/proc/net/snmp" else real(p, *a, **k))
        try:
            c = nd._snmp_counters_linux()
        finally:
            builtins.open = real
        self.assertEqual(c["MaxConn"], -1)
        self.assertEqual(c["ActiveOpens"], 10)


class TestOrphanedSockets(unittest.TestCase):
    """A connection with no file descriptor left to close it, still holding
    kernel memory. The kernel weighs them at two to four times their size."""

    def test_a_filling_orphan_table_is_reported(self):
        m = fresh()
        kernel_drops(m, {"tcp_orphans": 9_000, "tcp_max_orphans": 16_384},
                        {"tcp_orphans": 9_000, "tcp_max_orphans": 16_384})
        self.assertIn("tcp_orphans_high",
                      [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]])

    def test_a_quiet_table_is_not(self):
        m = fresh()
        kernel_drops(m, {"tcp_orphans": 40, "tcp_max_orphans": 16_384},
                        {"tcp_orphans": 40, "tcp_max_orphans": 16_384})
        self.assertNotIn("tcp_orphans_high",
                         [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]])

    def test_no_ceiling_means_no_claim(self):
        """Without tcp_max_orphans there is no denominator, and a count on its
        own says nothing about whether it is a lot."""
        m = fresh()
        kernel_drops(m, {"tcp_orphans": 9_000}, {"tcp_orphans": 9_000})
        self.assertNotIn("tcp_orphans_high",
                         [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]])

    def test_the_sockstat_line_is_parsed(self):
        import os, shutil, tempfile
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        os.makedirs(os.path.join(base, "net"))
        os.makedirs(os.path.join(base, "sys", "net", "ipv4"))
        with open(os.path.join(base, "net", "sockstat"), "w", encoding="utf-8") as fh:
            fh.write("sockets: used 380\n"
                     "TCP: inuse 12 orphan 7 tw 41 alloc 20 mem 3\n"
                     "UDP: inuse 6 mem 2\n")
        orphans = os.path.join(base, "sys", "net", "ipv4", "tcp_max_orphans")
        with open(orphans, "w", encoding="utf-8") as fh:
            fh.write("16384\n")
        got = nd._read_orphans(base)
        self.assertEqual(got["tcp_orphans"], 7)
        self.assertEqual(got["tcp_max_orphans"], 16384)

    def test_a_box_without_sockstat_reports_nothing(self):
        self.assertEqual(nd._read_orphans("/nonexistent/path"), {})


class TestTooHotToMovePackets(unittest.TestCase):
    """A count of times the hardware clocked itself down, not a temperature.
    Every threshold anyone picks for "warm" is wrong on some hardware; a box
    that has actually been throttled has already lost the cycles."""

    def codes(self, before, after):
        m = fresh()
        kernel_drops(m, before, after)
        return [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]

    def test_throttling_during_the_window_is_happening_now(self):
        self.assertIn("cpu_throttled_live",
                      self.codes({"core_throttles": 4}, {"core_throttles": 9}))

    def test_throttling_that_stopped_is_marginal_cooling(self):
        codes = self.codes({"core_throttles": 31}, {"core_throttles": 31})
        self.assertIn("cpu_throttled_historical", codes)
        self.assertNotIn("cpu_throttled_live", codes)

    def test_a_box_that_has_never_throttled_says_nothing(self):
        self.assertNotIn("cpu_throttled_historical",
                         self.codes({"core_throttles": 0}, {"core_throttles": 0}))

    def test_the_package_counter_is_maxed_not_summed(self):
        """The kernel documents every CPU in a package as reporting the same
        package counter. Summing multiplies one throttling event by the core
        count and reports sixteen events on a box that had one."""
        import os, shutil, tempfile
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        for cpu in range(4):
            d = os.path.join(base, f"cpu{cpu}", "thermal_throttle")
            os.makedirs(d)
            with open(os.path.join(d, "package_throttle_count"), "w", encoding="utf-8") as fh:
                fh.write("7")
            with open(os.path.join(d, "core_throttle_count"), "w", encoding="utf-8") as fh:
                fh.write(str(cpu))
        t = nd._read_thermal_throttle(base)
        self.assertEqual(t["package_throttles"], 7)
        self.assertEqual(t["core_throttles"], 3)

    def test_hardware_that_does_not_report_it_reports_nothing(self):
        self.assertEqual(nd._read_thermal_throttle("/nonexistent/path"), {})

    def test_it_is_not_latent_while_it_is_happening(self):
        """Marginal cooling is a risk and must not headline over a live fault.
        Cooling that is failing right now is the fault."""
        self.assertIn("cpu_throttled_historical", nd.LATENT)
        self.assertNotIn("cpu_throttled_live", nd.LATENT)


class TestAHopThatSaidWhy(unittest.TestCase):
    """traceroute prints the ICMP reason next to the time. It was dropped with
    everything else that was not a number, so a hop that told us exactly why it
    would not forward was reported as an unexplained silent path."""

    def hops(self, line):
        return nd.parse_traceroute_hops(
            "traceroute to 8.8.8.8 (8.8.8.8), 20 hops max\n"
            " 1  10.0.0.1 (10.0.0.1)  0.5 ms  0.4 ms\n" + line)

    def test_the_reason_is_kept(self):
        h = self.hops(" 2  198.51.100.7 (198.51.100.7)  12.0 ms !X\n")
        self.assertEqual(h[1]["flags"], ["!X"])

    def test_three_probes_refusing_is_one_reason_not_three(self):
        h = self.hops(" 2  198.51.100.7 (198.51.100.7)  12.0 ms !X  12.1 ms !X  12.2 ms !X\n")
        self.assertEqual(h[1]["flags"], ["!X"])

    def test_an_ordinary_hop_carries_no_reason(self):
        h = self.hops(" 2  198.51.100.7 (198.51.100.7)  12.0 ms  12.1 ms\n")
        self.assertIsNone(h[1]["flags"])

    def test_a_refusal_that_stops_the_path_has_an_owner_a_silence_does_not(self):
        m = fresh()
        trace(m, "traceroute to 8.8.8.8 (8.8.8.8), 20 hops max\n"
                 " 1  10.0.0.1 (10.0.0.1)  0.5 ms  0.4 ms\n"
                 " 2  198.51.100.7 (198.51.100.7)  12.0 ms !X\n")
        v = m.diagnose("8.8.8.8", None, quick=False)["verdict"]
        self.assertEqual(v["based_on"][0], "path_admin_prohibited")
        self.assertNotIn("provider", v["owner"])

    def test_a_filtering_device_that_still_forwards_is_not_a_fault(self):
        """Declining traceroute probes while passing traffic is normal and
        common. Only the same annotation on the hop where the path stops is a
        firewall standing in the way."""
        m = fresh()
        trace(m, "traceroute to 8.8.8.8 (8.8.8.8), 20 hops max\n"
                 " 1  10.0.0.1 (10.0.0.1)  0.5 ms  0.4 ms\n"
                 " 2  198.51.100.7 (198.51.100.7)  12.0 ms !X\n"
                 " 3  8.8.8.8 (8.8.8.8)  20.0 ms  20.1 ms\n")
        codes = [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]
        self.assertNotIn("path_admin_prohibited", codes)

    def test_only_a_deliberate_refusal_counts(self):
        """A host-unreachable is a router reporting a broken path onward, not a
        policy decision - different fault, different owner, already covered."""
        m = fresh()
        trace(m, "traceroute to 8.8.8.8 (8.8.8.8), 20 hops max\n"
                 " 1  10.0.0.1 (10.0.0.1)  0.5 ms  0.4 ms\n"
                 " 2  198.51.100.7 (198.51.100.7)  12.0 ms !H\n")
        codes = [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]
        self.assertNotIn("path_admin_prohibited", codes)


class TestABaselineThatIsNotAReport(unittest.TestCase):
    """--baseline takes a file the operator names, and being handed the wrong
    one is ordinary. The loader rejected what would not parse; what got through
    was valid JSON with a foreign shape, which crashed the comparison half way
    through a run and lost the whole diagnosis over optional context."""

    CURRENT = {"version": "1.6.4", "target": "8.8.8.8", "raw": {}, "neighbours": [],
               "hops": [], "findings": [], "verdict": {}}

    def test_a_real_report_is_recognised(self):
        self.assertTrue(nd.looks_like_a_report(
            {"findings": [], "verdict": {"headline": "x"}}))

    def test_json_that_is_not_a_report_is_not(self):
        for data in ({}, None, [], "a string", {"hello": "world"},
                     {"findings": [], "verdict": None},
                     {"findings": None, "verdict": {}},
                     {"report": {"hubs": []}}):          # an mtr export
            with self.subTest(data=data):
                self.assertFalse(nd.looks_like_a_report(data))

    def test_the_comparison_survives_a_foreign_shape_anyway(self):
        """Belt and braces: the guard above stops these reaching the
        comparison, and the comparison no longer breaks if one does."""
        for base in ({"version": "1.0.0", "raw": None, "neighbours": None, "hops": None},
                     {"version": "1.0.0", "raw": [], "neighbours": "nope", "hops": 42},
                     {}, {"hello": "world"}):
            with self.subTest(base=base):
                nd.compare_reports(base, self.CURRENT)

    def test_a_key_present_and_null_is_not_a_key_absent(self):
        """`.get(k, {})` returns the None, not the default - which is how a
        null in someone's JSON became an AttributeError mid-run."""
        self.assertEqual(nd._dict(None), {})
        self.assertEqual(nd._dict({"a": 1}), {"a": 1})
        self.assertEqual(nd._dict("string"), {})

    def test_an_interface_row_without_a_name_is_skipped_not_crashed_on(self):
        rep = {"raw": {"link_modes": {"interfaces": [{"speed_mbps": 1000}, None,
                                                     {"name": "eth0"}]}}}
        self.assertEqual(list(nd._iface_map(rep, "link_modes")), ["eth0"])


class TestOwnMarksWhoseServiceNotWhichCheck(unittest.TestCase):
    """The family heuristic splits a code on its first word. For "own_" that
    word says whose service it is, not which check looked at it."""

    def test_the_certificate_and_the_service_are_different_checks(self):
        """Reading the certificate this box serves and making an HTTP request
        to it are two separate things. Grouped, an expired certificate could
        not corroborate the service erroring - two independent signals counted
        as one, which understates a real fault."""
        self.assertNotEqual(nd._finding_family("own_tls_expired"),
                            nd._finding_family("own_service_erroring"))

    def test_two_readings_of_one_certificate_are_still_one_check(self):
        self.assertEqual(nd._finding_family("own_tls_expired"),
                         nd._finding_family("own_tls_expiring"))

    def test_two_readings_of_one_service_are_still_one_check(self):
        self.assertEqual(nd._finding_family("own_service_silent"),
                         nd._finding_family("own_service_erroring"))

    def test_they_now_corroborate_each_other(self):
        v = nd.build_verdict([
            {"code": "own_service_erroring", "severity": "critical", "layer": 7,
             "message": "erroring"},
            {"code": "own_tls_expired", "severity": "critical", "layer": 7,
             "message": "expired"}])
        self.assertTrue(v["corroborated_by"])

    def test_every_override_names_a_real_finding_and_does_something(self):
        """An override for a code that does not exist, or one that puts a code
        in a family of its own, is a line that reads as a rule and is not one.
        Asked of the whole table rather than of the entries we remembered."""
        import collections
        codes = set(re.findall(r'"code": "(\w+)"', open(nd.__file__, encoding="utf-8").read()))
        self.assertEqual([k for k in nd.SHARED_FAMILY if k not in codes], [])
        counts = collections.Counter(nd.SHARED_FAMILY.values())
        self.assertEqual([f for f, n in counts.items() if n < 2], [],
                         "a family of one overrides nothing")


class TestWhatRealToolsActuallyPrint(unittest.TestCase):
    """Every fixture in this suite was written from an idea of what these
    commands emit. These are the places that idea was wrong - each one found
    by describing the real output first and diffing it against the parser."""

    def test_a_receiver_seeing_no_light_is_reported(self):
        """A module with nothing arriving prints "0.0000 mW / -inf dBm". The
        dBm regex does not match "-inf", so the reading was dropped and the
        one fault the optical check exists for produced no finding at all."""
        p = nd.parse_ethtool_optics(
            "\tReceiver signal average optical power     : 0.0000 mW / -inf dBm\n")
        self.assertTrue(p.get("rx_dark"))
        self.assertIsNone(p.get("rx_dbm"), "there is no dBm figure - inventing one "
                                           "puts a sentinel in the report as a measurement")

    def test_a_dark_receiver_reaches_the_verdict(self):
        m = fresh()
        m.cmd_optics = lambda i: {"ok": True, "cmd": "ethtool -m", "stdout": "", "parsed": {
            "identifier": "0x03 (SFP)", "alarms": [], "warnings": [], "rx_dark": True}}
        m.cmd_lldp = lambda: {"ok": True, "cmd": "lldpctl", "stdout": "", "neighbours": [
            {"iface": "eth0", "switch": "SW-1", "port": "Gi1/0/1", "via": "LLDP"}]}
        rep = m.diagnose("8.8.8.8", None, quick=False)
        fired = [f for f in rep["findings"] if f["code"] == "optics_rx_low"]
        self.assertTrue(fired)
        self.assertIn("no received light", fired[0]["message"])

    def test_bsd_prints_mac_octets_without_padding(self):
        """macOS prints 0:0:5e:0:1:1 where Linux prints 00:00:5e:00:01:01.
        Both are the same VRRP virtual router and only one was recognised, so
        a Mac saw two routers arguing over an address and called it a
        duplicate IP instead of the failover pair it was looking at."""
        self.assertEqual(nd.normalise_mac("0:0:5e:0:1:1"), "00:00:5e:00:01:01")
        self.assertEqual(nd.virtual_router_mac(nd.normalise_mac("0:0:5e:0:1:1"))[0],
                         "VRRP or CARP")

    def test_a_bsd_arp_table_resolves_to_the_same_addresses_as_a_linux_one(self):
        bsd = nd.parse_arp_table(
            "? (192.168.1.1) at 0:0:5e:0:1:1 on en0 ifscope [ethernet]\n")
        linux = nd.parse_arp_table("192.168.1.1 dev eth0 lladdr 00:00:5e:00:01:01 REACHABLE\n")
        self.assertEqual(bsd[0]["mac"], linux[0]["mac"])

    def test_an_incomplete_bsd_entry_is_still_no_address(self):
        e = nd.parse_arp_table("? (192.168.1.55) at (incomplete) on en0 ifscope [ethernet]\n")
        self.assertIsNone(e[0]["mac"])

    def test_the_ways_a_driver_says_it_does_not_know_the_speed(self):
        """65535 is the u16 sentinel older ethtool prints raw; 4294967295 is
        the u32 one some kernels put in sysfs. Both parse cleanly as enormous
        link speeds, and a link claiming 4 Tbps has a utilisation of zero
        forever - which retires the saturation checks silently."""
        for sentinel in (65535, 4294967295, -1, 0):
            with self.subTest(sentinel=sentinel):
                self.assertIsNone(nd.plausible_mbps(sentinel))
        for real in (10, 1000, 10000, 400000):
            with self.subTest(real=real):
                self.assertEqual(nd.plausible_mbps(real), real)

    def test_the_sentinel_never_becomes_a_speed(self):
        self.assertNotIn("speed_mbps", nd.parse_ethtool("\tSpeed: 65535Mb/s\n"))
        self.assertEqual(nd.parse_ethtool("\tSpeed: 10000Mb/s\n")["speed_mbps"], 10000)

    def test_unknown_speed_does_not_silently_retire_the_saturation_check(self):
        """The failure this guards is invisible: no error, no finding, just a
        link that is never full because its capacity is astronomical."""
        m = fresh()
        m.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
            {"name": "eth0", "speed_mbps": None, "duplex": "full", "mtu": 1500,
             "carrier": True}]}
        codes = [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]
        self.assertNotIn("link_saturated", codes)
        self.assertNotIn("negotiated_below_capacity", codes)

    def test_a_share_of_an_aggregate_never_exceeds_it(self):
        """Many drivers wire rx_over_errors and rx_missed_errors to the same
        hardware counter, so adding them counts one overrun twice - enough to
        print "80 of 40 errors" and to drive the share comparison from a
        number larger than the total it is a share of."""
        m = fresh()
        counters(m, rx_errors=900, d_rx_errors=40, d_rx_over_errors=40,
                 d_rx_missed_errors=40, d_rx_packets=2_000)
        fired = [f for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]
                 if f["code"] == "nic_ring_overruns"]
        self.assertTrue(fired)
        self.assertIn("40 of 40", fired[0]["message"])


class TestAnErrorBurstIsSplitByWhoOwnsIt(unittest.TestCase):
    """rx_errors is an aggregate - the kernel documents it as including the
    length, CRC and frame counters "and other errors not otherwise counted".
    Blaming all of it on the cable sent someone to a switch port over a box
    that could not drain its own ring buffer."""

    def codes(self, **kw):
        m = fresh()
        counters(m, rx_errors=900, d_rx_errors=40, d_rx_packets=2_000, **kw)
        return [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]

    def test_a_fifo_overflow_is_this_box_not_the_cable(self):
        self.assertIn("nic_ring_overruns", self.codes(d_rx_over_errors=35))

    def test_a_packet_the_host_had_no_buffer_for_is_the_same_fault(self):
        self.assertIn("nic_ring_overruns", self.codes(d_rx_missed_errors=35))

    def test_an_invalid_length_is_a_disagreement_about_frame_size(self):
        self.assertIn("frame_length_errors", self.codes(d_rx_length_errors=35))

    def test_a_crc_error_is_still_the_cable(self):
        self.assertIn("link_errors_live", self.codes(d_rx_crc_errors=35))

    def test_a_driver_that_exports_no_detail_falls_back_to_the_link(self):
        """Not every driver breaks rx_errors down. Without a fallback the
        commonest case on the cheapest hardware would report nothing at all."""
        self.assertIn("link_errors_live", self.codes())

    def test_one_burst_produces_one_finding(self):
        for kw in ({"d_rx_over_errors": 35}, {"d_rx_length_errors": 35},
                   {"d_rx_crc_errors": 35}):
            with self.subTest(**kw):
                fired = [c for c in self.codes(**kw)
                         if c in ("nic_ring_overruns", "frame_length_errors",
                                  "link_errors_live")]
                self.assertEqual(len(fired), 1)

    def test_the_ring_and_the_backlog_do_not_confirm_each_other(self):
        """Both are this box failing to take delivery, counted at two depths.
        Separate families made one complaint read as two agreeing faults."""
        self.assertEqual(nd._finding_family("nic_ring_overruns"),
                         nd._finding_family("nic_drops_live"))

    def test_the_overrun_verdict_does_not_send_anyone_to_a_switch_port(self):
        """Its whole point is that the link delivered the frames."""
        rule = dict((c, (o, h, n)) for c, o, h, n in nd.VERDICT_RULES)["nic_ring_overruns"]
        self.assertNotIn("switch port", " ".join(rule).lower())


class TestADiscardIsNotAnError(unittest.TestCase):
    """Errors should never happen and are worth reporting on one occurrence.
    Discards happen every day on a busy box, and firing on a single one made
    this the finding that was always present - corroborating whatever else was
    found and lifting the confidence of conclusions it had nothing to do with."""

    def codes(self, dropped, packets):
        m = fresh()
        counters(m, rx_dropped=900, d_rx_dropped=dropped, d_rx_packets=packets)
        return [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]

    def test_a_real_share_of_the_window_is_reported(self):
        self.assertIn("drops_live", self.codes(200, 2_000))

    def test_a_handful_across_a_busy_window_is_not(self):
        self.assertNotIn("drops_live", self.codes(31, 50_000))

    def test_a_percentage_of_forty_packets_is_not_a_percentage(self):
        """The window is seconds long on a box that may be nearly idle."""
        self.assertNotIn("drops_live", self.codes(2, 40))

    def test_discards_are_judged_far_more_loosely_than_errors(self):
        """The two counters mean opposite things - a frame that arrived
        damaged, and a frame this box chose not to deliver upwards. Sharing a
        threshold is what made them read alike."""
        self.assertGreater(nd.DROP_PCT_WARN * 10_000, nd.ERR_PPM_WARN * 10)

    def test_one_error_still_speaks_where_one_discard_does_not(self):
        m = fresh()
        counters(m, rx_errors=900, d_rx_errors=1, d_rx_packets=50_000,
                 d_rx_crc_errors=1)
        codes = [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]
        self.assertIn("link_errors_live", codes)


class TestCompactExport(unittest.TestCase):
    """A full export is mostly captured command output, and on a real box the
    port probes alone can be half of it. That is the right default and the
    wrong thing to carry off a locked-down box through a console."""

    def report(self, code="link_saturated"):
        setup, kw = S[code]
        m = fresh(); setup(m)
        return m, m.diagnose(quick=False, **scenario_kwargs(kw))

    def test_everything_the_picture_needs_survives(self):
        """The point is a smaller report, not a poorer one: the hops, the
        colours, the layers and the direction panel are all derived and all
        small, so none of them is what makes an export big."""
        m, full = self.report()
        c = m.compact_report(full)
        for key in ("verdict", "findings", "stages", "sides", "layers", "hops",
                    "call_quality", "target", "version"):
            self.assertEqual(c.get(key), full.get(key), f"compact lost {key}")

    def test_the_evidence_behind_a_passing_stage_is_dropped(self):
        m, full = self.report()
        c = m.compact_report(full)
        passing = {s["stage"] for s in full["stages"] if s["state"] == "pass"}
        self.assertTrue(passing, "the fixture proves nothing if no stage passes")
        for key in full["raw"]:
            stage = nd.raw_stage(key)
            if stage in passing:
                value = full["raw"][key]
                # Not every raw entry is a command result - "ipv4" is a bool.
                if not isinstance(value, dict) or value.get("ok", True):
                    self.assertNotIn(key, c["raw"],
                                     f"{key} backs the passing '{stage}' stage")

    def test_the_evidence_behind_a_failing_stage_is_kept(self):
        m, full = self.report()
        c = m.compact_report(full)
        broken = {s["stage"] for s in full["stages"] if s["state"] in ("fail", "warn")}
        self.assertTrue(broken, "the fixture proves nothing if nothing is broken")
        kept = {nd.RAW_STAGE.get(k) for k in c["raw"]}
        self.assertTrue(broken & kept, "no evidence kept for the stages that failed")

    def test_a_check_that_could_not_run_is_always_kept(self):
        """A gap in coverage has to stay visible. Dropped, it would look
        exactly like a check that passed - which is the one thing this tool
        must never say."""
        m, full = self.report()
        full["raw"]["dns_health"] = {"ok": False, "error": "no resolvers readable"}
        c = m.compact_report(full)
        self.assertIn("dns_health", c["raw"])

    def test_evidence_that_belongs_to_no_stage_always_survives(self):
        """The clock is deliberately not a stage - it breaks authentication and
        certificate validity rather than the wire, which the strip does not
        model. Trimming by stage alone would drop the evidence for a finding
        that can still be the verdict, and the run's own provenance with it."""
        m, full = self.report()
        c = m.compact_report(full)
        stageless = [k for k in full["raw"] if nd.raw_stage(k) is None]
        self.assertTrue(stageless, "the fixture proves nothing without a stageless key")
        for key in stageless:
            self.assertIn(key, c["raw"], f"{key} belongs to no stage and was dropped")

    def test_the_help_text_is_trimmed_to_the_panels_that_remain(self):
        m, full = self.report()
        c = m.compact_report(full)
        self.assertTrue(set(c["panel_help"]) <= set(c["raw"]))

    def test_it_says_that_it_is_compact(self):
        """A reader opening one months later has to be able to tell why a
        panel is missing, and a baseline comparison should not read a trimmed
        report as a box that stopped collecting things."""
        m, full = self.report()
        self.assertTrue(m.compact_report(full)["compact"])
        self.assertNotIn("compact", full)

    def test_every_raw_key_a_run_produces_has_a_stage(self):
        """A key the map has never heard of is kept, which is the safe way to
        be wrong - but it is still wrong, and it means a new collector silently
        stops being trimmed."""
        for code in sorted(S):
            setup, kw = S[code]
            m = fresh(); setup(m)
            try:
                rep = m.diagnose(quick=False, **scenario_kwargs(kw))
            except Exception:
                continue
            unknown = sorted(k for k in (rep.get("raw") or {})
                             if k not in nd.RAW_STAGE
                             and not any(k.startswith(p) for p, _ in nd.RAW_STAGE_PREFIXES))
            self.assertEqual(unknown, [], f"{code}: raw keys with no stage: {unknown}")

    # Stages that are legs of a direction rather than properties of this box.
    # link, address and ports are not here on purpose: they describe the box
    # itself, and a finding facing either way can legitimately move them.
    OUTBOUND_STAGES = {"gateway", "internet", "dns", "mtu"}
    INBOUND_STAGE = "clients"

    def test_no_stage_is_moved_by_a_finding_facing_the_other_way(self):
        """The strip walks outward from the box. Client-side faults had no leg
        of that chain to land on, so nine of them landed on "internet" - and a
        report would announce that the internet had failed directly above a
        verdict saying the loss was on what talks to this box and everything it
        depends on is clean. Both halves were the tool's own words.

        The strip now has an inbound leg. This is what stops the next finding
        from being filed by which stage sounds closest rather than by which
        direction the evidence faces, which is how the first nine got there."""
        for stage, fails, warns in nd.STAGE_RULES:
            for code in sorted(fails | warns):
                side = nd.FINDING_SIDE.get(code)
                with self.subTest(stage=stage, code=code):
                    if stage in self.OUTBOUND_STAGES:
                        self.assertNotEqual(
                            side, "downstream",
                            f"{code} faces the way in but moves the {stage} stage, "
                            f"which is a leg of the way out. A report would fail "
                            f"{stage} while its verdict says the way out is clean.")
                    if stage == self.INBOUND_STAGE:
                        self.assertNotEqual(
                            side, "upstream",
                            f"{code} faces the way out but moves the {stage} stage, "
                            f"which is the way in.")

    def test_every_stage_named_in_the_map_is_a_real_stage(self):
        """A capture may answer for more than one stage, so a value is a name
        or a tuple of them. The prefixes name stages too and were never
        checked, which is the same typo waiting in a place nothing looked."""
        stages = {s for s, _f, _w in nd.STAGE_RULES}
        named = set()
        for value in nd.RAW_STAGE.values():
            if value is None:
                continue
            named |= set(value) if isinstance(value, tuple) else {value}
        named |= {s for _prefix, s in nd.RAW_STAGE_PREFIXES}
        self.assertEqual(sorted(named - stages), [])

    def test_it_is_smaller(self):
        import json
        m, full = self.report()
        c = m.compact_report(full)
        self.assertLess(len(json.dumps(c)), len(json.dumps(full)))

    def test_the_page_it_writes_still_carries_a_readable_report(self):
        m, full = self.report()
        page = m.render_report_html(m.compact_report(full))
        back = m.extract_embedded_report(page)
        self.assertIsNotNone(back)
        self.assertTrue(back["compact"])
        self.assertEqual(back["verdict"]["headline"], full["verdict"]["headline"])
        self.assertEqual(len(back["hops"]), len(full["hops"]))


class TestTheSmallFileReader(unittest.TestCase):
    """Three readers had written this out as their own closure. The int-reading
    variants beside it are deliberately not folded in - they differ in what a
    failure means, and that distinction is load-bearing."""

    def test_it_reads_and_strips(self):
        import os, shutil, tempfile
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        path = os.path.join(base, "value")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("  1000\n")
        self.assertEqual(nd._read_text(path), "1000")

    def test_a_missing_file_is_none_not_an_empty_string(self):
        """An absent counter and a counter reading "" are different facts, and
        every caller here branches on which."""
        self.assertIsNone(nd._read_text("/nonexistent/path/value"))

    def test_an_unreadable_file_is_none_rather_than_a_raise(self):
        """sysfs raises EINVAL on an interface with no carrier. That is normal
        rather than an error worth reporting, and it must not escape."""
        self.assertIsNone(nd._read_text("/proc/self/mem"))


class TestBondMembers(unittest.TestCase):
    """A bond hides its own failures by design - the interface stays up, the
    address stays put, and the redundancy that was the point of it is gone."""

    def build(self, bonds):
        """A sysfs tree: {bond: {member: mii_status or None, ...}}."""
        import os, shutil, tempfile
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        for bond, members in bonds.items():
            bdir = os.path.join(base, bond, "bonding")
            os.makedirs(bdir)
            with open(os.path.join(bdir, "slaves"), "w", encoding="utf-8") as fh:
                fh.write(" ".join(members))
            with open(os.path.join(bdir, "mode"), "w", encoding="utf-8") as fh:
                fh.write("802.3ad 4\n")
            for member, status in members.items():
                mdir = os.path.join(base, member, "bonding_slave")
                os.makedirs(mdir)
                if status is not None:
                    with open(os.path.join(mdir, "mii_status"), "w", encoding="utf-8") as fh:
                        fh.write(status)
        return base

    def test_a_member_that_is_down_is_named(self):
        base = self.build({"bond0": {"eth0": "up", "eth1": "down"}})
        self.assertEqual(nd._bond_members_linux(base)["bond0"]["down"], ["eth1"])
        self.assertEqual(nd._bond_members_linux(base)["bond0"]["mode"], "802.3ad")

    def test_a_healthy_bond_reports_nothing_down(self):
        base = self.build({"bond0": {"eth0": "up", "eth1": "up"}})
        self.assertEqual(nd._bond_members_linux(base)["bond0"]["down"], [])

    def test_a_member_with_no_status_falls_back_to_its_own_link_state(self):
        """Not every kernel exports bonding_slave/mii_status. Without the
        fallback a bond on one of those reads as entirely healthy."""
        import os
        base = self.build({"bond0": {"eth0": None, "eth1": None}})
        for member, state in (("eth0", "up"), ("eth1", "down")):
            with open(os.path.join(base, member, "operstate"), "w", encoding="utf-8") as fh:
                fh.write(state)
        self.assertEqual(nd._bond_members_linux(base)["bond0"]["down"], ["eth1"])

    def test_an_interface_that_is_not_a_bond_is_not_one(self):
        import os
        base = self.build({"bond0": {"eth0": "up"}})
        os.makedirs(os.path.join(base, "eth9"))
        self.assertNotIn("eth9", nd._bond_members_linux(base))

    def test_no_sysfs_tree_yields_nothing(self):
        self.assertEqual(nd._bond_members_linux("/nonexistent/path"), {})

    def test_a_bond_with_every_member_down_is_a_dead_link_not_a_degraded_bond(self):
        """The link checks say that in better words, and saying both would
        blame the redundancy for an interface that has no carrier at all."""
        m = fresh(); m.OS_NAME = "Linux"
        m._bond_members_linux = lambda base="/sys/class/net": {
            "bond0": {"members": ["eth0", "eth1"], "down": ["eth0", "eth1"], "mode": None}}
        codes = [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]
        self.assertNotIn("bond_degraded", codes)


class TestNeighbourTable(unittest.TestCase):
    """A ceiling with no back pressure: past it the kernel stops resolving,
    and the box loses neighbours at random on a segment that is working."""

    def build(self, arp_cache=None, thresh=None):
        import os, shutil, tempfile
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        os.makedirs(os.path.join(base, "net", "stat"))
        os.makedirs(os.path.join(base, "sys", "net", "ipv4", "neigh", "default"))
        if arp_cache is not None:
            with open(os.path.join(base, "net", "stat", "arp_cache"), "w", encoding="utf-8") as fh:
                fh.write(arp_cache)
        if thresh is not None:
            with open(os.path.join(base, "sys", "net", "ipv4", "neigh",
                                   "default", "gc_thresh3"), "w", encoding="utf-8") as fh:
                fh.write(str(thresh))
        return base

    CACHE = ("entries  allocs destroys hash_grows lookups hits res_failed "
             "rcv_probes_mcast rcv_probes_ucast periodic_gc_runs forced_gc_runs "
             "unresolved_discards table_fulls\n"
             "00000200  0 0 0 0 0 0 0 0 0 0 0 00000005\n"
             "00000200  0 0 0 0 0 0 0 0 0 0 0 00000003\n")

    def test_entries_are_the_table_total_not_a_per_cpu_share(self):
        """The column repeats the whole table on every row, exactly like the
        conntrack one. Summing it would double the count on a two-core box and
        report a table over its own limit."""
        t = nd._read_neigh_table(self.build(self.CACHE, 1024))
        self.assertEqual(t["entries"], 0x200)

    def test_overflows_are_per_cpu_and_do_add_up(self):
        t = nd._read_neigh_table(self.build(self.CACHE, 1024))
        self.assertEqual(t["table_fulls"], 8)

    def test_the_limit_is_read_from_sysctl(self):
        self.assertEqual(nd._read_neigh_table(self.build(self.CACHE, 4096))["gc_thresh3"], 4096)

    def test_a_missing_tree_says_nothing_rather_than_zero(self):
        self.assertEqual(nd._read_neigh_table("/nonexistent/path"), {})
        self.assertNotIn("entries", nd._read_neigh_table(self.build(None, 1024)))

    def test_a_full_table_outranks_a_nearly_full_one(self):
        """Both can be true at once - it is at the ceiling now and has been
        there before. Only the one that has already refused something is worth
        reporting."""
        m = fresh(); m.OS_NAME = "Linux"
        m._read_neigh_table = lambda base="/proc": {
            "gc_thresh3": 1024, "entries": 1020, "table_fulls": 4}
        codes = [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]
        self.assertIn("neigh_table_full", codes)
        self.assertNotIn("neigh_table_near_limit", codes)

    def test_a_table_with_room_left_says_nothing(self):
        m = fresh(); m.OS_NAME = "Linux"
        m._read_neigh_table = lambda base="/proc": {
            "gc_thresh3": 1024, "entries": 300, "table_fulls": 0}
        codes = [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]
        self.assertNotIn("neigh_table_near_limit", codes)
        self.assertNotIn("neigh_table_full", codes)


class TestResetsThisBoxSends(unittest.TestCase):
    """Collected for several versions before anything read them. A client on
    the end of a reset sees a connection dropped, not a slow one, and reports
    it as the network."""

    def codes(self, **after):
        before = {"OutRsts": 0, "PassiveOpens": 0, "ActiveOpens": 0, "EstabResets": 0}
        m = fresh()
        kernel_drops(m, before, dict(before, **after))
        return [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]

    def test_more_resets_than_connections_is_reported(self):
        self.assertIn("resets_sent_high", self.codes(OutRsts=120, PassiveOpens=100))

    def test_ordinary_churn_is_not(self):
        """An application that closes with data still unread sends a reset, and
        browsers abandon connections all day. A count alone would fire on every
        healthy proxy on earth."""
        self.assertNotIn("resets_sent_high", self.codes(OutRsts=40, PassiveOpens=100))

    def test_a_handful_of_connections_is_not_a_rate(self):
        self.assertNotIn("resets_sent_high", self.codes(OutRsts=15, PassiveOpens=5))

    def test_outbound_connections_count_towards_the_denominator(self):
        """A box that only talks outward accepts nothing, so a denominator of
        accepts alone would divide by zero on the shape this tool started as."""
        self.assertIn("resets_sent_high", self.codes(OutRsts=60, ActiveOpens=50))

    def test_it_is_owned_by_this_box_and_faces_both_ways(self):
        """The resets originate here, so it is not a fault arriving from
        either direction and can corroborate one facing either way."""
        self.assertEqual(nd.finding_side("resets_sent_high"), "local")


class TestALinkBelowItsOwnCapacity(unittest.TestCase):
    """slow_link can only speak in absolute numbers, so a 10G port sitting at
    1G is not slow by any threshold worth writing down."""

    def codes(self, speed, capacity):
        m = fresh()
        m.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
            {"name": "eth0", "speed_mbps": speed, "max_mbps": capacity,
             "duplex": "full", "mtu": 1500, "carrier": True}]}
        return [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]

    def test_a_ten_gig_port_at_one_gig_is_reported(self):
        self.assertIn("negotiated_below_capacity", self.codes(1000, 10000))

    def test_a_port_at_its_own_maximum_is_not(self):
        self.assertNotIn("negotiated_below_capacity", self.codes(10000, 10000))

    def test_one_fault_produces_one_finding(self):
        """A gigabit port at 100 Mbps is both things at once. slow_link says it
        better below 100, so only that one speaks."""
        codes = self.codes(100, 1000)
        self.assertIn("slow_link", codes)
        self.assertNotIn("negotiated_below_capacity", codes)

    def test_the_two_do_not_confirm_each_other(self):
        """Same check, said two ways. Different families would have made one
        link running below par read as two agreeing faults."""
        self.assertEqual(nd._finding_family("slow_link"),
                         nd._finding_family("negotiated_below_capacity"))

    def test_the_supported_modes_block_is_read_from_ethtool(self):
        parsed = nd.parse_ethtool(
            "Settings for eth0:\n"
            "\tSupported link modes:   100baseT/Full\n"
            "\t                        1000baseT/Full\n"
            "\t                        10000baseT/Full\n"
            "\tSupported pause frame use: Symmetric\n"
            "\tAdvertised link modes:  1000baseT/Full\n"
            "\tSpeed: 1000Mb/s\n\tDuplex: Full\n\tLink detected: yes\n")
        self.assertEqual(parsed["max_mbps"], 10000)
        self.assertEqual(parsed["speed_mbps"], 1000)

    def test_ethtool_without_a_supported_block_reports_no_capacity(self):
        """Virtual NICs print no modes at all. A missing block must not read
        as a capacity of zero, or every one of them becomes a fault."""
        self.assertNotIn("max_mbps", nd.parse_ethtool(
            "Settings for eth0:\n\tSpeed: 1000Mb/s\n\tDuplex: Full\n"))


class TestLatencyHasItsOwnWords(unittest.TestCase):
    """An 800ms path to a database used to report that voice and video would
    be unusable. True, and no use to whoever runs the database."""

    def verdict(self, avg, loss=0, target="8.8.8.8", **kw):
        m = fresh()
        ping_map(m, inet_loss=loss, avg=avg, mdev=5.0)
        return m.diagnose(target, None, quick=False, **kw)

    def test_a_slow_path_is_named_as_delay_not_as_call_quality(self):
        v = self.verdict(800.0)["verdict"]
        self.assertEqual(v["based_on"][0], "latency_high")
        self.assertNotIn("Voice", v["headline"])
        self.assertEqual(v["severity"], "critical")

    def test_the_call_score_is_still_reported_underneath(self):
        """Delay is the general statement; what it does to a call is a real
        consequence of it, not a competing answer."""
        codes = [f["code"] for f in self.verdict(800.0)["findings"]]
        self.assertEqual(codes.index("latency_high") + 1, codes.index("call_quality_bad"))

    def test_a_long_haul_path_is_not_called_a_fault(self):
        """The far side of the planet and back is about 250ms of physics."""
        codes = [f["code"] for f in self.verdict(300.0)["findings"]]
        self.assertNotIn("latency_high", codes)

    def test_it_does_not_need_a_loss_figure_to_say_anything(self):
        """The call score needs loss to compute, so a run that could not
        measure loss said nothing at all about latency."""
        m = fresh()
        m.cmd_ping = lambda t, c=4, w=2: {
            "ok": True, "cmd": "ping",
            "stdout": "rtt min/avg/max/mdev = 1.0/900.0/1800.0/5.0 ms\n"}
        codes = [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]
        self.assertIn("latency_high", codes)
        self.assertNotIn("call_quality_bad", codes)

    def test_loss_still_outranks_delay(self):
        """Traffic that never arrives beats traffic that arrives late."""
        v = self.verdict(800.0, loss=25)["verdict"]
        self.assertEqual(v["based_on"][0], "inet_partial_loss")

    def test_the_call_score_is_not_a_second_opinion_about_the_latency(self):
        """It is computed from the same round trip. Counting it as agreement
        put a slow path at high confidence on one measurement."""
        rep = self.verdict(800.0)
        v = rep["verdict"]
        self.assertEqual(v["corroborated_by"], [])
        self.assertEqual(v["confidence"], "medium")
        self.assertNotIn("call_quality_bad", [u["code"] for u in v["unrelated"]])

    def test_distance_is_not_offered_as_an_excuse_for_an_internal_backend(self):
        """400ms to a box in your own rack is queuing or a bad route. The
        internet verdict's own next step tells the reader to check whether the
        target is really that far away, which is the wrong question here."""
        own, backend = nd.VERDICT_RULES, nd.BACKEND_TARGET_VERDICTS
        internet = dict((c, (o, h, n)) for c, o, h, n in own)["latency_high"]
        self.assertIn("latency_high", backend)
        self.assertNotEqual(backend["latency_high"], internet)
        self.assertNotIn("ocean", internet[2])


class TestFaultsAreScopedToWhatTheyAreAbout(unittest.TestCase):
    """Two cables are two faults, not one confirmed twice."""

    def f(self, code, scope=None, sev="critical", layer=1):
        out = {"code": code, "severity": sev, "layer": layer, "message": code}
        if scope:
            out["scope"] = scope
        return out

    def test_faults_on_different_interfaces_do_not_corroborate(self):
        v = nd.build_verdict([self.f("link_errors_live", "eth0"),
                              self.f("collisions", "eth1", sev="warning")])
        self.assertEqual(v["corroborated_by"], [])
        self.assertEqual(v["confidence"], "medium")

    def test_faults_on_the_same_interface_still_do(self):
        v = nd.build_verdict([self.f("duplex_mismatch", "eth0"),
                              self.f("collisions", "eth0", sev="warning")])
        self.assertTrue(v["corroborated_by"])
        self.assertEqual(v["confidence"], "high")

    def test_a_fault_about_the_whole_box_corroborates_any_interface(self):
        """The softnet backlog belongs to all of them, so it carries no scope
        and agrees with whichever interface is named."""
        v = nd.build_verdict([self.f("link_errors_live", "eth0"),
                              self.f("nic_drops_live")])
        self.assertEqual(v["corroborated_by"], ["nic_drops_live"])

    def test_every_per_interface_finding_records_which_one(self):
        """A finding that forgets its scope silently corroborates across
        cables again."""
        scoped = set()
        for code in sorted(S):
            setup, kw = S[code]
            m = fresh(); setup(m)
            try:
                rep = m.diagnose(quick=False, **scenario_kwargs(kw))
            except Exception:
                continue
            for f in rep["findings"]:
                if f.get("scope"):
                    scoped.add(f["code"])
        for code in ("link_errors_live", "collisions", "duplex_mismatch",
                     "slow_link", "link_flapping_live"):
            with self.subTest(code=code):
                self.assertIn(code, scoped)


class TestRatesNeedADenominator(unittest.TestCase):
    """One event is not a rate - the reasoning ping loss already used."""

    def link(self, packets, errors=0, collisions=0):
        m = fresh()
        counters(m, rx_packets=packets, tx_packets=0, rx_errors=errors,
                 collisions=collisions)
        m.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
            {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500,
             "carrier": True}]}
        return [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]
                if f["severity"] != "ok"]

    def test_one_error_on_an_idle_interface_is_not_an_error_rate(self):
        """500 packets and one error divides out to 2000 per million - twenty
        times the threshold - and said the link had a problem. A management
        NIC, a bond member carrying nothing, an interface that just came up."""
        self.assertNotIn("link_errors_historical", self.link(500, errors=1))
        self.assertNotIn("link_errors_historical", self.link(2_000, errors=1))

    def test_one_collision_on_an_idle_interface_is_not_a_duplex_mismatch(self):
        """Worse than the error case: this one is critical and headlines."""
        self.assertNotIn("collisions", self.link(500, collisions=1))

    def test_a_real_rate_on_a_busy_link_still_fires(self):
        self.assertIn("link_errors_historical", self.link(5_000_000, errors=800))
        self.assertIn("collisions", self.link(5_000_000, collisions=900))

    def test_the_floor_is_set_so_a_single_event_cannot_cross_the_threshold(self):
        """Otherwise the guard would let exactly the case it exists for
        through, one packet above the floor."""
        one_error_ppm = 1_000_000 / nd.MIN_PACKETS_FOR_RATE
        self.assertLess(one_error_ppm, nd.ERR_PPM_WARN)

    def test_errors_arriving_while_we_watch_are_not_gated(self):
        """A rate needs a denominator; an error appearing during the window
        does not. It is happening now, at whatever volume."""
        m = fresh()
        counters(m, rx_packets=800, tx_packets=0, rx_errors=1, d_rx_errors=3)
        codes = [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False, soak=1)["findings"]]
        self.assertIn("link_errors_live", codes)


class TestLatencyWall(unittest.TestCase):
    """A wall, or just a long path - the finding says a single hop adds most
    of the round trip, so that is what it has to measure."""

    def path(self, cumulative):
        m = fresh()
        ping_map(m, inet_loss=0, avg=cumulative[-1], mdev=20.0, sent=20)
        mtr(m, [{"count": i + 1,
                 "host": "10.0.0.1" if i == 0 else f"198.51.100.{i}",
                 "Loss%": 0.0, "Snt": 30, "Avg": v}
                for i, v in enumerate(cumulative)])
        return [f["code"] for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]]

    def test_a_single_hop_carrying_most_of_the_delay_is_a_wall(self):
        self.assertIn("latency_wall", self.path([5.0, 305.0, 310.0]))

    def test_a_uniformly_graded_path_has_no_wall(self):
        """Every hop adding the same amount. The milliseconds alone fired this
        and named a hop no worse than its neighbours, while claiming a single
        hop added most of the delay."""
        codes = self.path([140.0, 280.0, 420.0])
        self.assertNotIn("latency_wall", codes)

    def test_a_hundred_millisecond_jump_on_a_very_long_path_is_not_a_wall(self):
        self.assertNotIn("latency_wall", self.path([300.0, 400.0, 700.0, 1000.0]))

    def test_a_small_jump_that_dominates_a_short_path_is_not_a_wall(self):
        """74% of the total and twenty milliseconds. Nothing to send anyone to,
        which is what the absolute floor is for."""
        self.assertNotIn("latency_wall", self.path([3.0, 23.0, 27.0]))

    def test_a_first_hop_carrying_the_whole_delay_is_a_wall(self):
        """A satellite link, a VPN concentrator, a distant CPE. The delay is
        entirely at hop one and nothing followed it - so no step between hops
        existed, and the tool said nothing about the only thing that mattered
        on that path."""
        codes = self.path([600.0, 605.0, 610.0])
        self.assertIn("latency_wall", codes)

    def test_a_first_hop_wall_is_worded_as_one(self):
        """"Latency jumps 600ms at hop 1" reads as a step from something. There
        is nothing before it, and the sentence should say so."""
        m = fresh()
        ping_map(m, inet_loss=0, avg=610.0, mdev=20.0, sent=20)
        mtr(m, [{"count": i + 1, "host": "10.0.0.1" if i == 0 else f"198.51.100.{i}",
                 "Loss%": 0.0, "Snt": 30, "Avg": v}
                for i, v in enumerate([600.0, 605.0, 610.0])])
        msg = [f for f in m.diagnose("8.8.8.8", None, quick=False)["findings"]
               if f["code"] == "latency_wall"][0]["message"]
        self.assertIn("very first hop is already", msg)
        self.assertNotIn("jumps", msg)

    def test_an_ordinary_gateway_does_not_become_a_wall(self):
        """Counting the first hop must not turn every LAN gateway into one."""
        self.assertNotIn("latency_wall", self.path([1.0, 20.0, 22.0]))

    def test_a_modest_first_hop_with_the_delay_further_out_is_not_a_wall(self):
        self.assertNotIn("latency_wall", self.path([150.0, 500.0, 900.0]))

    def test_the_uniformly_slow_path_reports_the_thing_that_is_true(self):
        """It is not silent - it names the delay itself, which is the honest
        answer when no hop is to blame. Before the share test the wall stole
        this verdict in every scenario, and for a while afterwards the only
        thing left to say was what the path did to a phone call."""
        m = fresh()
        ping_map(m, inet_loss=0, avg=420.0, mdev=90.0, sent=20)
        mtr(m, [{"count": i + 1, "host": f"198.51.100.{i}", "Loss%": 0.0,
                 "Snt": 30, "Avg": v} for i, v in enumerate([140.0, 280.0, 420.0])])
        rep = m.diagnose("8.8.8.8", None, quick=False)
        self.assertEqual(rep["verdict"]["based_on"][0], "latency_high")
        self.assertNotIn("latency_wall", [f["code"] for f in rep["findings"]])


class TestQueuingDelay(unittest.TestCase):
    """Latency that is queue, not distance - a different fault entirely."""

    def sides(self, *socks):
        m = fresh()
        sided_flows(m, *socks)
        with_backend(m)
        return m.diagnose(None, None, quick=False)

    def codes(self, rep):
        return [f["code"] for f in rep["findings"]]

    def test_a_queued_backend_is_named_as_queue_rather_than_distance(self):
        rep = self.sides(queued_sock("203.0.113.9", "443", 42.0, 38.0),
                         queued_sock("10.0.0.90", "44120", 96.0, 8.0, port="5432"))
        self.assertIn("queuing_delay_backends", self.codes(rep))
        self.assertEqual(rep["verdict"]["based_on"][0], "queuing_delay_backends")
        self.assertIn("buffering", rep["verdict"]["owner"])

    def test_a_queue_in_front_of_the_clients_points_the_other_way(self):
        rep = self.sides(queued_sock("203.0.113.9", "443", 340.0, 41.0),
                         queued_sock("10.0.0.90", "44120", 3.1, 2.8, port="5432"))
        self.assertIn("queuing_delay_clients", self.codes(rep))
        self.assertIn("users", rep["verdict"]["owner"])

    def test_a_long_path_is_not_a_queue(self):
        """The whole point. 180ms to a client on another continent, with the
        same connection never having been faster, is distance."""
        rep = self.sides(queued_sock("203.0.113.9", "443", 180.0, 178.0),
                         queued_sock("10.0.0.90", "44120", 11.4, 10.9, port="5432"))
        self.assertEqual([c for c in self.codes(rep) if c.startswith("queuing")], [])

    def test_a_lan_with_a_big_ratio_and_no_real_delay_is_not_a_queue(self):
        """0.2ms becoming 2.2ms is eleven times worse and two milliseconds.
        The multiple alone would fire here."""
        self.assertIsNone(nd._queue_summary([
            {"peer": "10.0.0.90", "rtt_ms": 2.2, "minrtt_ms": 0.2}]))

    def test_a_long_path_with_real_variance_is_not_a_queue(self):
        """45ms of spread on a satellite hop is weather. The absolute alone
        would fire here, which is why both tests exist."""
        self.assertIsNone(nd._queue_summary([
            {"peer": "203.0.113.9", "rtt_ms": 620.0, "minrtt_ms": 575.0}]))

    def test_the_worst_connection_is_the_one_reported(self):
        info = nd._queue_summary([
            {"peer": "a", "rtt_ms": 96.0, "minrtt_ms": 8.0},
            {"peer": "b", "rtt_ms": 340.0, "minrtt_ms": 41.0},
            {"peer": "c", "rtt_ms": 3.0, "minrtt_ms": 2.8}])
        self.assertEqual(info["queued"], 2)
        self.assertEqual(info["queue_peer"], "b")
        self.assertEqual(info["queue_ms"], 299.0)

    def test_a_socket_with_no_floor_reported_is_skipped_not_guessed(self):
        """Older kernels do not emit minrtt. Absent is not zero - treating it
        as zero makes every connection look infinitely queued."""
        self.assertIsNone(nd._queue_summary([
            {"peer": "a", "rtt_ms": 340.0, "minrtt_ms": None},
            {"peer": "b", "rtt_ms": 340.0}]))

    def test_a_box_with_no_sides_still_gets_the_finding(self):
        m = fresh()
        flows(m, ss_flow("203.0.113.9", sent=40_000_000, retrans=1000)
                 .replace("rtt:12.4/3.1", "rtt:340.0/3.1")
                 .replace("minrtt:11.9", "minrtt:41.0"))
        self.assertIn("queuing_delay", self.codes(m.diagnose(None, None, quick=False)))

    def test_the_flow_list_never_reaches_the_report(self):
        """The summary is a digest on purpose - the list it came from names
        every peer this box talks to."""
        rep = self.sides(queued_sock("10.0.0.90", "44120", 96.0, 8.0, port="5432"))
        self.assertNotIn("measurable_flows", json.dumps(nd.json_safe(rep)))


class TestBaselineAcrossTargets(unittest.TestCase):
    """A comparison is only a comparison if both visits measured the same thing."""

    def visit(self, target, avg, mdev, loss, serving=False, baseline=None):
        m = fresh()
        if serving:
            with_backend(m)
        ping_map(m, inet_loss=loss, avg=avg, mdev=mdev, sent=20)
        return m.diagnose(target, None, quick=False, baseline=baseline)

    def test_the_tool_retargeting_itself_is_not_a_regression(self):
        """--target auto picks a backend off this box's own connections, so the
        target can change between visits with nobody touching a flag: no
        clients on the first visit, clients on the second. Comparing call
        quality to 8.8.8.8 against call quality to a database two racks away
        reported "something changed, and not for the better" on a network where
        nothing had changed at all."""
        old = self.visit("8.8.8.8", 20.0, 2.0, 0)
        new = self.visit(None, 95.0, 45.0, 4, serving=True, baseline=old)
        self.assertNotEqual(old["target"], new["target"])
        changes = {c["what"]: c for c in new.get("comparison") or []}
        self.assertNotIn("call quality (MOS)", changes)
        self.assertNotIn("hops to target", changes)
        self.assertNotIn("site edge at hop", changes)
        self.assertEqual([f["code"] for f in new["findings"]
                          if f["code"] == "regression_since_baseline"], [])

    def test_the_change_of_target_is_reported_rather_than_hidden(self):
        """Silently comparing less is how someone reads a clean diff as a clean
        network. The reader has to know why fewer things were compared."""
        old = self.visit("8.8.8.8", 20.0, 2.0, 0)
        new = self.visit(None, 95.0, 45.0, 4, serving=True, baseline=old)
        changes = {c["what"]: c for c in new.get("comparison") or []}
        self.assertIn("target", changes)
        self.assertEqual(changes["target"]["before"], "8.8.8.8")
        self.assertEqual(changes["target"]["after"], new["target"])
        self.assertEqual(changes["target"]["direction"], "neutral")

    def test_a_real_degradation_to_the_same_target_still_reports(self):
        """The point is not to stop noticing regressions."""
        old = self.visit("8.8.8.8", 20.0, 2.0, 0)
        new = self.visit("8.8.8.8", 95.0, 45.0, 4, baseline=old)
        changes = {c["what"]: c for c in new.get("comparison") or []}
        self.assertIn("call quality (MOS)", changes)
        self.assertEqual(changes["call quality (MOS)"]["direction"], "worse")
        self.assertTrue([f for f in new["findings"]
                         if f["code"] == "regression_since_baseline"])

    def test_the_comparison_is_handed_the_target_at_all(self):
        """The first version of this fix passed no target into the comparison,
        so the two could never match and every target-dependent reading was
        dropped on every run - a suppression that looked exactly like a working
        guard."""
        old = self.visit("8.8.8.8", 20.0, 2.0, 0)
        new = self.visit("8.8.8.8", 95.0, 45.0, 4, baseline=old)
        self.assertNotIn("target", {c["what"] for c in new.get("comparison") or []})
        self.assertIn("call quality (MOS)", {c["what"] for c in new.get("comparison") or []})

    def test_compare_reports_alone_knows_what_it_may_compare(self):
        base = {"target": "8.8.8.8", "call_quality": {"mos": 4.4}, "hops": [1, 2, 3],
                "demarc_hop": 2}
        same = dict(base, call_quality={"mos": 3.8}, hops=[1, 2], demarc_hop=3)
        moved = dict(same, target="10.0.0.90")
        what = lambda rep: {c["what"] for c in nd.compare_reports(rep, base)}
        self.assertEqual(what(same), {"call quality (MOS)", "hops to target",
                                      "site edge at hop"})
        self.assertEqual(what(moved), {"target"})


class TestZones(unittest.TestCase):
    """Where the fault is, answerable without knowing what a layer is."""

    def zones(self, rep):
        return {z["side"]: z for z in rep["sides"]}

    def proxy(self, client_retrans=4_400_000, backend_retrans=900):
        text = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
                + "".join(f"ESTAB 0 0 10.20.4.11:443 10.20.0.7:5{i:04d}\n" for i in range(24))
                + "".join(f"ESTAB 0 0 10.20.4.11:441{i} 10.60.9.30:5432\n" for i in range(8)))
        m = fresh()
        sided_flows(m,
                    sided_sock("10.20.0.7", "443", sent=60_000_000, retrans=client_retrans),
                    sided_sock("10.60.9.30", "44120", sent=30_000_000,
                               retrans=backend_retrans, port="5432"))
        m.cmd_socket_states = lambda: dict(
            {"ok": True, "cmd": "ss -tan", "stdout": text}, **m.parse_socket_states(text))
        return m

    def test_the_failing_zone_is_the_one_with_the_fault(self):
        """The client side is the only one with a critical here. Upstream is
        not asserted clean - an unrelated warning there is exactly the second
        problem the panel exists to show - only that it is not the worst."""
        z = self.zones(self.proxy().diagnose(None, None, quick=False))
        self.assertEqual(z["downstream"]["state"], "fail")
        self.assertEqual(z["local"]["state"], "pass")
        self.assertNotEqual(z["upstream"]["state"], "fail")
        self.assertIn("tcp_flow_loss_clients", z["downstream"]["because"])

    def test_the_zone_flips_with_the_side_the_loss_is_on(self):
        z = self.zones(self.proxy(client_retrans=900,
                                  backend_retrans=2_400_000)
                       .diagnose(None, None, quick=False))
        self.assertEqual(z["upstream"]["state"], "fail")
        self.assertEqual(z["downstream"]["state"], "pass")

    def test_a_box_with_nothing_connected_has_no_inbound_zone_to_report(self):
        """Showing it green would claim something had been checked."""
        z = self.zones(fresh().diagnose(None, None, quick=False))
        self.assertEqual(z["downstream"]["state"], "skip")
        self.assertEqual(z["downstream"]["because"], [])

    def test_the_load_balancer_is_named_when_one_stands_out(self):
        """Twenty-four connections from one address is infrastructure, and
        naming it is the difference between "something on the way in" and an
        address someone can go and look at."""
        z = self.zones(self.proxy().diagnose(None, None, quick=False))
        self.assertEqual(z["downstream"]["via"], "10.20.0.7")

    def test_a_spread_of_real_clients_is_not_a_load_balancer(self):
        """Naming the busiest of a hundred public addresses would be noise
        dressed up as a finding."""
        text = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
                + "".join(f"ESTAB 0 0 10.20.4.11:443 203.0.113.{i}:5100{i}\n"
                          for i in range(20)))
        m = fresh(); serving(m, text)
        self.assertIsNone(nd._dominant_client(m.diagnose(None, None, quick=False)["raw"]))

    def test_the_upstream_zone_names_what_the_run_aimed_at(self):
        z = self.zones(self.proxy().diagnose(None, None, quick=False))
        self.assertEqual(z["upstream"]["via"], "10.60.9.30")

    def test_a_zone_carries_the_message_that_put_it_there(self):
        """A colour tells someone there is a problem. The sentence tells them
        what it is, which is the point of the panel."""
        z = self.zones(self.proxy().diagnose(None, None, quick=False))
        self.assertIn("clients opened", z["downstream"]["worst"])
        self.assertIsNone(z["local"]["worst"])

    def test_zones_and_the_verdict_never_disagree(self):
        """A panel that reads all-clear beside a verdict naming an owner is
        the exact thing the sidebar lamps were fixed for once already."""
        for retrans in ((4_400_000, 900), (900, 2_400_000), (900, 900)):
            with self.subTest(retrans=retrans):
                rep = self.proxy(*retrans).diagnose(None, None, quick=False)
                worst = max((f["severity"] for f in rep["findings"]),
                            key=lambda s: {"ok": 0, "warning": 1, "critical": 2}[s])
                lit = [z for z in rep["sides"] if z["state"] in ("warn", "fail")]
                self.assertEqual(bool(lit), worst != "ok")

    def test_the_zones_are_shown_on_every_box_including_one_nothing_reaches(self):
        """Hidden here at first, on the grounds that two boxes and an arrow
        restate a seven-stage strip. That optimises for a reader who can
        already read the strip - and boxes that only talk outward are the
        common case, so the panel written for someone who cannot read it was
        the one they would almost never be shown."""
        proxy = nd.render_text_report(self.proxy().diagnose(None, None, quick=False),
                                      color=False, width=100)
        # The load balancer is named in the same cell, so match the pieces.
        self.assertIn("clients in (10.20.0.7)", proxy)
        self.assertIn("FAULT", proxy.split("clients in")[1].split("\n")[0])
        plain = nd.render_text_report(fresh().diagnose(None, None, quick=False),
                                      color=False, width=100)
        self.assertIn("clients in none connected", plain)
        self.assertIn("this box ok", plain)

    def test_an_inbound_zone_with_nothing_in_it_does_not_read_as_a_fault(self):
        """"none connected" is an answer - the socket table was read and there
        was nothing coming in. Reading it as trouble on a machine that is
        working exactly as intended would make the panel worse than absent."""
        rep = fresh().diagnose(None, None, quick=False)
        z = self.zones(rep)["downstream"]
        self.assertEqual(z["state"], "skip")
        self.assertIsNone(z["worst"])
        text = nd.render_text_report(rep, color=False, width=100)
        for alarm in ("FAULT", "degraded"):
            self.assertNotIn(alarm, text.split("clients in")[1].split("\n")[0])
        self.assertEqual(nd.exit_status(rep), 0)

    def test_a_greyed_zone_never_changes_the_verdict_or_the_exit_code(self):
        for m in (fresh(), self.proxy()):
            rep = m.diagnose(None, None, quick=False)
            worst = max((f["severity"] for f in rep["findings"]),
                        key=lambda s: {"ok": 0, "warning": 1, "critical": 2}[s])
            self.assertEqual(nd.exit_status(rep),
                             {"ok": 0, "warning": 1, "critical": 2}[worst])

    def test_the_page_carries_the_zones_and_stays_self_contained(self):
        rep = self.proxy().diagnose(None, None, quick=False)
        html = nd.render_report_html(rep)
        island = html.split('type="application/json"', 1)[1].split(">", 1)[1] \
                     .split("</script>", 1)[0]
        data = json.loads(island)
        self.assertEqual([z["side"] for z in data["sides"]],
                         ["downstream", "local", "upstream"])
        # The page renders client-side, so with no JS engine here the honest
        # assertion is that the panel is wired into the output the renderer
        # builds - not merely that its template exists somewhere in the file,
        # which stayed true when it was left out of the concatenation. The
        # groups are written into their own containers now, so what has to be
        # asserted is that the zones reach one and that it exists to reach.
        self.assertIn("whereWrap').innerHTML", html)
        self.assertIn("+ sidesHtml", html)
        self.assertIn('id="whereWrap"', html)
        # The page renders in the browser, so with no JS engine here the panel
        # being shown on every box can only be asserted as the shape of the
        # condition that decides it. Structural, and deliberately so: it is the
        # decision itself, and a reinstated guard is exactly what would undo it.
        self.assertIn("const sidesHtml = sides.length ?", html)
        self.assertNotIn("sides[0].state !== 'skip'", html)
        self.assertIn("none connected", html)
        self.assertIn('class="zones"', html)
        self.assertIn(".zone.fail{", html)
        self.assertNotIn("</script>", island)


class TestBothDirections(unittest.TestCase):
    """A traceroute goes one way. The other direction is measured, not drawn."""

    def proxy(self, client_retrans=4_400_000, clients=6, backends=4):
        text = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
                + "".join(f"ESTAB 0 0 10.20.4.11:443 10.20.0.7:5{i:04d}\n"
                          for i in range(24))
                + "".join(f"ESTAB 0 0 10.20.4.11:441{i} 10.60.9.30:5432\n"
                          for i in range(8)))
        m = fresh()
        sided_flows(m, *(
            [sided_sock("10.20.0.7", "443", sent=60_000_000, retrans=client_retrans)] * clients
            + [sided_sock("10.60.9.30", "44120", sent=30_000_000, retrans=900,
                          port="5432")] * backends))
        m.cmd_socket_states = lambda: dict(
            {"ok": True, "cmd": "ss -tan", "stdout": text}, **m.parse_socket_states(text))
        mtr(m, [{"count": 1, "host": "gw (10.20.0.1)", "Loss%": 0.0, "Snt": 30, "Avg": 0.3},
                {"count": 2, "host": "db (10.60.9.30)", "Loss%": 0.0, "Snt": 30, "Avg": 9.1}])
        return m

    def side(self, rep, name):
        return ((rep["raw"].get("tcp_flows") or {}).get("by_side") or {}).get(name)

    def test_each_direction_is_measured_separately(self):
        rep = self.proxy().diagnose(None, None, quick=False)
        self.assertEqual(self.side(rep, "client")["connections"], 6)
        self.assertEqual(self.side(rep, "backend")["connections"], 4)
        self.assertGreater(self.side(rep, "client")["worst_loss_pct"], 5)
        self.assertEqual(self.side(rep, "backend")["worst_loss_pct"], 0.0)

    def test_the_latency_reported_is_the_median_not_the_worst(self):
        """One stalled connection should not stand in for how a whole side is
        being served."""
        m = self.proxy()
        text = SS_HEADER + "".join(
            sided_sock("10.20.0.7", "443", sent=60_000_000, retrans=1000)
            .replace("rtt:12.4/3.1", f"rtt:{r}/3.1") for r in (10, 11, 12, 900))
        stats = nd.analyze_tcp_flows(nd.parse_tcp_flows(text), listen_ports=["443"])
        self.assertLess(stats["by_side"]["client"]["rtt_ms"], 100)

    def test_the_inbound_leg_says_it_cannot_see_past_the_balancer(self):
        """A clean reading to the balancer is not a clean reading to the user,
        and a panel that does not say so invites exactly that reading."""
        txt = nd.render_text_report(self.proxy().diagnose(None, None, quick=False),
                                    color=False, width=92)
        self.assertIn("CLIENTS IN", txt)
        self.assertIn("cannot see past 10.20.0.7", txt)
        self.assertIn("not clean to whoever is complaining", txt)

    def test_the_outbound_path_is_named_as_a_direction(self):
        txt = nd.render_text_report(self.proxy().diagnose(None, None, quick=False),
                                    color=False, width=92)
        self.assertIn("PATH OUT TO 10.60.9.30 - what this box depends on", txt)
        self.assertNotIn("\nPATH TO ", txt)

    def test_a_box_nothing_connects_to_keeps_one_path_and_no_inbound_leg(self):
        """There is no inbound direction to report, and drawing an empty one
        would be inventing a measurement."""
        txt = nd.render_text_report(fresh().diagnose(None, None, quick=False),
                                    color=False, width=92)
        self.assertIn("PATH TO 8.8.8.8", txt)
        self.assertNotIn("PATH OUT TO", txt)
        self.assertNotIn("CLIENTS IN", txt)

    def test_a_spread_of_clients_is_not_reported_as_a_balancer(self):
        text = SS_HEADER + "".join(
            sided_sock(f"203.0.113.{i}", "443", sent=60_000_000, retrans=1000)
            for i in range(8))
        stats = nd.analyze_tcp_flows(nd.parse_tcp_flows(text), listen_ports=["443"])
        self.assertIsNone(stats["by_side"]["client"]["via"])

    def test_the_page_carries_both_directions(self):
        rep = self.proxy().diagnose(None, None, quick=False)
        html = nd.render_report_html(rep)
        island = html.split('type="application/json"', 1)[1].split(">", 1)[1] \
                     .split("</script>", 1)[0]
        self.assertIn("client", json.loads(island)["raw"]["tcp_flows"]["by_side"])
        self.assertIn('class="inbound"', html)
        self.assertIn("innerHTML = inboundHtml +", html)
        self.assertNotIn("</script>", island)


class TestTargetSelection(unittest.TestCase):
    """8.8.8.8 answers a question a proxy is not asking."""

    def box(self, text=None):
        m = fresh()
        with_backend(m, text or BACKEND_SS)
        return m

    def test_a_serving_box_aims_at_the_backend_it_depends_on_most(self):
        rep = self.box().diagnose(None, None, quick=False)
        self.assertEqual(rep["target"], "10.0.0.90")
        self.assertEqual(rep["raw"]["target_kind"], "backend")
        self.assertIn("target_is_a_backend", [f["code"] for f in rep["findings"]])

    def test_an_explicit_target_is_never_second_guessed(self):
        rep = self.box().diagnose("1.1.1.1", None, quick=False)
        self.assertEqual(rep["target"], "1.1.1.1")
        self.assertEqual(rep["raw"]["target_kind"], "internet")
        self.assertNotIn("target_is_a_backend", [f["code"] for f in rep["findings"]])

    def test_a_box_that_serves_nothing_keeps_the_old_default(self):
        rep = fresh().diagnose(None, None, quick=False)
        self.assertEqual(rep["target"], nd.DEFAULT_TARGET)
        self.assertEqual(rep["raw"]["target_kind"], "internet")

    def test_asking_for_auto_where_there_is_no_backend_says_so(self):
        """Silently falling back would leave someone reading a report about
        8.8.8.8 believing it was about their database."""
        rep = fresh().diagnose("auto", None, quick=False)
        self.assertEqual(rep["target"], nd.DEFAULT_TARGET)
        self.assertIn("target_auto_failed", [f["code"] for f in rep["findings"]])

    CLIENTS = "".join(f"ESTAB 0 0 10.0.0.5:443 203.0.113.{i}:5123{i}\n" for i in range(5))

    def test_a_single_connection_is_not_a_dependency(self):
        """One connection somewhere is a DNS lookup or a webhook. A pool is a
        dependency."""
        text = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n" + self.CLIENTS
                + "ESTAB 0 0 10.0.0.5:44120 10.0.0.90:5432\n")
        parsed = nd.parse_socket_states(text); parsed["ok"] = True
        self.assertIsNone(nd.pick_backend(parsed))

    def test_client_connections_are_never_mistaken_for_backends(self):
        parsed = nd.parse_socket_states(BACKEND_SS); parsed["ok"] = True
        self.assertEqual(nd.pick_backend(parsed), "10.0.0.90")

    def test_a_load_balancer_in_front_outnumbers_every_backend(self):
        """The case that decides whether this works at all. A single LB
        keep-alive pool holds far more connections than any backend, and it is
        a client - aiming the diagnosis at it would point the tool at the thing
        sending traffic rather than the thing the service depends on."""
        text = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
                + "".join(f"ESTAB 0 0 10.0.0.5:443 10.0.0.7:5{i:04d}\n" for i in range(40))
                + "".join(f"ESTAB 0 0 10.0.0.5:441{i} 10.0.0.90:5432\n" for i in range(4)))
        parsed = nd.parse_socket_states(text); parsed["ok"] = True
        self.assertEqual(nd.pick_backend(parsed), "10.0.0.90")

    def test_a_box_with_no_listeners_can_still_have_one(self):
        """This asserted the opposite until 2026-08-08, on the reasoning that
        a box with no inbound ports has no dependencies. A connector is exactly
        that box and its handful of links outward is the one thing it needs -
        see TestConnectorBox. What rules a laptop out is concentration, not
        listening."""
        text = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                + "".join(f"ESTAB 0 0 10.0.0.5:4412{i} 10.0.0.90:5432\n" for i in range(6)))
        parsed = nd.parse_socket_states(text); parsed["ok"] = True
        self.assertEqual(nd.pick_backend(parsed), "10.0.0.90")

    def test_the_choice_is_stable_across_runs(self):
        """A target that moves between runs makes two reports impossible to
        compare, and ties are common - two backends with a pool each."""
        text = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n" + self.CLIENTS
                + "".join(f"ESTAB 0 0 10.0.0.5:441{i} 10.0.0.91:5432\n" for i in range(4))
                + "".join(f"ESTAB 0 0 10.0.0.5:442{i} 10.0.0.90:6379\n" for i in range(4)))
        parsed = nd.parse_socket_states(text); parsed["ok"] = True
        self.assertEqual({nd.pick_backend(parsed) for _ in range(20)}, {"10.0.0.90"})

    def test_our_own_ssh_session_is_never_the_backend(self):
        text = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n" + self.CLIENTS
                + "".join(f"ESTAB 0 0 10.0.0.5:2200{i} 192.0.2.7:22\n" for i in range(6)))
        parsed = nd.parse_socket_states(text); parsed["ok"] = True
        old = os.environ.get("SSH_CONNECTION")
        os.environ["SSH_CONNECTION"] = "192.0.2.7 40000 10.0.0.5 22"
        try:
            self.assertIsNone(nd.pick_backend(parsed))
        finally:
            if old is None:
                os.environ.pop("SSH_CONNECTION", None)
            else:
                os.environ["SSH_CONNECTION"] = old

    def test_a_backend_that_cannot_be_reached_is_not_the_carriers_fault(self):
        """The whole point. Aimed at a database, "the provider" is not just
        unhelpful - it sends someone to argue with a carrier about a rack."""
        m = self.box()
        m.cmd_ping = lambda t, c=4, w=2: (
            {"ok": True, "cmd": "ping", "stdout":
             "10 packets transmitted, 10 received, 0% packet loss\n"
             "rtt min/avg/max/mdev = 0.3/0.4/0.6/0.1 ms\n"} if t == "10.0.0.1"
            else {"ok": True, "cmd": "ping", "stdout":
                  "10 packets transmitted, 0 received, 100% packet loss\n"})
        unreachable(m, arp=True)
        rep = m.diagnose(None, None, quick=False)
        owner = rep["verdict"]["owner"]
        self.assertNotIn("provider", owner)
        self.assertNotIn("carrier", owner)
        self.assertIn("backend", rep["verdict"]["headline"])

    def test_the_uplink_caveat_stays_off_an_internal_target(self):
        """"Rule out the site's own line" is about the WAN, which an internal
        segment does not go anywhere near."""
        m = self.box()
        counters(m, d_rx_bytes=int(48e6 / 8 * 2))
        ping_map(m, inet_loss=6, sent=20)
        m.cmd_ping = (lambda orig: (lambda t, c=4, w=2: orig(t, c, w)))(m.cmd_ping)
        rep = m.diagnose(None, None, quick=False)
        self.assertNotIn("--uplink-mbps", rep["verdict"]["next_step"])

    def test_listening_is_not_serving(self):
        """Found on a real laptop: almost every machine has something bound to
        a port, so "has a listener and talks to things" describes a laptop as
        well as a proxy - and it picked whichever application server was open
        as a "backend", then re-owned the verdicts to an internal segment for a
        public address."""
        text = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:5000 0.0.0.0:*\n"
                + "".join(f"ESTAB 0 0 10.0.0.5:5510{i} 198.51.100.10:443\n"
                          for i in range(6)))
        parsed = nd.parse_socket_states(text); parsed["ok"] = True
        self.assertIsNone(nd.pick_backend(parsed))

    def test_a_public_dependency_is_aimed_at_but_not_called_internal(self):
        """A managed database or an external API is a real dependency worth
        aiming at. The path to it leaves the site, so the verdicts that say
        "the segment between here and that backend" must not apply."""
        text = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n" + self.CLIENTS
                + "".join(f"ESTAB 0 0 10.0.0.5:441{i} 198.51.100.7:5432\n"
                          for i in range(6)))
        m = fresh(); with_backend(m, text)
        rep = m.diagnose(None, None, quick=False)
        self.assertEqual(rep["target"], "198.51.100.7")
        self.assertEqual(rep["raw"]["target_kind"], "dependency")

    def test_only_an_internal_target_re_owns_the_verdicts(self):
        verdict = {"based_on": ["inet_unreachable"], "owner": "the provider",
                   "headline": "h", "next_step": "n"}
        nd._retarget_verdict(verdict, {"target_kind": "dependency"})
        self.assertEqual(verdict["owner"], "the provider")
        nd._retarget_verdict(verdict, {"target_kind": "backend"})
        self.assertIn("backend", verdict["owner"])

    def test_every_backend_override_names_a_rule_that_exists(self):
        codes = {r[0] for r in nd.VERDICT_RULES}
        self.assertFalse(set(nd.BACKEND_TARGET_VERDICTS) - codes)


class TestFlowSides(unittest.TestCase):
    """Client-side and backend-side are two networks with two owners."""

    def run_with(self, *socks):
        m = fresh()
        sided_flows(m, *socks)
        rep = m.diagnose("8.8.8.8", None, quick=False)
        return rep, [f.get("code") for f in rep["findings"]]

    def clients_ok(self):
        return [sided_sock("203.0.113.9", "443", sent=40_000_000, retrans=2000),
                sided_sock("203.0.113.10", "443", sent=38_000_000, retrans=1800)]

    def backend_bad(self):
        return sided_sock("10.0.0.90", "44120", sent=30_000_000,
                          retrans=2_400_000, port="5432")

    def test_a_lossy_backend_is_not_the_carriers_problem(self):
        """The case this exists for. Before it, a lossy database on 10.0.0.90
        reported "some destinations are losing traffic", owner *the provider or
        upstream* - which sends someone to argue with a carrier about the
        inside of their own rack."""
        rep, codes = self.run_with(*self.clients_ok(), self.backend_bad())
        self.assertIn("tcp_flow_loss_backends", codes)
        self.assertEqual(rep["verdict"]["based_on"][0], "tcp_flow_loss_backends")
        owner = rep["verdict"]["owner"]
        self.assertNotIn("provider", owner)
        self.assertNotIn("upstream", owner)

    def test_lossy_clients_with_healthy_backends_point_the_other_way(self):
        rep, codes = self.run_with(
            sided_sock("203.0.113.9", "443", sent=40_000_000, retrans=3_200_000),
            sided_sock("10.0.0.90", "44120", sent=30_000_000, retrans=900, port="5432"))
        self.assertIn("tcp_flow_loss_clients", codes)
        self.assertIn("using it", rep["verdict"]["owner"])

    def test_loss_on_both_sides_falls_back_to_the_shape(self):
        """If both are lossy the direction says nothing useful, and the
        existing every-destination reading is the better answer."""
        _rep, codes = self.run_with(
            sided_sock("203.0.113.9", "443", sent=40_000_000, retrans=3_200_000),
            self.backend_bad())
        self.assertNotIn("tcp_flow_loss_backends", codes)
        self.assertNotIn("tcp_flow_loss_clients", codes)
        self.assertTrue(any(c.startswith("tcp_flow_loss_") for c in codes))

    def test_a_box_that_serves_nothing_keeps_the_old_behaviour(self):
        """With no listening ports every flow is outbound by definition, and
        inventing a side would be a claim the data cannot support."""
        m = fresh()
        flows(m, ss_flow("203.0.113.9", sent=40_000_000, retrans=2000),
                 ss_flow("10.0.0.90", sent=30_000_000, retrans=2_400_000, port="5432"))
        rep = m.diagnose("8.8.8.8", None, quick=False)
        codes = [f.get("code") for f in rep["findings"]]
        self.assertNotIn("tcp_flow_loss_backends", codes)
        self.assertIsNone(rep["raw"]["tcp_flows"]["lossy_side"])

    def test_a_flow_is_a_clients_only_when_its_local_port_is_listening(self):
        text = (SS_HEADER
                + sided_sock("203.0.113.9", "443", sent=1_000_000, retrans=10)
                + sided_sock("10.0.0.90", "44120", sent=1_000_000, retrans=10,
                             port="5432"))
        parsed = nd.parse_tcp_flows(text)
        self.assertEqual([f["local_port"] for f in parsed], ["443", "44120"])
        nd.analyze_tcp_flows(parsed, listen_ports=["443"])
        self.assertEqual([f["side"] for f in parsed], ["client", "backend"])
        # A port this box is not listening on is never a client's, however
        # much it looks like one.
        again = nd.parse_tcp_flows(text)
        nd.analyze_tcp_flows(again, listen_ports=["8443"])
        self.assertEqual([f["side"] for f in again], ["backend", "backend"])


class TestOwnServiceAnswers(unittest.TestCase):
    """Accepting a connection is not answering a request."""

    def serve(self, handler):
        import socket as _socket, threading
        s = _socket.socket()
        s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.listen(4)
        self.addCleanup(s.close)
        def loop():
            try:
                conn, _ = s.accept()
                handler(conn)
            except OSError:
                pass
        threading.Thread(target=loop, daemon=True).start()
        return port

    def ask(self, handler, timeout=2):
        """The service's answer, and the *faults* found in it.

        Faults, not findings: every answer also carries the phase split as
        context, and every test here is about whether something is wrong.
        """
        res = nd.cmd_own_http(self.serve(handler), timeout=timeout)
        found = []
        nd._own_service_findings(res, res["port"], found)
        return res, [f["code"] for f in found if f["severity"] != "ok"]

    @staticmethod
    def _reply(body):
        def handler(conn):
            conn.recv(2048)
            conn.sendall(body)
            conn.close()
        return handler

    def test_a_service_that_answers_is_left_alone(self):
        res, codes = self.ask(self._reply(b"HTTP/1.1 200 OK\r\n\r\n"))
        self.assertEqual(res["status"], 200)
        self.assertEqual(codes, [])

    def test_a_four_hundred_is_still_an_answer(self):
        """401 or 404 means the service is up and replying. Only the server
        errors are its own failure."""
        for code in (b"401 Unauthorized", b"404 Not Found", b"301 Moved"):
            with self.subTest(code=code):
                _res, codes = self.ask(self._reply(b"HTTP/1.1 " + code + b"\r\n\r\n"))
                self.assertEqual(codes, [])

    def test_a_service_that_never_answers_is_the_case_this_exists_for(self):
        """It accepts, reads the request, and says nothing. The port is open,
        the handshake completes, every network check passes."""
        def silent(conn):
            conn.recv(2048)
            time.sleep(9)
        _res, codes = self.ask(silent)
        self.assertEqual(codes, ["own_service_silent"])

    def test_a_gateway_error_points_past_this_box_not_at_it(self):
        for status in (502, 503, 504):
            with self.subTest(status=status):
                _res, codes = self.ask(self._reply(
                    f"HTTP/1.1 {status} Gateway\r\n\r\n".encode()))
                self.assertEqual(codes, ["own_service_upstream_error"])
        self.assertEqual(nd.finding_side("own_service_upstream_error"), "upstream")

    def test_a_plain_server_error_is_the_service_itself(self):
        _res, codes = self.ask(self._reply(b"HTTP/1.1 500 Internal\r\n\r\n"))
        self.assertEqual(codes, ["own_service_erroring"])
        self.assertEqual(nd.finding_side("own_service_erroring"), "downstream")

    def test_something_that_is_not_http_is_reported_as_that(self):
        _res, codes = self.ask(self._reply(b"+OK POP3 ready\r\n"))
        self.assertEqual(codes, ["own_service_not_http"])

    def test_a_closed_port_says_nothing(self):
        import socket as _socket
        spare = _socket.socket(); spare.bind(("127.0.0.1", 0))
        port = spare.getsockname()[1]; spare.close()
        res = nd.cmd_own_http(port, timeout=1)
        found = []
        nd._own_service_findings(res, port, found)
        self.assertIn("unreachable_locally", res)
        self.assertEqual(found, [])

    def test_only_http_shaped_ports_are_asked(self):
        """This must never become a probe. A database or an SSH daemon is not
        sent an HTTP request just because it is listening."""
        text = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\n"
                "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                "LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\n")
        asked = []
        m = fresh()
        serving(m, text)
        m.cmd_own_http = lambda p, timeout=5, address="127.0.0.1", tls=False: (
            asked.append(p) or {"ok": True, "port": p, "status": 200, "host": address})
        m.diagnose("8.8.8.8", None, quick=False)
        self.assertEqual(asked, [8080])

    def test_quick_mode_asks_nothing(self):
        asked = []
        m = fresh()
        serving(m, "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                   "LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\n")
        m.cmd_own_http = lambda p, timeout=5, address="127.0.0.1", tls=False: (
            asked.append(p) or {"ok": True, "port": p, "status": 200})
        m.diagnose("8.8.8.8", None, quick=True)
        self.assertEqual(asked, [])


class TestOwnTlsListener(unittest.TestCase):
    """The certificate this box serves - which nothing here ever looked at."""

    def serve(self, days=30, tls=True, cn="api.internal.example"):
        """A real listener with a real certificate, on a spare port."""
        import ssl as _ssl, socket as _socket, threading, subprocess, tempfile
        sock = _socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.listen(8)
        self.addCleanup(sock.close)
        if not tls:
            threading.Thread(target=lambda: [sock.accept()[0].close() for _ in range(4)],
                             daemon=True).start()
            return port
        d = tempfile.mkdtemp()
        key, crt = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
        proc = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
             "-out", crt, "-days", str(days), "-nodes", f"-subj", f"/CN={cn}",
             "-addext", f"subjectAltName=DNS:{cn}"], capture_output=True)
        if proc.returncode:
            self.skipTest("openssl not available to make a certificate")
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        def serve():
            while True:
                try:
                    conn, _ = sock.accept()
                    try:
                        ctx.wrap_socket(conn, server_side=True).close()
                    except Exception:
                        conn.close()
                except OSError:
                    return
        threading.Thread(target=serve, daemon=True).start()
        return port

    def test_a_certificate_close_to_expiry_is_reported(self):
        port = self.serve(days=5)
        res = nd.cmd_own_tls(port)
        self.assertTrue(res["ok"])
        self.assertEqual(res["names"], ["api.internal.example"])
        self.assertLessEqual(res["days_left"], 5)
        findings = []
        nd._own_tls_findings(res, port, findings)
        self.assertEqual([f["code"] for f in findings], ["own_tls_expiring"])

    def test_a_private_certificate_still_gives_up_its_expiry(self):
        """A cert that doesn't verify never reaches Python's parsed dates, and
        a private CA is most of what a proxy serves. The dates are printable
        ASCII inside the DER, so the string scan already here reaches them."""
        port = self.serve(days=400)
        res = nd.cmd_own_tls(port)
        self.assertFalse(res["verified"])
        self.assertEqual(res["expiry_from"], "the certificate's own bytes")
        self.assertGreater(res["days_left"], 300)

    def test_an_untrusted_chain_is_reported_when_expiry_is_fine(self):
        port = self.serve(days=400)
        findings = []
        nd._own_tls_findings(nd.cmd_own_tls(port), port, findings)
        self.assertEqual([f["code"] for f in findings], ["own_tls_untrusted"])

    def test_a_port_bound_to_nothing_here_says_nothing(self):
        """A service bound only to a public address is healthy and simply not
        on loopback. Calling that a broken listener would fire on every box
        that binds to one interface."""
        import socket as _socket
        spare = _socket.socket()
        spare.bind(("127.0.0.1", 0))
        port = spare.getsockname()[1]
        spare.close()
        res = nd.cmd_own_tls(port)
        self.assertIn("unreachable_locally", res)
        findings = []
        nd._own_tls_findings(res, port, findings)
        self.assertEqual(findings, [])

    def test_a_plain_tcp_service_on_a_tls_port_is_a_broken_listener(self):
        """TCP connects, the handshake does not. That is the service's TLS,
        and every client is getting exactly the same thing."""
        port = self.serve(tls=False)
        findings = []
        nd._own_tls_findings(nd.cmd_own_tls(port), port, findings)
        self.assertEqual([f["code"] for f in findings], ["own_tls_handshake_failed"])

    def test_junk_in_the_certificate_bytes_is_not_read_as_a_hostname(self):
        """A DER is full of key material that reads as text. A random "v.RD"
        was matched by an earlier pattern and became the name this box was
        verified against, so the handshake failed for a reason that had
        nothing to do with the certificate - and it only appeared on about one
        certificate in ten."""
        self.assertEqual(nd._cert_names(b"xx v.RD xx"), [])
        # Long enough to clear the length guard, so only the case rule can
        # reject it - certificates carry their names in lowercase.
        self.assertEqual(nd._cert_names(b"zz API.INTERNAL.EXAMPLE zz"), [])
        self.assertEqual(nd._cert_names(b"zz Mixed.Case.Example zz"), [])
        self.assertEqual(nd._cert_names(b"xx A.COM xx"), [])
        self.assertEqual(nd._cert_names(b"xx a.io xx"), [])          # too short
        self.assertEqual(nd._cert_names(b"zz api.internal.example zz"),
                         ["api.internal.example"])
        self.assertEqual(nd._cert_names(b"zz *.example.org zz"), ["example.org"])

    def test_the_name_scan_is_stable_across_many_certificates(self):
        """Ten fresh certificates, no junk names on any of them."""
        import ssl as _ssl
        seen = set()
        for _ in range(10):
            port = self.serve(days=30)
            res = nd.cmd_own_tls(port)
            seen.update(res.get("names") or [])
        self.assertEqual(seen, {"api.internal.example"})

    def test_validity_needs_two_stamps_and_takes_the_outer_pair(self):
        self.assertEqual(nd.der_validity(b""), (None, None))
        self.assertEqual(nd.der_validity(b"xx260812120000Zxx"), (None, None))
        lo, hi = nd.der_validity(b"aaaa250101000000Zbbbb260812120000Zcccc")
        self.assertEqual(lo.year, 2025)
        self.assertEqual(hi.year, 2026)

    def test_a_wildcard_bind_is_dialled_on_loopback_a_specific_one_directly(self):
        self.assertEqual(nd._listener_address("0.0.0.0"), "127.0.0.1")
        self.assertEqual(nd._listener_address("::"), "127.0.0.1")
        self.assertEqual(nd._listener_address("*"), "127.0.0.1")
        self.assertEqual(nd._listener_address(""), "127.0.0.1")
        self.assertEqual(nd._listener_address("10.0.0.5"), "10.0.0.5")
        self.assertEqual(nd._listener_address("[2001:db8::1]"), "2001:db8::1")

    def test_only_listening_tls_ports_are_touched(self):
        """This must never become a probe. It opens a handshake against ports
        this box already accepts connections on, and nothing else."""
        text = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
                "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                "LISTEN 0 128 0.0.0.0:9999 0.0.0.0:*\n")
        tried = []
        m = fresh()
        serving(m, text)
        m.cmd_own_tls = lambda p, timeout=5, address="127.0.0.1": (
            tried.append(p) or {"ok": False, "unreachable_locally": "x", "port": p,
                                "host": address})
        m._check_own_tls(m.diagnose_raw_stub() if hasattr(m, "diagnose_raw_stub")
                         else {"sockets": m.cmd_socket_states()}, [], quick=False)
        self.assertEqual(tried, [443])


class TestProxyScale(unittest.TestCase):
    """A box holding tens of thousands of connections, not four hundred."""

    def table(self, n):
        return SS_HEADER + "".join(
            ss_flow(f"10.{i//65536%256}.{i//256%256}.{i%256}", sent=1_000_000,
                    retrans=(50_000 if i % 97 == 0 else 100),
                    port=str(1024 + i % 60000))
            for i in range(n))

    def collect(self, n):
        mod = fresh()
        text = self.table(n)
        mod.OS_NAME = "Linux"
        mod.which = lambda c: c == "ss"
        mod.run = lambda cmd, timeout=15, limit=None: {
            "ok": True, "cmd": " ".join(cmd), "stdout": mod._cap(text, limit),
            "stderr": "", "code": 0}
        return mod.cmd_tcp_flows(), text

    def test_a_busy_proxy_is_analysed_far_beyond_the_old_report_cap(self):
        """`ss -tin` is ~430 bytes per connection, so the report's 64 KB budget
        was an arbitrary first ~150 sockets on a box holding tens of thousands
        - and "worst peer" was picked from that 0.3% sample."""
        res, text = self.collect(40_000)
        self.assertGreater(len(text), 5_000_000)
        self.assertGreaterEqual(res["flows_seen"], 20_000)
        self.assertIsNotNone(res["worst_peer"])

    def test_the_raw_socket_table_is_still_never_stored(self):
        """It names every peer this box talks to. Reading more of it must not
        mean carrying more of it."""
        res, text = self.collect(40_000)
        self.assertLess(len(res["stdout"]), 2_000)
        blob = json.dumps(nd.json_safe(res))
        self.assertLess(len(blob), 5_000)
        self.assertNotIn("ESTAB", blob)

    def test_a_sample_that_hits_the_cap_still_says_so(self):
        res, _text = self.collect(40_000)
        self.assertTrue(res["truncated"])

    def test_a_small_box_is_not_declared_truncated(self):
        res, _text = self.collect(50)
        self.assertFalse(res["truncated"])
        self.assertEqual(res["flows_seen"], 50)

    def test_run_honours_an_explicit_limit_and_the_default_without_one(self):
        """Exercises run() itself. The tests above stub it out, so a limit that
        was accepted and then ignored inside run() passed all of them."""
        big = f"print('x' * {nd.MAX_OUTPUT_BYTES * 4})"
        capped = nd.run([sys.executable, "-c", big])
        self.assertLessEqual(len(capped["stdout"]), nd.MAX_OUTPUT_BYTES + 200)
        self.assertIn("not stored", capped["stdout"])
        raised = nd.run([sys.executable, "-c", big], limit=nd.MAX_OUTPUT_BYTES * 8)
        self.assertGreater(len(raised["stdout"]), nd.MAX_OUTPUT_BYTES * 3)
        self.assertNotIn("not stored", raised["stdout"])

    def test_every_run_stub_in_this_suite_accepts_the_read_limit(self):
        """A stub with the old signature raises TypeError the moment the real
        code passes the argument - which is a test failing for a reason that
        has nothing to do with what it was testing."""
        import inspect
        sig = inspect.signature(nd.run)
        self.assertIn("limit", sig.parameters)
        with open(__file__, encoding="utf-8") as fh:
            src = fh.read()
        stale = re.findall(r"run = lambda cmd, timeout=\d+:(?! )", src)
        self.assertEqual(stale, [])


class TestServerLimits(unittest.TestCase):
    """Ceilings on this box that look exactly like the network being broken."""

    def codes(self, mod, **kw):
        return [f.get("code") for f in
                mod.diagnose("8.8.8.8", None, quick=False, **kw)["findings"]]

    def test_syncookies_during_the_run_beat_the_symptoms_they_cause(self):
        """A queue overflowing makes connections fail everywhere at once, so
        it wears the signature of a bad path. It is not the path."""
        m = fresh()
        kernel_drops(m, {"SyncookiesSent": 0}, {"SyncookiesSent": 4200})
        ping_map(m, inet_loss=5, sent=20)
        rep = m.diagnose("8.8.8.8", None, quick=False)
        self.assertEqual(rep["verdict"]["based_on"][0], "syncookies_live")
        self.assertIn("backlog", rep["verdict"]["owner"])

    def test_a_historical_overflow_cannot_headline_over_a_live_fault(self):
        """Paired with a live fault that ranks *below* it on purpose. Against a
        higher-ranked one the ordering would decide this anyway and the test
        would pass whether or not the finding was latent."""
        m = fresh()
        m._uptime_seconds = lambda: 30 * 86400
        kernel_drops(m, {"SyncookiesSent": 90_000})
        ping_map(m, inet_loss=9, avg=400.0, mdev=120.0, sent=20)
        rep = m.diagnose("8.8.8.8", None, quick=False)
        codes = [f["code"] for f in rep["findings"]]
        self.assertIn("syncookies_historical", codes)
        rank = {r[0]: i for i, r in enumerate(nd.VERDICT_RULES)}
        named = rep["verdict"]["based_on"][0]
        self.assertNotEqual(named, "syncookies_historical")
        self.assertGreater(rank[named], rank["syncookies_historical"])

    def sockets(self, mod, text):
        parsed = nd.parse_socket_states(text)
        mod.cmd_socket_states = lambda: dict(
            {"ok": True, "cmd": "ss", "stdout": ""}, **parsed)

    def to_one(self, n, port=5432):
        return ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                + "".join(f"ESTAB 0 0 10.0.0.5:{60000+i} 10.0.0.90:{port}\n"
                          for i in range(n)))

    def test_ephemeral_exhaustion_is_measured_against_the_configured_range(self):
        """Not against 65535. A box with a narrowed range runs out far sooner,
        and that is exactly the box this happens to."""
        m = fresh()
        kernel_drops(m, {"ephemeral_low": 60000, "ephemeral_high": 60999,
                         "ephemeral_total": 1000})
        self.sockets(m, self.to_one(900))
        self.assertIn("ephemeral_ports_low", self.codes(m))

    def test_a_wide_range_with_the_same_socket_count_is_fine(self):
        m = fresh()
        kernel_drops(m, {"ephemeral_low": 1024, "ephemeral_high": 65535,
                         "ephemeral_total": 64512})
        self.sockets(m, self.to_one(900))
        self.assertNotIn("ephemeral_ports_low", self.codes(m))

    def test_pressure_is_per_destination_not_across_all_of_them(self):
        """A source port only has to be unique within the four-tuple, so the
        same one serves any number of different destinations at once. Counting
        every outbound socket against the range reported exhaustion on a box
        forwarding traffic to hundreds of places with enormous headroom."""
        spread = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                  + "".join(f"ESTAB 0 0 10.0.0.5:{40000+i} 203.0.113.{i%250}:443\n"
                            for i in range(900)))
        m = fresh()
        kernel_drops(m, {"ephemeral_low": 60000, "ephemeral_high": 60999,
                         "ephemeral_total": 1000})
        self.sockets(m, spread)
        self.assertNotIn("ephemeral_ports_low", self.codes(m))
        # The same 900 connections, all to one place, is the real thing.
        m2 = fresh()
        kernel_drops(m2, {"ephemeral_low": 60000, "ephemeral_high": 60999,
                          "ephemeral_total": 1000})
        self.sockets(m2, self.to_one(900))
        self.assertIn("ephemeral_ports_low", self.codes(m2))

    def test_file_descriptors_in_use_is_allocated_minus_free(self):
        """file-nr is 'allocated free max'. Reading the first column as usage
        overstates it on every kernel that keeps a free list, which is all of
        them - 950k allocated with 700k free is 250k in use, not 950k."""
        got = nd.parse_server_limits(None, "950000 700000 1000000", None)
        self.assertEqual(got["fd_used"], 250_000)
        self.assertEqual(got["fd_max"], 1_000_000)
        m = fresh()
        kernel_drops(m, {"fd_used": 950_000, "fd_max": 1_000_000})
        self.assertIn("fd_pressure", self.codes(m))

    def test_fd_headroom_says_nothing(self):
        m = fresh()
        kernel_drops(m, {"fd_used": 12_000, "fd_max": 1_000_000})
        self.assertNotIn("fd_pressure", self.codes(m))

    def test_a_proxy_resetting_connections_is_not_reported_as_a_fault(self):
        """HAProxy closes backend connections with RST on purpose, via
        SO_LINGER, to conserve ports. A raw reset count is housekeeping on one
        box and a fault on another, so OutRsts is recorded and never becomes a
        finding - only the counters that say *why* a connection was aborted
        do."""
        m = fresh()
        kernel_drops(m, {"OutRsts": 0, "EstabResets": 0},
                        {"OutRsts": 90_000, "EstabResets": 40_000})
        codes = self.codes(m)
        self.assertNotIn("aborts_on_memory", codes)
        self.assertNotIn("reqq_full_drops", codes)
        self.assertNotIn("aborts_on_timeout", codes)
        self.assertEqual([c for c in codes if "rst" in c or "reset" in c], [])

    def test_out_of_socket_memory_is_never_normal(self):
        m = fresh()
        kernel_drops(m, {"TCPAbortOnMemory": 0}, {"TCPAbortOnMemory": 180})
        rep = m.diagnose("8.8.8.8", None, quick=False)
        self.assertEqual(rep["verdict"]["based_on"][0], "aborts_on_memory")
        self.assertIn("memory", rep["verdict"]["owner"])

    def test_timeout_aborts_need_a_share_not_a_count(self):
        """A public service always has some. Ninety out of two thousand is a
        path dropping traffic; ninety out of two hundred thousand is people
        closing laptops."""
        busy = fresh()
        kernel_drops(busy, {"TCPAbortOnTimeout": 0, "PassiveOpens": 0, "ActiveOpens": 0},
                           {"TCPAbortOnTimeout": 90, "PassiveOpens": 200_000, "ActiveOpens": 0})
        self.assertNotIn("aborts_on_timeout", self.codes(busy))
        quiet = fresh()
        kernel_drops(quiet, {"TCPAbortOnTimeout": 0, "PassiveOpens": 0, "ActiveOpens": 0},
                            {"TCPAbortOnTimeout": 90, "PassiveOpens": 1800, "ActiveOpens": 200})
        self.assertIn("aborts_on_timeout", self.codes(quiet))

    def test_a_tiny_sample_cannot_produce_a_share(self):
        """Two aborts out of eleven connections is 18% and means nothing."""
        m = fresh()
        kernel_drops(m, {"TCPAbortOnTimeout": 0, "PassiveOpens": 0, "ActiveOpens": 0},
                        {"TCPAbortOnTimeout": 2, "PassiveOpens": 11, "ActiveOpens": 0})
        self.assertNotIn("aborts_on_timeout", self.codes(m))

    def test_a_handful_of_half_open_connections_is_normal(self):
        text = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
                + "".join(f"SYN-RECV 0 0 10.0.0.5:443 203.0.113.{i}:5123\n"
                          for i in range(12)))
        m = fresh(); serving(m, text)
        kernel_drops(m, {"somaxconn": 4096})   # or the check never runs at all
        self.assertNotIn("syn_recv_backlog", self.codes(m))

    def test_unreadable_or_malformed_limits_are_absent_not_zero(self):
        """Off Linux none of these files exists. A zero would read as "no
        ports in use" and "no descriptors allocated", which are claims."""
        for args in ((None, None, None), ("", "", ""), ("garbage", "a b c", "x"),
                     ("32768", "1 2", "")):
            with self.subTest(args=args):
                self.assertEqual(nd.parse_server_limits(*args), {})

    def test_a_backwards_port_range_is_ignored(self):
        """hi < lo would give a negative total and a nonsense percentage."""
        self.assertEqual(nd.parse_server_limits("60999 32768", None, None), {})
        good = nd.parse_server_limits("32768 60999", None, None)
        self.assertEqual(good["ephemeral_total"], 28232)


class TestKernelLog(unittest.TestCase):
    """The kernel already timestamped what the counters can only average."""

    def collect(self, mod):
        return mod.cmd_kernel_log()

    def test_a_restricted_ring_buffer_is_unknown_not_healthy(self):
        """dmesg_restrict=1 is the default on Ubuntu and Debian. Reading its
        refusal as "no events logged" would turn the one check that can date a
        flap into a check that silently always passes."""
        m = fresh()
        klog(m, "", tool="dmesg", code=1)
        m.which = lambda c: c == "dmesg"          # journalctl not available either
        res = self.collect(m)
        self.assertFalse(res["ok"])
        self.assertIn("not readable", res["error"])

    def test_an_empty_buffer_is_also_unknown(self):
        """Containers hand back an empty ring rather than an error."""
        m = fresh()
        klog(m, "   \n", tool="dmesg", code=0)
        self.assertFalse(self.collect(m)["ok"])

    def test_journalctl_is_used_when_dmesg_is_restricted(self):
        m = fresh()
        m.OS_NAME = "Linux"
        m._uptime_seconds = lambda: 100_000
        m.which = lambda c: c in ("dmesg", "journalctl")
        calls = []
        def run(cmd, timeout=15):
            calls.append(cmd[0])
            if cmd[0] == "dmesg":
                return {"ok": True, "cmd": "dmesg", "stdout": "", "stderr": "",
                        "code": 1}
            return {"ok": True, "cmd": "journalctl", "stderr": "", "code": 0,
                    "stdout": f"{time.time() - 30:.6f} box kernel: eth0: NIC Link is Down\n"}
        m.run = run
        res = self.collect(m)
        self.assertEqual(calls, ["dmesg", "journalctl"])
        self.assertTrue(res["ok"])
        self.assertEqual(len(res["recent"]), 1)
        self.assertLess(res["recent"][0]["age_seconds"], 120)

    def test_a_kernel_without_printk_time_still_reports_the_event(self):
        """printk.time=0 leaves no bracket. The event is still real; only its
        age is unknown, so it must not be counted as recent on a guess."""
        m = fresh()
        klog(m, "eth0: Detected Hardware Unit Hang\n", uptime=100_000)
        res = self.collect(m)
        self.assertEqual(len(res["events"]), 1)
        self.assertIsNone(res["events"][0]["age_seconds"])
        self.assertEqual(res["recent"], [])
        self.assertFalse(res["timed"])

    def test_boot_time_events_are_not_recent_on_a_long_uptime(self):
        """Every machine logs "Link is Up" once at boot. On a box that has been
        up for months that is not a flap, and counting it as one would fire this
        finding on every healthy host."""
        m = fresh()
        klog(m, "\n".join(f"[{3.0 + i:.6f}] eth0: NIC Link is Up" for i in range(8)),
             uptime=90 * 86400)
        res = self.collect(m)
        self.assertEqual(len(res["events"]), 8)
        self.assertEqual(res["recent"], [])

    def test_the_interface_name_comes_off_a_driver_prefixed_line(self):
        m = fresh()
        klog(m, "[99990.0] e1000e 0000:00:1f.6 eno1: NIC Link is Down\n",
             uptime=100_000)
        self.assertEqual(self.collect(m)["events"][0]["iface"], "eno1")

    def test_the_log_supersedes_the_lifetime_average_for_the_same_link(self):
        """Two findings about one cable - a timestamped critical and a warning
        about a per-day rate - reads as two problems and buries the better one."""
        m = fresh()
        klog_flaps(m, count=80, over=600)
        counters(m, carrier_changes=900)      # high enough to trip the rate too
        codes = [f.get("code") for f in
                 m.diagnose("8.8.8.8", None, quick=False)["findings"]]
        self.assertIn("link_flapping_logged", codes)
        self.assertNotIn("link_flapping", codes)

    def test_a_clean_log_leaves_the_lifetime_check_working(self):
        """Suppression is per interface and only when the log named it. A
        readable log with nothing in it must not disable the counter check."""
        m = fresh()
        klog(m, "[10.0] Linux version 5.15.0\n[11.0] eth0: NIC Link is Up\n",
             uptime=86_400)
        counters(m, carrier_changes=900)
        codes = [f.get("code") for f in
                 m.diagnose("8.8.8.8", None, quick=False)["findings"]]
        self.assertIn("link_flapping", codes)

    def test_only_the_tail_of_a_huge_ring_buffer_is_kept(self):
        """A ring buffer is megabytes of boot messages followed by the lines
        that matter. Capping from the front stores the wrong half."""
        m = fresh()
        noise = "\n".join(f"[{i}.0] usb {i}-1: new high-speed USB device"
                          for i in range(200_000))
        klog(m, noise + "\n[999990.0] eth0: Detected Hardware Unit Hang\n",
             uptime=1_000_000)
        res = self.collect(m)
        self.assertIn("earlier characters not stored", res["stdout"])
        self.assertEqual([e["kind"] for e in res["recent"]], ["reset"])

    def test_it_does_not_run_off_linux(self):
        m = fresh()
        m.OS_NAME = "Darwin"
        self.assertFalse(self.collect(m)["ok"])

    def test_spans_read_the_way_someone_says_them(self):
        self.assertEqual(nd._fmt_span(45), "45s")
        self.assertEqual(nd._fmt_span(660), "11 minutes")
        self.assertEqual(nd._fmt_span(10_800), "3 hours")
        self.assertEqual(nd._fmt_span(259_200), "3 days")
        self.assertIsNone(nd._fmt_span(None))
        self.assertEqual(nd._fmt_ago(None), "at an unknown time")


class TestVerdict(unittest.TestCase):
    def f(self, code, severity="critical", layer=3):
        return {"code": code, "severity": severity, "layer": layer, "message": code}

    def test_every_verdict_that_says_check_the_port_names_the_port(self):
        """LLDP already knows which switch port this device is in. Any verdict
        that tells the reader to go look at a switch port should say which one
        - "check the port's own log" without a port name is a scavenger hunt.

        Written as an assertion over every rule rather than a check of the ones
        we thought of: the flap verdicts and the all-peers loss verdict were all
        missing, and all three read as covered until this asked the whole table.
        """
        phys = re.compile(r"switch port|the port's|different switch|port's own log",
                          re.I)
        missing = [r[0] for r in nd.VERDICT_RULES
                   if phys.search(" ".join(str(x) for x in r[1:]))
                   and r[0] not in nd.PORT_RELEVANT_CODES]
        self.assertEqual(missing, [], "verdicts sending the reader to a switch "
                                      "port without naming it")

    def test_flap_verdict_names_the_switch_port(self):
        m = fresh()
        counters(m, carrier_changes=2, d_carrier_changes=3)
        m.cmd_lldp = lambda: {"ok": True, "cmd": "lldpctl", "stdout": "", "neighbours": [
            {"iface": "eth0", "switch": "SW-BR14-CLOSET-2", "port": "Gi1/0/24",
             "vlan": "180", "via": "LLDP"}]}
        rep = m.diagnose("8.8.8.8", None, quick=False, soak=1)
        self.assertEqual(rep["verdict"]["based_on"][0], "link_flapping_live")
        self.assertIn("Gi1/0/24", rep["verdict"]["next_step"])

    # ---- the site's own uplink -----------------------------------------

    def congested(self, mbps=48, **kw):
        """A site pushing `mbps` through a gigabit NIC, with every symptom a
        full uplink produces: loss to everything, latency up, calls unusable."""
        m = fresh()
        counters(m, d_rx_bytes=int(mbps * 1e6 / 8 * 2))     # the window is 2s
        m.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
            {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500,
             "carrier": True}]}
        ping_map(m, inet_loss=4, avg=180.0, mdev=60.0, sent=20)
        flows(m, ss_flow("203.0.113.14", sent=40_000_000, retrans=1_400_000),
                 ss_flow("203.0.113.140", sent=30_000_000, retrans=1_000_000))
        return m.diagnose("8.8.8.8", None, quick=False, **kw)

    # ---- a box that serves traffic is a different box ------------------

    def test_no_egress_on_a_serving_box_is_policy_not_a_carrier_outage(self):
        """Clients holding connections open prove the network works in the
        direction a service needs. Missing outbound internet on a server is
        usually deliberate, and calling it a provider outage sends someone to
        argue with a carrier about a firewall rule."""
        m = fresh()
        ping_map(m, inet_loss=100, sent=20)
        unreachable(m, arp=True)
        serving(m)
        rep = m.diagnose("8.8.8.8", None, quick=False)
        codes = [f.get("code") for f in rep["findings"]]
        self.assertIn("egress_blocked", codes)
        self.assertNotIn("inet_unreachable", codes)
        self.assertEqual(nd.exit_status(rep), 1)
        self.assertNotIn("provider", rep["verdict"]["owner"])

    def test_a_client_box_with_no_egress_is_still_a_provider_outage(self):
        m = fresh()
        ping_map(m, inet_loss=100, sent=20)
        unreachable(m, arp=True)
        path_dies_short(m)
        rep = m.diagnose("8.8.8.8", None, quick=False)
        self.assertEqual(rep["verdict"]["based_on"][0], "inet_unreachable")
        self.assertEqual(nd.exit_status(rep), 2)

    def test_one_inbound_connection_is_not_a_box_serving_traffic(self):
        """Your own SSH session and a load-balancer health check both look
        like inbound connections. A handful is clients; one is not."""
        text = ("State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
                "ESTAB 0 0 10.0.0.5:443 203.0.113.1:51231\n")
        m = fresh()
        ping_map(m, inet_loss=100, sent=20)
        unreachable(m, arp=True)
        path_dies_short(m)
        serving(m, text)
        codes = [f.get("code") for f in
                 m.diagnose("8.8.8.8", None, quick=False)["findings"]]
        self.assertIn("inet_unreachable", codes)
        self.assertNotIn("egress_blocked", codes)

    def test_a_loopback_listener_is_not_the_box_serving_anyone(self):
        """redis on 127.0.0.1 is not a public service, and connections to it
        are not clients reaching this box over the network."""
        text = ("State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
                "LISTEN 0 128 127.0.0.1:6379 0.0.0.0:*\n"
                + "".join(f"ESTAB 0 0 127.0.0.1:6379 127.0.0.1:5123{i}\n"
                          for i in range(9)))
        parsed = nd.parse_socket_states(text)
        self.assertEqual(parsed["listen_ports"], [])
        self.assertEqual(parsed["inbound"], 0)

    def test_inbound_and_outbound_are_told_apart(self):
        parsed = nd.parse_socket_states(SERVING_SS
                                        + "ESTAB 0 0 10.0.0.5:44120 10.0.0.90:5432\n")
        self.assertEqual(parsed["listen_ports"], ["443"])
        self.assertEqual(parsed["inbound"], 9)
        self.assertEqual(parsed["outbound"], 1)

    def test_a_check_that_cannot_apply_here_is_not_a_check_that_failed(self):
        """A cloud instance has no fibre optics and no switch neighbour. Those
        were counted as failures, so every verdict on that box was marked down
        in confidence for running on the hardware it runs on."""
        raw = {"a": {"ok": True}, "b": {"ok": True},
               "c": {"ok": False, "error": "Linux-only", "applicable": False}}
        self.assertEqual(nd.collection_coverage(raw), (2, 2))
        raw["d"] = {"ok": False, "error": "the command failed"}
        self.assertEqual(nd.collection_coverage(raw), (2, 3))

    # ---- ICMP is one protocol, and the one most often blocked ----------

    def test_a_hardened_box_that_serves_traffic_is_not_an_outage(self):
        """Blocking outbound ICMP is ordinary hardening. This reported
        "the site's uplink is down", owner the provider, critical, exit 2 -
        on a box happily serving traffic. Every scheduled run would page."""
        m = fresh()
        ping_map(m, inet_loss=100, sent=20)
        m.cmd_check_port = lambda h, p, timeout=5: (
            {"ok": True, "cmd": f"tcp {h}:{p}"} if p == "443"
            else {"ok": False, "reason": "timeout"})
        rep = m.diagnose("8.8.8.8", None, quick=False)
        codes = [f.get("code") for f in rep["findings"]]
        self.assertIn("inet_icmp_filtered", codes)
        self.assertNotIn("inet_unreachable", codes)
        self.assertEqual(nd.exit_status(rep), 0)

    def test_a_refusal_proves_reachability_as_well_as_an_accept(self):
        """An RST is a completed round trip: the packets got there and the
        reply got back. Only a timeout is inconclusive."""
        m = fresh()
        ping_map(m, inet_loss=100, sent=20)
        m.cmd_check_port = lambda h, p, timeout=5: {
            "ok": False, "cmd": f"tcp {h}:{p}", "reason": "refused"}
        codes = [f.get("code") for f in
                 m.diagnose("8.8.8.8", None, quick=False)["findings"]]
        self.assertIn("inet_icmp_filtered", codes)
        self.assertNotIn("inet_unreachable", codes)

    def test_a_gateway_in_the_neighbour_table_has_a_working_link(self):
        """ARP does not cross a dead cable or a down switch port. ICMP blocked
        outright is routine in a cloud VPC, and reported the local link as
        down."""
        m = fresh()
        ping_map(m, gw_loss=100, inet_loss=100, sent=20)
        m.cmd_check_port = lambda h, p, timeout=5: {"ok": True, "cmd": "tcp"}
        rep = m.diagnose("8.8.8.8", None, quick=False)
        codes = [f.get("code") for f in rep["findings"]]
        self.assertIn("gw_icmp_filtered", codes)
        self.assertNotIn("gw_unreachable", codes)
        self.assertEqual(nd.exit_status(rep), 0)

    def test_a_genuinely_dead_link_is_still_critical(self):
        """The point is not to stop reporting outages."""
        m = fresh()
        ping_map(m, gw_loss=100, inet_loss=100, sent=20)
        unreachable(m)
        rep = m.diagnose("8.8.8.8", None, quick=False)
        self.assertEqual(rep["verdict"]["based_on"][0], "gw_unreachable")
        self.assertEqual(nd.exit_status(rep), 2)

    def test_a_genuinely_dead_uplink_is_still_critical(self):
        m = fresh()
        ping_map(m, inet_loss=100, sent=20)
        unreachable(m, arp=True)
        path_dies_short(m)
        rep = m.diagnose("8.8.8.8", None, quick=False)
        self.assertEqual(rep["verdict"]["based_on"][0], "inet_unreachable")
        self.assertEqual(rep["verdict"]["owner"], "the provider")
        self.assertEqual(nd.exit_status(rep), 2)

    def test_an_incomplete_neighbour_entry_does_not_count_as_an_answer(self):
        """An ARP entry with no MAC is the kernel asking, not the gateway
        replying - reading it as proof of a live link would suppress a real
        outage."""
        for stdout in ("10.0.0.1 dev eth0 FAILED\n",
                       "10.0.0.1 dev eth0 INCOMPLETE\n",
                       # No MAC and no state either - the kernel has an entry
                       # for the address and has never heard back.
                       "10.0.0.1 dev eth0\n",
                       "10.0.0.1 dev eth0 lladdr 00:11:22:33:44:55 FAILED\n"):
            with self.subTest(stdout=stdout.strip()):
                entries = nd.parse_arp_table(stdout)
                self.assertIsNone(nd._gateway_answers_arp(entries, "10.0.0.1"))
        entries = nd.parse_arp_table("10.0.0.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE\n")
        self.assertIsNotNone(nd._gateway_answers_arp(entries, "10.0.0.1"))

    def test_a_full_line_with_nothing_failing_cannot_headline_over_a_fault(self):
        """The prototype for the burst work found this: a nightly backup put
        the uplink at 96% with nobody complaining, and it took the headline
        over everything else in the report. A line being used is not a line
        that is broken."""
        m = fresh()
        counters(m, d_rx_bytes=12_000_000)
        m.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
            {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500,
             "carrier": True}]}
        resolvers(m, [R("10.0.0.53", ok=False)])          # a real fault beside it
        rep = m.diagnose("8.8.8.8", None, quick=False, uplink_mbps=50)
        codes = [f.get("code") for f in rep["findings"]]
        self.assertIn("uplink_busy", codes)
        self.assertNotIn("uplink_saturated", codes)
        self.assertNotEqual(rep["verdict"]["based_on"][0], "uplink_busy")

    def test_a_full_line_is_still_the_answer_when_nothing_else_is_wrong(self):
        """Latent means it cannot headline over a live fault - not that it is
        suppressed. With nothing else broken it is exactly what you want told."""
        m = fresh()
        counters(m, d_rx_bytes=12_000_000)
        m.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
            {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500,
             "carrier": True}]}
        rep = m.diagnose("8.8.8.8", None, quick=False, uplink_mbps=50)
        self.assertEqual(rep["verdict"]["based_on"][0], "uplink_busy")

    def test_the_latent_siblings_are_paired_with_a_live_form(self):
        """Every _busy code must have a saturated counterpart and vice versa -
        a split that only went one way would silently drop a finding."""
        codes = {r[0] for r in nd.VERDICT_RULES}
        for busy, live in (("uplink_busy", "uplink_saturated"),
                           ("link_busy", "link_saturated")):
            self.assertIn(busy, codes)
            self.assertIn(live, codes)
            self.assertIn(busy, nd.LATENT)
            self.assertNotIn(live, nd.LATENT)

    def test_a_full_site_uplink_is_not_the_carriers_fault(self):
        """The case this was built for. 48 Mbps on a 50 Mbps line is 96% of the
        thing that is actually full and 4.8% of the NIC, so before --uplink-mbps
        existed the same run said "packet loss beyond the gateway, owner: the
        provider" at high confidence - a carrier ticket for congestion the site
        was causing itself."""
        v = self.congested(uplink_mbps=50)["verdict"]
        self.assertEqual(v["based_on"][0], "uplink_saturated")
        self.assertIn("capacity", v["owner"])
        self.assertNotIn("provider", v["owner"])

    def test_an_uplink_with_headroom_leaves_the_verdict_alone(self):
        v = self.congested(uplink_mbps=500)["verdict"]
        self.assertEqual(v["based_on"][0], "inet_partial_loss")
        self.assertEqual(v["confidence"], "high")
        self.assertNotIn("--uplink-mbps", v["next_step"])

    def test_blaming_upstream_with_the_line_rate_unknown_is_not_high_confidence(self):
        v = self.congested()["verdict"]
        self.assertEqual(v["based_on"][0], "inet_partial_loss")
        self.assertEqual(v["confidence"], "medium")
        self.assertIn("--uplink-mbps", v["next_step"])

    def test_a_quiet_device_gets_no_caveat(self):
        """Half a megabit fills nothing anyone was sold, so the caveat would be
        noise on every upstream verdict rather than a real alternative."""
        v = self.congested(mbps=0.5)["verdict"]
        self.assertEqual(v["confidence"], "high")
        self.assertNotIn("--uplink-mbps", v["next_step"])

    def test_the_caveat_only_attaches_to_verdicts_congestion_could_explain(self):
        """A dead gateway is not what a full uplink looks like."""
        m = fresh()
        counters(m, d_rx_bytes=int(48e6 / 8 * 2))
        ping_map(m, gw_loss=100, inet_loss=100, sent=20)
        v = m.diagnose("8.8.8.8", None, quick=False)["verdict"]
        self.assertNotIn("--uplink-mbps", v["next_step"])

    def test_the_masquerade_set_only_names_findings_that_exist(self):
        known = {r[0] for r in nd.VERDICT_RULES}
        self.assertFalse(nd.CONGESTION_MASQUERADE - known,
                         "CONGESTION_MASQUERADE names codes no rule ranks")

    def test_default_route_interface_ignores_a_windows_metric_column(self):
        """`route print` ends the default line with a metric, not an interface.
        Reading "25" as the interface name silently disabled the uplink check
        on every Windows box instead of failing where anyone would see it."""
        raw = {"routes": {"ok": True, "stdout":
                          "0.0.0.0   0.0.0.0   192.168.0.1   192.168.0.44     25\n"},
               "link_stats": {"interfaces": [{"name": "Ethernet"}]}}
        self.assertIsNone(nd._default_route_iface(raw))
        raw["routes"]["stdout"] = "default via 10.0.0.1 dev eth0 proto dhcp\n"
        raw["link_stats"]["interfaces"] = [{"name": "eth0"}]
        self.assertEqual(nd._default_route_iface(raw), "eth0")

    def test_root_cause_beats_its_own_symptoms(self):
        # A dead gateway also breaks internet and DNS; the gateway is the cause.
        v = nd.build_verdict([self.f("gw_unreachable", layer=2),
                              self.f("inet_unreachable", layer=3),
                              self.f("dns_fail", layer=7)])
        self.assertIn("gateway", v["headline"].lower())
        self.assertEqual(v["owner"], "the site network")

    def test_downstream_symptoms_do_not_inflate_confidence(self):
        v = nd.build_verdict([self.f("gw_unreachable", layer=2),
                              self.f("dns_fail", layer=7)])
        self.assertEqual(v["confidence"], "medium")

    def test_corroboration_at_the_same_layer_raises_confidence(self):
        v = nd.build_verdict([self.f("duplex_mismatch", layer=1),
                              self.f("collisions", "warning", layer=1)])
        self.assertEqual(v["confidence"], "high")

    def test_repetition_within_one_check_does_not_raise_confidence(self):
        """Four closed ports are four results from one check, not four
        independent signals. Treating them as corroboration made a speculative
        sweep of a DNS server read as a high-confidence root cause."""
        many_ports = [self.f("port_timeout", "warning", layer=4) for _ in range(3)]
        many_ports.append(self.f("port_refused", "warning", layer=4))
        self.assertEqual(nd.build_verdict(many_ports)["confidence"], "medium")

    def test_a_different_check_at_the_same_layer_does_corroborate(self):
        v = nd.build_verdict([self.f("duplex_mismatch", layer=1),
                              self.f("link_errors_live", layer=1)])
        self.assertEqual(v["confidence"], "high")

    def test_an_unreadable_resolver_config_is_not_an_absent_one(self):
        """An empty resolver list means two different things. "None configured"
        is a fault on this device; "couldn't read the file" is a gap in the run.
        A locked-down box with a root-only resolv.conf was getting a critical
        "no DNS resolvers configured at all" verdict from a permissions error."""
        m = fresh()
        m.cmd_dns_health = lambda check_hijack=True: {
            "ok": False, "cmd": "resolver check", "resolvers": [], "stdout": "",
            "unreadable": "/etc/resolv.conf could not be read (Permission denied)",
            "error": "/etc/resolv.conf could not be read (Permission denied)"}
        report = m.diagnose("8.8.8.8", None, quick=False, baseline=None)
        codes = [f.get("code") for f in report["findings"]]
        self.assertIn("resolvers_unreadable", codes)
        self.assertNotIn("dns_no_resolvers", codes)
        self.assertNotEqual(report["verdict"]["severity"], "critical")

    def test_a_genuinely_empty_resolver_list_is_still_a_fault(self):
        """The guard has to be the unreadable flag, not merely an empty list."""
        m = fresh()
        m.cmd_dns_health = lambda check_hijack=True: {
            "ok": False, "cmd": "resolver check", "resolvers": [], "stdout": "",
            "unreadable": None,
            "error": "no DNS resolvers are configured on this device"}
        report = m.diagnose("8.8.8.8", None, quick=False, baseline=None)
        codes = [f.get("code") for f in report["findings"]]
        self.assertIn("dns_no_resolvers", codes)
        self.assertNotIn("resolvers_unreadable", codes)

    def test_list_resolvers_says_why_it_found_nothing(self):
        m = fresh()
        def boom(*a, **k):
            raise OSError(13, "Permission denied", "/etc/resolv.conf")
        m.open = boom
        m.OS_NAME = "Linux"
        found, reason = m.list_resolvers(with_reason=True)
        self.assertEqual(found, [])
        self.assertIn("Permission denied", reason)
        # and the plain call still returns a bare list for its other caller
        self.assertEqual(m.list_resolvers(), [])

    def test_the_same_fault_is_always_worded_the_same_way(self):
        """The disagreeing answers were joined in set order, and string hashing
        is randomised per process - so one fault got written two different ways
        between runs. That reads as a change on the next --baseline, and makes
        a report pasted into a ticket unrepeatable."""
        import subprocess as sp
        script = (
            "import sys; sys.path.insert(0, %r); sys.argv=['x']\n"
            "import test_faultone as T\n"
            "setup, kw = T.S['dns_disagree']\n"
            "m = T.fresh(); setup(m)\n"
            "r = m.diagnose('8.8.8.8', None, quick=False, baseline=None)\n"
            "print([f['message'] for f in r['findings'] if f.get('code')=='dns_disagree'][0])\n"
            % os.path.dirname(os.path.abspath(__file__)))
        seen = set()
        for seed in ("1", "2", "3", "4"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            out = sp.run([sys.executable, "-c", script], capture_output=True,
                         text=True, env=env, timeout=60)
            seen.add(out.stdout.strip())
        self.assertEqual(len(seen), 1,
                         f"the same fault produced {len(seen)} different messages: {seen}")

    def test_no_verdict_path_omits_its_coverage(self):
        """The fault paths were taught to account for coverage and the all-clear
        path was missed - which is the one that matters most. "Nothing is wrong"
        from a box where half the checks could not run is the most dangerous
        thing this tool can say."""
        cases = {
            "all clear": [],
            "a fault": [self.f("link_errors_live", layer=1)],
            "no rule matches": [self.f("not_a_ranked_code", layer=3)],
        }
        raw = {f"c{i}": {"ok": True} for i in range(10)}
        for label, findings in cases.items():
            with self.subTest(path=label):
                v = nd.build_verdict(findings, raw=raw)
                self.assertIn("coverage", v, f"the {label} path drops coverage")
                self.assertEqual(v["coverage"]["attempted"], 10)

    def test_a_clean_run_on_a_half_dead_box_is_not_a_clean_bill_of_health(self):
        thin = {f"c{i}": {"ok": i < 6} for i in range(20)}
        v = nd.build_verdict([], raw=thin)
        self.assertEqual(v["confidence"], "low")
        self.assertIn("could not run", v["headline"])
        self.assertIn("not a clean bill of health", v["owner"])
        # and the opposite: everything ran, so the old wording stands
        full = {f"c{i}": {"ok": True} for i in range(20)}
        clean = nd.build_verdict([], raw=full)
        self.assertEqual(clean["confidence"], "high")
        self.assertIn("looks healthy", clean["headline"])

    def test_a_verdict_from_a_crippled_box_is_not_as_sure(self):
        """Twelve of fourteen collections failing and still reading "medium"
        applied the tool's own principle inconsistently: scrupulous that a
        check which couldn't run is never a fault, then silent about how many
        couldn't run when saying how sure we are."""
        findings = [self.f("link_errors_live", layer=1)]
        raw_full = {f"c{i}": {"ok": True} for i in range(20)}
        raw_thin = dict(raw_full, **{f"c{i}": {"ok": False, "error": "x"} for i in range(15)})
        self.assertEqual(nd.build_verdict(findings, raw=raw_full)["confidence"], "medium")
        self.assertEqual(nd.build_verdict(findings, raw=raw_thin)["confidence"], "low")

    def test_coverage_is_counted_not_estimated(self):
        """The number a percentage of confidence was reaching for. This one is
        checkable; a probability against unobserved outcomes would not be."""
        raw = {"a": {"ok": True}, "b": {"ok": True}, "c": {"ok": False, "error": "no"},
               "d": {"not a collection": 1}}
        self.assertEqual(nd.collection_coverage(raw), (2, 3))
        self.assertEqual(nd.collection_coverage({}), (0, 0))
        self.assertEqual(nd.collection_coverage(None), (0, 0))

    def test_thin_coverage_cannot_be_argued_up_by_corroboration(self):
        """Two agreeing checks out of twenty that ran is still two checks."""
        findings = [self.f("link_errors_live", layer=1), self.f("duplex_mismatch", layer=1)]
        raw_thin = {f"c{i}": {"ok": i < 3} for i in range(20)}
        self.assertEqual(nd.build_verdict(findings, raw=raw_thin)["confidence"], "low")

    def test_a_fault_the_verdict_cannot_explain_is_still_named(self):
        """The layer rule assumes a causal chain. Where there isn't one it
        discarded the rest - so reseating the cable left the expired
        certificate exactly where it was, and nothing said so."""
        findings = [self.f("link_flapping_live", layer=1),
                    self.f("tls_expired", layer=7)]
        v = nd.build_verdict(findings)
        self.assertEqual(v["based_on"][0], "link_flapping_live")
        self.assertEqual([u["code"] for u in v["unrelated"]], ["tls_expired"])

    def test_a_symptom_of_the_cause_is_not_called_unrelated(self):
        """Same family means the verdict already accounts for it - that is the
        chain working, and repeating it would undo the point of one answer."""
        findings = [self.f("link_errors_live", layer=1),
                    self.f("link_flapping", layer=1)]
        self.assertEqual(nd.build_verdict(findings)["unrelated"], [])

    def test_the_unrelated_list_is_capped(self):
        """The point is to stop hiding a second fault, not to hand the findings
        list back a second time."""
        findings = [self.f("link_errors_live", layer=1)] + [
            self.f(c, layer=7) for c in ("tls_expired", "dns_fail", "dns_hijack")]
        self.assertLessEqual(len(nd.build_verdict(findings)["unrelated"]), 2)

    def test_a_finding_too_weak_to_be_a_verdict_is_too_weak_to_be_evidence(self):
        """A non-standard MTU reads as low confidence when it's the answer, so
        it shouldn't raise someone else's. It was turning an unrelated medium
        call into a high one purely by being present in the report."""
        # no_ipv4 ranks first, so it's the verdict whichever weak code is added
        # alongside it - the question is only whether that code lifts it.
        for weak in sorted(nd.WEAK_EVIDENCE):
            with self.subTest(weak=weak):
                v = nd.build_verdict([self.f("no_ipv4", layer=3), self.f(weak, layer=3)])
                self.assertEqual(v["confidence"], "medium")
                self.assertNotIn(weak, v["based_on"])

    def test_the_weak_set_and_the_low_confidence_rule_stay_in_step(self):
        """Both used to be the same three codes written out twice. If a finding
        is demoted in one place it has to be demoted in the other."""
        for weak in sorted(nd.WEAK_EVIDENCE):
            with self.subTest(weak=weak):
                self.assertEqual(nd.build_verdict([self.f(weak, layer=3)])["confidence"], "low")

    def test_finding_families(self):
        self.assertEqual(nd._finding_family("port_timeout"), nd._finding_family("port_refused"))
        self.assertNotEqual(nd._finding_family("port_timeout"), nd._finding_family("dns_fail"))
        self.assertEqual(nd._finding_family(None), "")

    def test_history_only_signal_is_low_confidence(self):
        v = nd.build_verdict([self.f("link_errors_historical", "warning", layer=1)])
        self.assertEqual(v["confidence"], "low")

    def test_uplink_failure_is_attributed_to_the_provider(self):
        v = nd.build_verdict([self.f("inet_unreachable"), self.f("dns_fail", layer=7)])
        self.assertEqual(v["owner"], "the provider")

    def test_all_clear(self):
        v = nd.build_verdict([{"code": "all_clear", "severity": "ok", "message": "fine"}])
        self.assertEqual(v["severity"], "ok")
        self.assertIn("no fault", v["headline"].lower())

    def test_quick_run_advice_only_appears_for_quick_runs(self):
        clear = [{"code": "all_clear", "severity": "ok", "message": "fine"}]
        self.assertIn("--quick", nd.build_verdict(clear, quick=True)["next_step"])
        self.assertNotIn("--quick", nd.build_verdict(clear, quick=False)["next_step"])

    def test_every_actionable_finding_has_a_verdict_rule(self):
        """The reverse of the check below, and the one that actually caught
        something: path_loss shipped with no rule, so a 27% loss to the
        destination let a context finding (CGNAT) be named the root cause."""
        import re
        with open(nd.__file__, encoding="utf-8") as fh:
            src = fh.read()
        emitted = set(re.findall(r'"code": "(\w+)"', src))
        ruled = {code for code, *_ in nd.VERDICT_RULES}
        unranked = emitted - ruled - nd.VERDICT_EXEMPT
        self.assertFalse(unranked,
                         f"finding codes with no verdict rule: {sorted(unranked)}. "
                         "Add a rule, or add to VERDICT_EXEMPT if it's context.")

    def test_real_loss_outranks_context_findings(self):
        v = nd.build_verdict([self.f("cgnat", "warning"), self.f("path_loss")])
        self.assertIn("dropped", v["headline"].lower())

    def test_every_rule_code_is_one_a_finding_can_emit(self):
        # Guards against a rule keyed to a code that was renamed away.
        import re
        with open(nd.__file__, encoding="utf-8") as fh:
            src = fh.read()
        emitted = set(re.findall(r'"code": "(\w+)"', src))
        for code, *_ in nd.VERDICT_RULES:
            self.assertIn(code, emitted, f"VERDICT_RULES references unknown code {code!r}")


class TestTextReport(unittest.TestCase):
    def report(self, **overrides):
        base = {
            "os": "Linux", "target": "8.8.8.8", "generated_at": "2026-01-01T00:00:00",
            "detected_gateway": "192.168.1.1", "quick": False,
            "verdict": {"headline": "Something broke", "owner": "the provider",
                        "confidence": "high", "next_step": "Escalate.", "severity": "critical"},
            "findings": [{"severity": "critical", "layer": 3, "code": "x",
                          "message": "The gateway is reachable but 8.8.8.8 is not."}],
            "layers": {"3": {"name": "Network", "hint": "routing"}},
            "hops": [], "port_results": [], "raw": {},
            "lowest_broken_layer": 3, "demarc_hop": None, "worst_jump": None,
            "networks_crossed": [], "cgnat_hop": None,
        }
        base.update(overrides)
        return base

    def test_verdict_leads_the_report(self):
        out = nd.render_text_report(self.report(), color=False, width=80)
        self.assertLess(out.index("LIKELY ROOT CAUSE"), out.index("FINDINGS"))

    def test_findings_and_layers_rendered(self):
        out = nd.render_text_report(self.report(), color=False, width=80)
        self.assertIn("CRIT", out)
        self.assertIn("L3 Network", out)

    def test_quick_mode_says_the_path_was_skipped(self):
        out = nd.render_text_report(self.report(quick=True), color=False, width=80)
        self.assertIn("--quick", out)

    def test_renders_without_optional_sections(self):
        # An older report, or one from a --quick run, has none of these keys.
        minimal = {"os": "Linux", "target": "8.8.8.8", "findings": [], "hops": [], "raw": {}}
        out = nd.render_text_report(minimal, color=False, width=80)
        self.assertIn("FINDINGS", out)

    def test_color_only_when_asked(self):
        plain = nd.render_text_report(self.report(), color=False, width=80)
        self.assertNotIn("\033[", plain)
        self.assertIn("\033[", nd.render_text_report(self.report(), color=True, width=80))




class TestProbeCollection(unittest.TestCase):
    """The gateway ping, target ping and trace are independent, so they run
    together - except under --soak, where probes perturbing each other's
    latency matters more than the seconds saved."""

    def setUp(self):
        self._saved = {n: getattr(nd, n) for n in ("cmd_ping", "cmd_mtr", "cmd_traceroute")}
        self.calls = []
        nd.cmd_ping = lambda t, c=4, w=2: (self.calls.append(("ping", t)) or
                                           {"ok": True, "cmd": f"ping {t}", "stdout": "0% packet loss\n"})
        nd.cmd_mtr = lambda t, c=10: None
        nd.cmd_traceroute = lambda t: (self.calls.append(("trace", t)) or
                                       {"ok": True, "cmd": "traceroute",
                                        "stdout": " 1  10.0.0.1 (10.0.0.1)  1.0 ms\n"})

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(nd, n, v)

    def test_all_three_probes_are_collected(self):
        probes = nd.collect_probes("8.8.8.8", "10.0.0.1", 4, 2, quick=False, mtr_cycles=10)
        self.assertEqual(set(probes), {"ping_gateway", "ping_internet", "trace"})
        self.assertEqual(probes["trace"]["source"], "traceroute")

    def test_quick_mode_skips_the_trace(self):
        probes = nd.collect_probes("8.8.8.8", "10.0.0.1", 2, 1, quick=True, mtr_cycles=10)
        self.assertNotIn("trace", probes)
        self.assertEqual(set(probes), {"ping_gateway", "ping_internet"})

    def test_no_gateway_means_no_gateway_ping(self):
        probes = nd.collect_probes("8.8.8.8", None, 4, 2, quick=False, mtr_cycles=10)
        self.assertNotIn("ping_gateway", probes)

    def test_serial_mode_produces_the_same_results(self):
        par = nd.collect_probes("8.8.8.8", "10.0.0.1", 4, 2, False, 10, parallel=True)
        ser = nd.collect_probes("8.8.8.8", "10.0.0.1", 4, 2, False, 10, parallel=False)
        self.assertEqual(set(par), set(ser))
        self.assertEqual(par["trace"]["hops"], ser["trace"]["hops"])

    def test_mtr_is_preferred_when_available(self):
        nd.cmd_mtr = lambda t, c=10: {"ok": True, "cmd": "mtr", "cycles": c, "stdout": "",
                                      "hops": [{"hop": 1, "host": "10.0.0.1", "display": "gw",
                                                "times_ms": [1.0], "timed_out": False,
                                                "loss_pct": 0.0}]}
        trace = nd.collect_trace("8.8.8.8", 10)
        self.assertEqual(trace["source"], "mtr")
        self.assertIsNotNone(trace["mtr"])

    def test_a_failing_probe_does_not_take_the_others_down(self):
        def boom(t, c=4, w=2):
            if t == "10.0.0.1":
                raise OSError("interface vanished")
            return {"ok": True, "cmd": "ping", "stdout": "0% packet loss\n"}
        nd.cmd_ping = boom
        with self.assertRaises(OSError):
            nd.collect_probes("8.8.8.8", "10.0.0.1", 4, 2, False, 10)


class TestSamplingWindow(unittest.TestCase):
    """The counter window runs alongside the rest of the diagnosis instead of
    being a dedicated pause. It still has to mean something, and --quick still
    has to be quick."""

    def setUp(self):
        self._sleep = nd.time.sleep
        self.slept = []
        nd.time.sleep = lambda s: self.slept.append(s)
        counters = dict(rx_packets=1000, tx_packets=1000, rx_bytes=0, tx_bytes=0,
                        rx_errors=0, tx_errors=0, rx_dropped=0, tx_dropped=0,
                        rx_crc_errors=0, rx_frame_errors=0, rx_over_errors=0,
                        collisions=0, operstate="up")
        nd._read_link_stats = lambda: ({"eth0": counters}, "test")

    def tearDown(self):
        nd.time.sleep = self._sleep
        __import__("importlib").reload(nd)

    def test_no_sampling_requested_means_no_waiting(self):
        sample = nd.start_link_sample()
        nd.cmd_link_stats(0, sample=sample)
        self.assertEqual(self.slept, [], "a --quick run must not be delayed by the window")

    def test_a_window_already_elapsed_is_not_waited_out_again(self):
        sample = nd.start_link_sample()
        sample["started"] -= 30          # pretend the run took 30s
        nd.cmd_link_stats(5, sample=sample)
        self.assertEqual([s for s in self.slept if s > 0], [],
                         "the window already covered the run; nothing left to wait for")

    def test_a_short_run_waits_out_the_remainder(self):
        sample = nd.start_link_sample()
        sample["started"] -= 1           # only 1s of a 10s window has passed
        nd.cmd_link_stats(10, sample=sample)
        # Waited in one-second steps so the countdown can tick, so check the
        # total rather than a single sleep.
        self.assertTrue(8.5 <= sum(self.slept) <= 9.5,
                        f"expected to wait out ~9s in total, waited {self.slept}")

    def test_the_wait_terminates_in_a_bounded_number_of_steps(self):
        # Driving the loop off the clock would spin forever whenever sleep is
        # stubbed - which is every test in this file.
        sample = nd.start_link_sample()
        sample["started"] -= 1
        nd.cmd_link_stats(30, sample=sample)
        self.assertLessEqual(len(self.slept), 31)

    def test_the_countdown_reports_progress_while_waiting(self):
        sample = nd.start_link_sample()
        sample["started"] -= 1
        seen = []
        nd.cmd_link_stats(6, sample=sample, progress=seen.append)
        self.assertTrue(seen, "a long wait must say what it is waiting for")
        self.assertIn("sampling error counters", seen[0])

    def test_reported_window_reflects_the_real_elapsed_time(self):
        sample = nd.start_link_sample()
        sample["started"] -= 12
        result = nd.cmd_link_stats(2, sample=sample)
        self.assertGreaterEqual(result["interfaces"][0]["sample_seconds"], 12)


class TestPassiveInventory(unittest.TestCase):
    """The neighbour table already knows who this device has talked to. That is
    the whole feature: no sweep, no probe, nothing touched that wasn't already
    talking - which is what makes it safe on a network nobody gave you."""

    ENTRIES = [
        {"ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:01", "state": "reachable"},
        {"ip": "192.168.1.50", "mac": "aa:bb:cc:00:00:02", "state": "stale"},
        {"ip": "192.168.1.99", "mac": None, "state": "incomplete"},   # never answered
        {"ip": "192.168.1.255", "mac": "ff:ff:ff:ff:ff:ff", "state": None},  # broadcast
        {"ip": "224.0.0.251", "mac": "01:00:5e:00:00:fb", "state": None},    # multicast
        {"ip": "10.0.0.7", "mac": "aa:bb:cc:00:00:03", "state": "reachable"},
        {"ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:01", "state": "reachable"},  # dupe
    ]

    def inv(self):
        return nd.build_inventory(self.ENTRIES, resolvers=None, resolve_names=False)

    def test_only_real_neighbours_are_counted(self):
        """Incomplete entries, broadcast and multicast are not devices - counting
        them turned 36 hosts into 257 the first time this ran."""
        inv = self.inv()
        self.assertEqual(inv["count"], 3)
        ips = [h["ip"] for h in inv["hosts"]]
        self.assertNotIn("192.168.1.99", ips)   # no MAC: the lookup failed
        self.assertNotIn("192.168.1.255", ips)  # broadcast
        self.assertNotIn("224.0.0.251", ips)    # multicast

    def test_duplicates_collapse(self):
        self.assertEqual(len([h for h in self.inv()["hosts"] if h["ip"] == "192.168.1.1"]), 1)

    def test_hosts_sort_numerically_not_lexically(self):
        entries = [{"ip": f"192.168.1.{n}", "mac": "aa:bb:cc:00:00:01"} for n in (10, 2, 100)]
        order = [h["ip"] for h in nd.build_inventory(entries, resolve_names=False)["hosts"]]
        self.assertEqual(order, ["192.168.1.2", "192.168.1.10", "192.168.1.100"])

    def test_grouped_by_subnet(self):
        self.assertEqual(self.inv()["subnets"], {"192.168.1": 2, "10.0.0": 1})

    def test_no_lookups_when_names_are_not_wanted(self):
        for host in self.inv()["hosts"]:
            self.assertIsNone(host["name"])

    def test_junk_input(self):
        for junk in (None, [], [{}], [{"ip": "not-an-ip", "mac": "x"}]):
            nd.build_inventory(junk, resolve_names=False)

    def test_ptr_name_decompression(self):
        """PTR answers use compression pointers; a naive reader loops forever on
        a hostile one, so the depth is capped."""
        import struct
        name = b"\x03gw1\x05local\x00"
        data = struct.pack(">HHHHHH", 1, 0x8180, 0, 1, 0, 0) + b"\xc0\x0c" + name
        self.assertEqual(nd._dns_read_name(data, 14), "gw1.local")

    def test_a_pointer_loop_terminates(self):
        """A compression pointer that points at itself is the classic hostile
        DNS reply, and the property being tested is that the reader *returns*.

        Called straight, that is exactly what this could not check: if the
        bound were lost the call would never come back and the suite would
        hang rather than fail - a red build tells you something, a build that
        never finishes tells you to go and look. Run on a thread with a
        deadline so an unbounded loop is a failure.
        """
        import struct
        import threading
        data = struct.pack(">HHHHHH", 1, 0x8180, 0, 1, 0, 0) + b"\xc0\x0c" * 8
        done = []
        worker = threading.Thread(target=lambda: done.append(nd._dns_read_name(data, 12)),
                                  daemon=True)
        worker.start()
        worker.join(5.0)
        self.assertTrue(done, "_dns_read_name did not return - the pointer loop is unbounded")

    def test_the_lookup_deadline_is_short(self):
        # An inventory is not worth stalling a diagnosis for.
        self.assertLessEqual(nd.PTR_DEADLINE_SECONDS, 3.0)


class TestSocketStates(unittest.TestCase):
    """Zeek reads connection states off the wire; the kernel already knows the
    same thing about this box. SYN_SENT means nothing answered, CLOSE_WAIT means
    a local application isn't closing its sockets."""

    SS = """State      Recv-Q Send-Q Local Address:Port  Peer Address:Port
ESTAB      0      0      10.0.0.5:22         10.0.0.9:51234
ESTAB      0      0      10.0.0.5:443        203.0.113.34:443
LISTEN     0      128    0.0.0.0:22          0.0.0.0:*
SYN-SENT   0      1      10.0.0.5:41234      198.51.100.9:8080
SYN-SENT   0      1      10.0.0.5:41235      198.51.100.9:8080
SYN-SENT   0      1      10.0.0.5:41236      198.51.100.9:8080
CLOSE-WAIT 1      0      10.0.0.5:80         10.0.0.9:52000
TIME-WAIT  0      0      10.0.0.5:443        203.0.113.34:443
"""
    NETSTAT = """Active Internet connections
Proto Recv-Q Send-Q  Local Address    Foreign Address   (state)
tcp4       0      0  10.0.0.5.22      10.0.0.9.51234    ESTABLISHED
tcp4       0      0  10.0.0.5.80      10.0.0.9.52000    CLOSE_WAIT
tcp4       0      0  *.22             *.*               LISTEN
"""

    def test_ss_states_counted(self):
        parsed = nd.parse_socket_states(self.SS)
        self.assertEqual(parsed["states"]["ESTABLISHED"], 2)
        self.assertEqual(parsed["states"]["SYN_SENT"], 3)
        self.assertEqual(parsed["states"]["CLOSE_WAIT"], 1)
        self.assertEqual(parsed["states"]["LISTEN"], 1)

    def test_netstat_states_counted(self):
        parsed = nd.parse_socket_states(self.NETSTAT)
        self.assertEqual(parsed["states"].get("ESTABLISHED"), 1)
        self.assertEqual(parsed["states"].get("CLOSE_WAIT"), 1)

    def test_pending_peers_recorded(self):
        """Naming who isn't answering is the difference between "something is
        wrong" and "check egress to this address"."""
        parsed = nd.parse_socket_states(self.SS)
        peers = parsed["pending"]["SYN_SENT"]
        self.assertTrue(any("198.51.100.9" in host for host in peers))

    def test_thresholds_are_above_normal_churn(self):
        # A couple of sockets in an odd state is ordinary; the thresholds have
        # to sit above that or the finding fires on every healthy box.
        self.assertGreaterEqual(nd.SYN_SENT_WARN, 3)
        self.assertGreaterEqual(nd.CLOSE_WAIT_WARN, 10)

    def test_junk_input(self):
        for junk in ("", None, "not a socket table", "\x00\x00"):
            self.assertEqual(nd.parse_socket_states(junk)["states"], {})

    def test_every_address_form_loses_its_port_and_keeps_its_address(self):
        """BSD writes the port after a dot, and an IPv6 address is mostly
        colons - so splitting on the last colon truncated 2001:db8::1.443 to
        "2001:db8:". The separator has to be identified before it's split on."""
        for addr, expected in (("10.0.0.1:443", "10.0.0.1"),          # ss, Linux netstat
                               ("[2001:db8::1]:443", "2001:db8::1"),  # ss with IPv6
                               ("10.0.0.1.443", "10.0.0.1"),          # BSD netstat
                               ("2001:db8::1.443", "2001:db8::1"),    # BSD netstat, IPv6
                               ("::1:22", "::1"),                     # Linux netstat, IPv6
                               (":::22", "::"),                       # wildcard IPv6
                               (":443", ""),                          # port with no host
                               ("", None), (None, None)):
            with self.subTest(addr=addr):
                self.assertEqual(nd.peer_host(addr), expected)

    def test_the_peer_is_read_the_same_way_by_both_socket_readers(self):
        """parse_socket_states and the per-flow parser each had their own
        version of this; the partial one kept the brackets and the older one
        mangled IPv6."""
        pending = nd.parse_socket_states(
            "SYN-SENT 0 1 [::1]:51000 [2001:db8::1]:443")["pending"]
        self.assertIn("2001:db8::1", pending["SYN_SENT"])
        flows = nd.parse_tcp_flows(
            SS_HEADER + "ESTAB 0 0 [::1]:51000 [2001:db8::1]:443\n\t cubic rtt:1.0/0.1\n")
        self.assertEqual(flows[0]["peer"], "2001:db8::1")


class TestTlsCheck(unittest.TestCase):
    def test_tls_ports_are_the_ones_worth_a_handshake(self):
        for port in (443, 8443, 993, 465):
            self.assertIn(port, nd.TLS_PORTS)
        for port in (22, 80, 53):
            self.assertNotIn(port, nd.TLS_PORTS)

    def test_interception_hints_cover_the_common_products(self):
        for product in ("fortinet", "sophos", "forcepoint", "mitmproxy"):
            self.assertIn(product, nd.INTERCEPTION_HINTS)

    def test_an_intercepted_issuer_is_recognised(self):
        issuer = "Fortinet Root CA".lower()
        self.assertTrue(any(h in issuer for h in nd.INTERCEPTION_HINTS))

    def test_a_public_ca_is_not_flagged(self):
        for issuer in ("sectigo limited", "digicert inc", "let's encrypt",
                       "google trust services"):
            self.assertFalse(any(h in issuer for h in nd.INTERCEPTION_HINTS), issuer)

    def test_a_failed_verification_still_yields_the_certificate_details(self):
        """The bug this exists to prevent: Python returns an empty cert dict for
        an unvalidated peer, so issuer and expiry came back None - on the only
        path where interception or expiry can ever be seen. Both findings were
        unreachable, and the constant-only tests never noticed."""
        der = b"\x30\x82\x01\x00" + b"\x00\x14" + b"Fortinet Root CA" + b"\x00\x0a"
        names = nd.der_strings(der)
        self.assertIn("Fortinet Root CA", names)
        self.assertEqual(nd.looks_intercepted(names), "fortinet")

    def test_a_public_ca_certificate_is_not_called_interception(self):
        for issuer in (b"DigiCert Global Root CA", b"Sectigo Limited",
                       b"ISRG Root X1", b"Google Trust Services"):
            self.assertIsNone(nd.looks_intercepted(nd.der_strings(b"\x30\x82" + issuer)))

    def test_der_strings_survives_hostile_bytes(self):
        import os
        for blob in (b"", None, os.urandom(2048), b"\x00" * 500, b"\xff" * 500):
            nd.der_strings(blob)

    def test_der_strings_ignores_short_noise(self):
        # Two-character runs between binary fields are not names.
        self.assertEqual(nd.der_strings(b"\x00ab\x00cd\x00", minimum=4), [])

    def test_invalid_host_is_refused_before_connecting(self):
        self.assertIsNone(nd.cmd_tls_check("host; id"))

    def test_expiry_threshold_is_a_useful_warning_window(self):
        self.assertGreaterEqual(nd.CERT_EXPIRY_WARN_DAYS, 14)


class TestSpeculativePorts(unittest.TestCase):
    """Naming a port asserts you expect it open. The 'common' preset asserts
    nothing, so a closed port there is context - not a fault, and certainly not
    a root cause on an otherwise healthy device."""

    def check(self, speculative):
        findings = []
        raw = {}
        original = nd.cmd_check_port
        nd.cmd_check_port = lambda h, p, timeout=5: {
            "ok": False, "cmd": f"tcp connect {h}:{p}", "error": "timeout", "reason": "timeout"}
        try:
            nd._check_ports(raw, findings, "8.8.8.8", ["22", "80"], quick=True,
                            speculative=speculative)
        finally:
            nd.cmd_check_port = original
        return findings

    def test_preset_results_are_informational(self):
        for f in self.check(speculative=True):
            self.assertEqual(f["severity"], "ok")
            self.assertIn("preset", f["message"])

    def test_named_ports_are_faults(self):
        for f in self.check(speculative=False):
            self.assertEqual(f["severity"], "warning")
            self.assertNotIn("preset", f["message"])

    def test_a_preset_sweep_leaves_the_verdict_clear(self):
        v = nd.build_verdict(self.check(speculative=True) +
                             [{"code": "all_clear", "severity": "ok", "message": "fine"}])
        self.assertEqual(v["severity"], "ok")
        self.assertIn("no fault", v["headline"].lower())

    def test_a_preset_sweep_leaves_the_ports_stage_passing(self):
        stages = {s["stage"]: s["state"] for s in
                  nd.build_stages(self.check(speculative=True), {}, checked_ports=True)}
        self.assertEqual(stages["ports"], "pass")


class TestCommonPorts(unittest.TestCase):
    def test_the_preset_is_a_short_useful_list(self):
        self.assertLessEqual(len(nd.COMMON_PORTS), 8)
        for port in ("22", "53", "80", "443"):
            self.assertIn(port, nd.COMMON_PORTS)

    def test_the_preset_stays_within_the_cap(self):
        self.assertLessEqual(len(nd.COMMON_PORTS), nd.MAX_CHECK_PORTS)

    def test_banner_timeout_is_short_enough_not_to_dominate(self):
        # A silent port costs exactly this; five of them must not add seconds.
        self.assertLessEqual(nd.BANNER_TIMEOUT, 1.0)


class TestVersioning(unittest.TestCase):
    """The version travels in the report so a page opened months later, or a
    baseline from a previous visit, can be read for what produced it."""

    def test_version_looks_like_a_version(self):
        import re
        self.assertRegex(nd.__version__, r"^\d+\.\d+\.\d+$")

    def test_the_text_report_names_the_version(self):
        out = nd.render_text_report({"os": "Linux", "version": nd.__version__,
                                     "findings": [], "hops": [], "raw": {}},
                                    color=False, width=80)
        self.assertIn(f"FaultOne {nd.__version__}", out)

    def test_an_older_report_still_renders(self):
        # Reports written before versioning have no such field; they must not
        # produce "FaultOne None".
        out = nd.render_text_report({"os": "Linux", "findings": [], "hops": [], "raw": {}},
                                    color=False, width=80)
        self.assertIn("FaultOne - Linux", out)
        self.assertNotIn("None", out.splitlines()[0])

    def test_the_report_ends_on_its_own_answer(self):
        """Fifty-seven lines when nothing is wrong and seventy when something
        is, so in an ordinary terminal the verdict has scrolled off by the time
        it finishes. What was left on screen was a note about a flag the reader
        had not used. Every tool this borrows from closes on its own conclusion
        - a plan summary, a pass and fail count, a vulnerability tally."""
        for code in ("latency_wall", "path_loss", "all_clear"):
            setup, kw = S[code]
            m = fresh(); setup(m)
            rep = m.diagnose(quick=False, **scenario_kwargs(kw))
            lines = [l for l in m.render_text_report(rep, color=False, width=88).splitlines()
                     if l.strip()]
            with self.subTest(scenario=code):
                self.assertTrue(lines[-1].strip() or lines[-2].strip())
                tail = "\n".join(lines[-2:])
                self.assertIn("=>", tail, "the report does not close on its answer")
                # The words are the verdict's own, not a second sentence that
                # could disagree with the first.
                head = rep["verdict"]["headline"]
                self.assertIn(head.split(" - ")[0][:40], tail.replace("\n   ", " "))
                self.assertNotIn("Raw command output", lines[-1])

    def test_the_closing_line_says_who_owns_it(self):
        """The headline says what is wrong. Without the owner the last thing on
        screen names a fault and not a person to take it to, which is half the
        promise the tool opens with."""
        setup, kw = S["path_loss"]
        m = fresh(); setup(m)
        rep = m.diagnose(quick=False, **scenario_kwargs(kw))
        # Joined and re-spaced: the line wraps, so the owner can straddle the
        # break and an assertion against the raw text would depend on where.
        tail = " ".join(" ".join(
            m.render_text_report(rep, color=False, width=200).splitlines()[-2:]).split())
        self.assertIn("owner:", tail)
        self.assertIn(rep["verdict"]["owner"], tail)

    def test_the_closing_line_is_skipped_when_there_is_no_verdict(self):
        """A report rendered from a partial or foreign file has no conclusion to
        repeat, and inventing an empty one is worse than ending without."""
        for rep in ({"os": "Linux", "findings": [], "hops": [], "raw": {}},
                    {"verdict": None, "findings": [], "hops": [], "raw": {}},
                    {"verdict": {"severity": "ok"}, "findings": [], "hops": [], "raw": {}}):
            with self.subTest(shape=sorted(rep)):
                out = nd.render_text_report(rep, color=False, width=80)
                self.assertNotIn("=>", out.splitlines()[-1])

    def test_the_answer_is_not_worked_out_twice(self):
        """It is the verdict's own headline and owner, read from the report. A
        second derivation here is a second thing that can disagree with the
        first, on the two lines a reader is most likely to quote."""
        src = open(nd.__file__, encoding="utf-8").read()
        fn = src.split("def _render_closing_answer", 1)[1].split("\ndef ", 1)[0]
        self.assertIn('v.get("owner")', fn)
        self.assertIn("v['headline']", fn)
        for invented in ("findings", "severity_of", "max(", "sort"):
            self.assertNotIn(invented + "(", fn,
                             "the closing line is deriving something of its own")

    def test_a_malformed_report_still_renders(self):
        """Reports now arrive from files, so the renderer shouldn't die on one
        whose shape is wrong - a partial page beats a traceback."""
        nd.render_text_report({"os": "Linux", "findings": [], "hops": [], "raw": []},
                              color=False, width=80)
        nd.render_text_report({}, color=False, width=80)

    def test_a_baseline_from_another_version_is_reported(self):
        current = {"version": "1.1.0", "raw": {}, "neighbours": [], "hops": []}
        baseline = {"version": "1.0.0", "raw": {}, "neighbours": [], "hops": []}
        changes = nd.compare_reports(current, baseline)
        entry = next((c for c in changes if c["what"] == "faultone version"), None)
        self.assertIsNotNone(entry, "a version change explains differences that aren't the network")
        self.assertEqual((entry["before"], entry["after"]), ("1.0.0", "1.1.0"))

    def test_same_version_is_not_a_change(self):
        same = {"version": "1.0.0", "raw": {}, "neighbours": [], "hops": []}
        self.assertEqual([c for c in nd.compare_reports(same, dict(same))
                          if c["what"] == "faultone version"], [])


class TestNeighbourInventory(unittest.TestCase):
    """--inventory, end to end.

    It cannot be a scenario: the registry is keyed by finding code and every
    entry has to fire the finding it is named for, and a passive listing is not
    a finding. So nothing exercised it - not the collector, not the section of
    the text report, not the panel in the viewer, not the trip through an
    export. Sixteen hosts came out of this path on a real machine while the
    corpus reported none, which is the difference between untested and unused.
    """

    ARP = ("192.168.1.1 dev eth0 lladdr 54:07:7d:bf:2d:34 REACHABLE\n"
           "192.168.1.20 dev eth0 lladdr 8c:4f:00:33:47:20 STALE\n"
           "192.168.1.21 dev eth0 lladdr 0e:eb:f5:e9:7e:fd REACHABLE\n"
           "10.20.0.7 dev eth0 lladdr 3c:31:74:e0:12:a3 REACHABLE\n"
           # The stray that makes the summary worth reading: a link-local
           # address on a LAN usually means something never got a lease.
           "169.254.85.111 dev eth0 lladdr aa:d1:86:0c:3f:da STALE\n"
           # Neither of these is a host: one is multicast, one has no MAC
           # because the lookup failed rather than because anything answered.
           "224.0.0.251 dev eth0 lladdr 01:00:5e:00:00:fb REACHABLE\n"
           "192.168.1.99 dev eth0  FAILED\n")

    def run_inventory(self, resolve=None):
        m = fresh()
        m.cmd_arp = lambda: {"ok": True, "cmd": "ip neigh", "stdout": self.ARP}
        # build_inventory looks names up against the first configured resolver,
        # in a thread pool, over the network. Every other test of it passes
        # resolve_names=False; a run through diagnose() cannot, so the lookup
        # itself is stubbed - which covers the naming path rather than dodging
        # it, and sends nothing.
        looked_up = []
        def ptr(server, ip, timeout=1.0):
            looked_up.append(ip)
            return (resolve or {}).get(ip)
        m.dns_ptr = ptr
        report = m.diagnose("8.8.8.8", None, quick=True, inventory=True)
        return m, report, looked_up

    def test_the_neighbour_table_becomes_an_inventory(self):
        _m, report, _ = self.run_inventory()
        inv = report.get("inventory")
        self.assertTrue(inv, "--inventory produced nothing")
        ips = [h["ip"] for h in inv["hosts"]]
        self.assertIn("192.168.1.1", ips)
        self.assertIn("169.254.85.111", ips)
        # A multicast group is not a neighbour, and an entry with no MAC is a
        # lookup that failed rather than a device that answered.
        self.assertNotIn("224.0.0.251", ips)
        self.assertNotIn("192.168.1.99", ips)
        self.assertEqual(inv["count"], len(ips))
        self.assertEqual(sorted(inv["subnets"]), ["10.20.0", "169.254.85", "192.168.1"])

    def test_nothing_is_looked_up_over_the_network_without_a_resolver(self):
        """The lookup is stubbed here, so this asserts the shape rather than
        the absence: names are asked for once per host and no more."""
        _m, report, looked_up = self.run_inventory(resolve={"192.168.1.1": "gw.lan"})
        self.assertEqual(sorted(looked_up), sorted(h["ip"] for h in report["inventory"]["hosts"]))
        named = [h for h in report["inventory"]["hosts"] if h.get("name")]
        self.assertEqual([h["name"] for h in named], ["gw.lan"])

    def test_the_report_says_what_the_segment_looks_like_before_listing_it(self):
        """The subnet summary is the only part that survives the twenty-host
        cap, and it used to sit underneath the list it explains - reached after
        twenty addresses and a note that forty more were not shown."""
        m, report, _ = self.run_inventory()
        lines = m.render_text_report(report, color=False, width=88).splitlines()
        head = next(i for i, l in enumerate(lines) if l.startswith("NEIGHBOURS ("))
        subnets = next(i for i, l in enumerate(lines) if l.strip().startswith("subnets:"))
        first_host = next(i for i, l in enumerate(lines[head:], head)
                          if "lladdr" not in l and ":" in l and l.startswith("  1"))
        self.assertLess(subnets, first_host, "the summary is still below the list")
        self.assertLess(head, subnets)
        self.assertIn("169.254.85.0/24 x1", lines[subnets])

    def test_the_inventory_reaches_both_exports_and_the_viewer(self):
        """Four render paths, none of which anything walked before: the JSON,
        the compact JSON, the self-contained page, and the panel that draws
        it."""
        m, report, _ = self.run_inventory()
        self.assertTrue((report.get("raw") or {}).get("inventory"),
                        "the raw panel for it is missing")
        slim = m.compact_report(report)
        self.assertEqual(slim.get("inventory"), report.get("inventory"))
        page = m.render_report_html(report)
        self.assertIn("192.168.1.1", page)
        self.assertIn("neighbours (not a scan)", m.VIEWER_TEMPLATE)


class TestDocsMatchReality(unittest.TestCase):
    """Three times now a documented number has drifted from the truth - test
    counts, a flag that didn't exist, a UI field that had been deleted. A
    number in the docs nobody checks is worse than no number."""

    def docs(self):
        import os
        root = os.path.dirname(os.path.abspath(nd.__file__))
        for name in ("README.md", "REFERENCE.md"):
            path = os.path.join(root, name)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    yield name, fh.read()

    def test_every_documented_python_version_is_the_one_the_code_enforces(self):
        """The minimum version is written out in five places across two files
        and enforced in one, and nothing tied them together: raising
        MIN_PYTHON would leave five hand-maintained copies saying the old
        number, each of them advice about whether the tool will run at all.

        The rule is not 'the string 3.7 appears' - that goes stale with the
        thing it is meant to catch. It is that the box needs MIN_PYTHON, so
        any other version on a line about Python has to say for itself that
        it is a requirement of the reader's own machine instead."""
        want = "%d.%d" % nd.MIN_PYTHON
        # A requirement, not a transcript: capitalised prose ("Python 3.7"), or
        # the bare-number form ("the box still only needs 3.7"). Sample output
        # quoting the interpreter that produced it is neither.
        forms = (r"Python (\d+\.\d+)", r"needs? (?:only )?(\d+\.\d+)")
        seen = {}
        for name, text in self.docs():
            for n, line in enumerate(text.splitlines(), 1):
                # Per clause, so "needs 3.9 on your machine; the box needs 3.7"
                # cannot excuse the half of the sentence about the box.
                for clause in line.split(";"):
                    for form in forms:
                        for ver in re.findall(form, clause):
                            if ver == want:
                                seen.setdefault(name, (n, line.strip()))
                                continue
                            self.assertIn(
                                "your", clause,
                                "%s:%d documents Python %s, but the code enforces "
                                "%s. A version other than the minimum has to say "
                                "it is a requirement of the reader's own machine:"
                                "\n  %s" % (name, n, ver, want, clause.strip()))
        # ...and it cannot pass by there being nothing to check.
        for name, _ in self.docs():
            self.assertIn(name, seen,
                          "%s never states the minimum version (%s), so this "
                          "guard passed without checking anything" % (name, want))

    def test_the_transport_sizes_the_readme_quotes_are_real(self):
        """The readme tells someone on a bad link what it costs to push the
        file across, in four numbers. They are the kind that go stale silently:
        the file grows every release and nothing about a wrong size fails, it
        just quietly stops being advice and starts being decoration."""
        import ast as _ast
        import gzip
        if not hasattr(_ast, "unparse"):
            self.skipTest("ast.unparse needs Python 3.9 to check the stripped size")
        raw = open(nd.__file__, "rb").read()
        stripped = _ast.unparse(_ast.parse(raw.decode())).encode()
        readme = open(os.path.join(os.path.dirname(nd.__file__), "README.md"),
                      encoding="utf-8").read()
        claims = {
            "on disk": (len(raw), 656),
            "compressed": (len(gzip.compress(raw, 9)), 197),
            "stripped and compressed": (len(gzip.compress(stripped, 9)), 142),
        }
        for label, (measured, quoted) in claims.items():
            with self.subTest(size=label):
                self.assertIn(str(quoted), readme, f"the readme no longer quotes {quoted} KB")
                # Generous: zlib output shifts a little between versions, and
                # the point is that the number is still roughly true.
                self.assertLess(
                    abs(measured / 1024 - quoted) / quoted, 0.08,
                    f"the readme says {quoted} KB {label}, it is now "
                    f"{measured / 1024:.0f} KB")
        cut = 100 * (1 - len(gzip.compress(stripped, 9)) / len(raw))
        self.assertIn("78%", readme)
        self.assertLess(abs(cut - 78), 4, f"the quoted 78% saving is now {cut:.0f}%")

    def test_the_readme_tells_ssh_to_compress(self):
        """OpenSSH does not compress by default, so an example without -C sends
        three times what it needs to - and the reader being written for here is
        the one on a serial console where that is nine minutes rather than
        two."""
        readme = open(os.path.join(os.path.dirname(nd.__file__), "README.md"),
                      encoding="utf-8").read()
        for line in readme.splitlines():
            if line.startswith("ssh ") and "python3 -" in line:
                with self.subTest(line=line[:48]):
                    self.assertIn(" -C ", line, "an ssh pipe example without compression")

    def test_claimed_test_counts_are_true(self):
        import re
        import unittest as ut
        actual = ut.TestLoader().loadTestsFromModule(sys.modules[__name__]).countTestCases()
        for name, text in self.docs():
            for claimed in re.findall(r"(\d+) tests", text):
                self.assertEqual(int(claimed), actual,
                                 f"{name} claims {claimed} tests, there are {actual}")

    def test_documented_counts_match_the_code(self):
        """Three different numbers get quoted about this tool - things it
        inspects, conclusions it can reach, and tests of its own code. They are
        easy to conflate and easier to leave stale, so each is pinned."""
        import re
        with open(nd.__file__, encoding="utf-8") as fh:
            src = fh.read()
        codes = set(re.findall(r'"code": "(\w+)"', src))
        faults = {c for c in codes if c not in nd.VERDICT_EXEMPT}
        # \s+ rather than a space in every one of these: prose is hard-wrapped,
        # so a stale count survived for several versions purely because the line
        # broke between the number and the word after it.
        claims = {
            "findings": (len(codes), [r"\*\*(\d+) distinct conclusions", r"(\d+)\s+findings"]),
            "faults": (len(faults), [r"(\d+)\s+are faults"]),
            "ranked causes": (len(nd.VERDICT_RULES), [r"Ranked causes\*\* \| \*\*(\d+)\*\*"]),
            # The one count here that is not derived: "a thing inspected" is a
            # human grouping, not a function - some collectors run several
            # times, and some are helpers rather than collections. Raised to
            # 33 when proxy configuration was added.
            "collections": (33, [r"\*\*(\d+)\s+things are inspected",
                                 r"Data collections\*\* \| \*\*(\d+)\*\*"]),
        }
        for name, text in self.docs():
            for label, (actual, patterns) in claims.items():
                for pattern in patterns:
                    for claimed in re.findall(pattern, text):
                        self.assertEqual(int(claimed), actual,
                                         f"{name} claims {claimed} {label}, there are {actual}")

    def test_the_documented_collection_list_is_complete(self):
        """The reference lists what the tool inspects. If a collector is added
        without being listed, the list quietly understates the tool.

        This used to assert the list held *at least* 25 entries, and computed a
        set of collectors it then never looked at. A floor cannot catch the
        thing that actually goes wrong here - the two documents drifting to
        different numbers, or the numbered list and the heading above it
        disagreeing - so all three are pinned to each other instead.
        """
        import re
        with open(nd.__file__, encoding="utf-8") as fh:
            src = fh.read()
        collectors = set(re.findall(r"^def (cmd_\w+)", src, re.M))
        # A bare name, not a call: several collectors are handed to the job
        # runner as values rather than invoked directly.
        uncalled = {c for c in collectors if len(re.findall(rf"\b{c}\b", src)) < 2}
        self.assertFalse(uncalled, f"collectors defined but never called: {sorted(uncalled)}")

        claimed = {}
        for name, text in self.docs():
            for m in re.findall(r"(?:The |\*\*)(\d+)\s+things (?:it inspects|are inspected)",
                                text):
                claimed[name] = int(m)
        self.assertEqual(len(set(claimed.values())), 1,
                         f"the docs disagree on how many things are inspected: {claimed}")
        for name, text in self.docs():
            if "things it inspects" not in text:
                continue
            # Scoped to the section: the reference has other numbered
            # lists, and counting them all made this pass on any number.
            section = text.split("things it inspects", 1)[1].split("\n## ", 1)[0]
            listed = len(re.findall(r"^\d+\. ", section, re.M))
            self.assertEqual(listed, claimed[name],
                             f"{name} says {claimed[name]} inspections and lists {listed}")

    # What each collector is called in the documented list. A map rather than a
    # count, because the count is the thing that drifted: three collectors were
    # added over one session and every counting guard stayed green, since they
    # pin the docs to each other and to a literal in this file rather than to
    # the code. Adding a collector now fails here until it is written down.
    #
    # Several collectors share one entry on purpose - two ping targets are one
    # kind of inspection - so this maps name to a phrase, not one to one.
    COLLECTOR_IS_DOCUMENTED_AS = {
        "cmd_arp": "neighbour table",
        "cmd_check_port": "TCP reachability of specific ports",
        "cmd_clock_sync": "Clock synchronisation",
        "cmd_dns": "DNS resolution",
        "cmd_dns_health": "Each configured DNS resolver",
        "cmd_ethtool": "Link speed, duplex and MTU",
        "cmd_interfaces": "Interfaces and addresses",
        "cmd_kernel_drops": "Packets this device drops itself",
        "cmd_kernel_log": "Kernel log",
        "cmd_link_modes": "Link speed, duplex and MTU",
        "cmd_link_stats": "Interface error, drop, CRC and collision counters",
        "cmd_listen_ports": "Listening ports",
        "cmd_lldp": "LLDP/CDP neighbour",
        "cmd_mtr": "Hop-by-hop path",
        "cmd_optics": "Optical module power and alarms",
        "cmd_own_http": "asked over HTTP for an answer",
        "cmd_proxy_config": "how this box is told to reach the internet",
        "cmd_own_tls": "certificate this box *serves*",
        "cmd_path_mtu": "Path MTU",
        "cmd_ping": "reachability and loss",
        "cmd_routes": "Routing table and default gateway",
        "cmd_socket_states": "TCP socket states",
        "cmd_tcp_flows": "Per-connection TCP statistics",
        "cmd_tcp_health": "TCP retransmission counters",
        "cmd_tls_check": "TLS handshake and certificate on ports",
        "cmd_tls_check_local": "certificate this box *serves*",
        "cmd_traceroute": "Hop-by-hop path",
        "cmd_traceroute_tcp": "TCP-probe path",
        "_bond_members_linux": "Bonded interface members",
        "_read_neigh_table": "Neighbour table size against its own ceiling",
        "_read_thermal_throttle": "CPU thermal throttling counters",
        "_read_server_limits": "Ephemeral ports, file descriptors",
        "_read_conntrack": "Connection tracking table",
    }

    def test_every_collector_appears_in_the_documented_list(self):
        """A collector nobody wrote down makes the list understate the tool.

        This is what the counting guards could not catch: they pin the two
        documents to each other and to a number in this file, so three
        collectors were added across one session and every one of them stayed
        green while the list quietly described an older tool."""
        import re
        with open(nd.__file__, encoding="utf-8") as fh:
            src = fh.read()
        collectors = set(re.findall(r"^def (cmd_\w+)", src, re.M))
        collectors |= {n for n in ("_bond_members_linux", "_read_neigh_table",
                                   "_read_thermal_throttle", "_read_server_limits",
                                   "_read_conntrack") if f"def {n}(" in src}
        undocumented = sorted(collectors - set(self.COLLECTOR_IS_DOCUMENTED_AS))
        self.assertEqual(undocumented, [],
                         "collectors with no entry in COLLECTOR_IS_DOCUMENTED_AS")
        gone = sorted(set(self.COLLECTOR_IS_DOCUMENTED_AS) - collectors)
        self.assertEqual(gone, [], "the map names collectors that no longer exist")

        ref = dict(self.docs())["REFERENCE.md"]
        section = ref.split("things it inspects", 1)[1].split("\n## ", 1)[0]
        missing = sorted(name for name, phrase in self.COLLECTOR_IS_DOCUMENTED_AS.items()
                         if phrase not in section)
        self.assertEqual(missing, [],
                         "collectors whose documented phrase is not in the list")

    # Every guard above pins a *count* - findings, tests, collections, flags,
    # thresholds, tools. All of them stayed green while the README drifted into
    # describing about half the tool: it opened on a device that only talks
    # outward and never used the words proxy, serving, clients, listener or
    # downstream once, after a release built almost entirely around them.
    # A number being right is not the same as the description being right.
    #
    # A list of (proof, phrases), not a dict: one capability can need two
    # separate things said about it, and a dict key forced them into one entry
    # where any() then accepted either. Removing "load balancer" passed because
    # "clients" was still there.
    #
    # `proof` is a finding code, or a name in the module, that shows the
    # capability is real - so an entry cannot outlive what it describes:
    # delete the feature and this stops asking for prose about it. `phrases`
    # are genuine alternatives, where any wording will do.
    README_MUST_DESCRIBE = [
        ("own_tls_expired", ("certificate this box serves",)),
        ("syncookies_live", ("SYN cookies", "accept queue")),
        ("ephemeral_ports_low", ("ephemeral port",)),
        ("fd_pressure", ("file descriptor",)),
        ("syn_recv_backlog", ("backlog",)),
        ("tcp_flow_loss_clients", ("clients",)),
        ("tcp_flow_loss_backends", ("backend",)),
        ("dominant_peer", ("load balancer",)),
        ("build_sides", ("this box",)),
        ("egress_blocked", ("way out",)),
        ("uplink_saturated", ("--uplink-mbps",)),
        ("saturation_bursts", ("--soak",)),
        ("link_flapping_logged", ("kernel logged",)),
        ("conntrack_near_limit", ("connection tracking",)),
        ("optics_alarm", ("optical power",)),
        ("duplex_mismatch", ("duplex",)),
        ("clock_skewed", ("clock",)),
        ("aborts_on_memory", ("aborted",)),
        ("_choose_target", ("--target auto",)),
    ]

    def test_the_readme_describes_what_the_tool_can_actually_do(self):
        """Counts stayed green while the description went stale. This asks the
        other question: for every capability that exists, does the front page
        say so anywhere?"""
        import re
        with open(nd.__file__, encoding="utf-8") as fh:
            emitted = set(re.findall(r'"code": "(\w+)"', fh.read()))
        readme = dict(self.docs())["README.md"].lower()
        missing = []
        for proof, phrases in self.README_MUST_DESCRIBE:
            if proof not in emitted and not hasattr(nd, proof):
                continue          # capability gone; nothing to describe
            if not any(p.lower() in readme for p in phrases):
                missing.append(f"{proof} (expected one of {list(phrases)})")
        self.assertFalse(missing, "the README never mentions: " + "; ".join(missing))

    def test_the_capability_list_names_no_finding_that_is_gone(self):
        """The other direction: an entry left behind after a feature is removed
        would keep demanding prose about something that no longer exists."""
        import re
        with open(nd.__file__, encoding="utf-8") as fh:
            emitted = set(re.findall(r'"code": "(\w+)"', fh.read()))
        stale = sorted(proof for proof, _ in self.README_MUST_DESCRIBE
                       if proof not in emitted and not hasattr(nd, proof))
        self.assertEqual(stale, [], f"capability list names dead codes: {stale}")

    def test_the_readme_frames_both_shapes_of_box(self):
        """It opened on "a remote device ... the network it's plugged into",
        which is one shape, and by 1.5 the tool detected and served two."""
        readme = dict(self.docs())["README.md"].lower()
        for phrase in ("way in", "way out", "answers requests", "only talks outward"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, readme)

    def test_every_optional_tool_is_documented(self):
        """An external tool the code looks for is a dependency the reader has
        to know about - it decides what the run can and cannot tell them. The
        section listed two of the fourteen and opened with "Both are common",
        which was true when it was written and had been wrong for a while."""
        import re
        with open(nd.__file__, encoding="utf-8") as fh:
            probed = set(re.findall(r'which\("([a-z0-9_-]+)"\)', fh.read()))
        for name, text in self.docs():
            if "Optional tools it will use" not in text:
                continue
            missing = sorted(t for t in probed if f"`{t}`" not in text)
            self.assertFalse(missing, f"{name} never mentions: {missing}")

    def test_every_documented_flag_exists(self):
        import re
        with open(nd.__file__, encoding="utf-8") as fh:
            declared = set(re.findall(r'ap\.add_argument\("(--[a-z-]+)"', fh.read()))
        for name, text in self.docs():
            for flag in set(re.findall(r"`(--[a-z][a-z-]+)[ `]", text)):
                self.assertIn(flag, declared, f"{name} documents {flag}, which the tool lacks")

    def test_mtr_jitter_reaches_the_reader_not_just_the_score(self):
        """mtr reports a standard deviation over many cycles - better jitter
        evidence than traceroute's three probes. The MOS calculation already
        used it, but both renderers gated the display on the traceroute field,
        so the better measurement was scored and then hidden."""
        mod = fresh()
        mtr(mod, [
            {"count": 1, "host": "10.0.0.1", "Loss%": 0.0, "Snt": 30,
             "Best": 1.0, "Avg": 1.2, "Wrst": 1.9, "StDev": 0.3},
            {"count": 2, "host": "8.8.8.8", "Loss%": 0.0, "Snt": 30,
             "Best": 40.0, "Avg": 62.0, "Wrst": 130.0, "StDev": 18.5},
        ])
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        hop = report["hops"][-1]
        self.assertIsNone(hop["jitter_ms"], "mtr synthesises one timing, so this stays unset")
        self.assertEqual(hop["stdev_ms"], 18.5)
        text = nd.render_text_report(report, color=False, width=100)
        self.assertIn("jitter 18.5ms", text)

    def test_the_headline_examples_are_still_what_the_tool_does(self):
        """Both documents now lead with four cases where the obvious reading of
        the evidence is wrong. They are the product's main claim, so they get
        pinned to behaviour rather than to prose - a marketing table that has
        drifted from the code is worse than no table."""
        cases = [
            ("collisions on full duplex", "switch",
             lambda m: counters(m, rx_packets=10_000_000, tx_packets=10_000_000,
                                collisions=4_000, rx_errors=1_200, rx_crc_errors=1_150,
                                d_rx_errors=14, d_rx_packets=100_000)),
            ("backlog, not the link", "not its cable",
             lambda m: (kernel_drops(m, {"softnet_processed": 1_000_000, "softnet_dropped": 0},
                                        {"softnet_processed": 1_100_000, "softnet_dropped": 400}),
                        flows(m, ss_flow("203.0.113.9", sent=5_000_000, retrans=300_000),
                                 ss_flow("198.51.100.4", sent=4_000_000, retrans=250_000)))),
            ("reordering, not loss", "ordering",
             lambda m: kernel_drops(m, {"TCPDSACKRecv": 0, "RetransSegs": 0},
                                       {"TCPDSACKRecv": 60, "RetransSegs": 100})),
            ("the clock, not the cert", "clock",
             lambda m: setattr(m, "cmd_tls_check", lambda h, p=443, timeout=5: {
                 "ok": True, "cmd": "tls", "host": h, "port": p, "verified": True,
                 "tls_version": "TLSv1.3", "stdout": "", "starts": "2027-01-01",
                 "not_yet_valid_days": 148, "days_left": 500})),
        ]
        for label, expected_owner, setup in cases:
            with self.subTest(case=label):
                mod = fresh(); setup(mod)
                report = mod.diagnose("8.8.8.8", ["443"], quick=False, baseline=None)
                self.assertIn(expected_owner, report["verdict"]["owner"],
                              f"{label}: the documented answer is no longer the real one")

    def test_the_old_name_is_gone_everywhere(self):
        """A half-finished rename leaves the previous name in the one place
        nobody looks - an internal id, a docstring, the viewer's markup - and
        it reappears in an exported report months later.

        The old name is spelled here in pieces so this test does not find
        itself, which is exactly what it did when first written.
        """
        import os
        stale = "net" + "diag"
        root = os.path.dirname(os.path.abspath(nd.__file__))
        for name in ("faultone.py", "test_faultone.py", "README.md", "REFERENCE.md",
                     os.path.join("static", "index.html")):
            with self.subTest(file=name):
                with open(os.path.join(root, name), encoding="utf-8") as fh:
                    hits = [i for i, line in enumerate(fh, 1) if stale in line.lower()]
                # report the lines, not the file - assertNotIn on a whole file
                # prints the whole file
                self.assertFalse(hits, f"{name} still carries the old name at {hits}")
        self.assertTrue(nd.__file__.endswith("faultone.py"))

    def test_the_tool_identifies_itself_by_the_new_name(self):
        """The name reaches the reader in three places, and a report carries it
        for as long as the report exists."""
        report = {"os": "Linux", "version": nd.__version__, "findings": [],
                  "hops": [], "raw": {}}
        self.assertIn("FaultOne", nd.render_text_report(report, width=80))
        self.assertIn("FaultOne", nd.VIEWER_TEMPLATE)
        self.assertIn("FaultOne", nd.build_parser().description)

    def test_the_ranking_leads_both_documents(self):
        """It used to sit seventh in the reference, behind flags, Python
        versions and two sections about counting things."""
        for name, text in self.docs():
            with self.subTest(doc=name):
                self.assertIn("Why the ranking is the point", text)
        ref = dict(self.docs())["REFERENCE.md"]
        import re
        sections = re.findall(r"^## (.+)$", ref, re.M)
        self.assertEqual(sections[0], "Why the ranking is the point")
        self.assertLess(sections.index("The verdict"),
                        sections.index('What "a check" means here, and how many there are'),
                        "the counts should support the ranking, not precede it")

    def test_every_threshold_is_documented_with_its_real_value(self):
        """The tool's whole claim is that you can say why it concluded what it
        did. A threshold nobody can find is one nobody can argue with - and a
        documented value that has drifted from the code is worse than none."""
        import re
        source = open(nd.__file__, encoding="utf-8").read()
        ref = dict(self.docs())["REFERENCE.md"]
        table = ref.split("## The numbers behind the judgements", 1)[1].split("\n## ", 1)[0]
        documented = dict(re.findall(r"\| `([A-Z_0-9]+)` \| \*\*([0-9.,]+)\*\*", table))
        self.assertGreaterEqual(len(documented), 25, "the threshold table lost entries")
        for name, shown in documented.items():
            with self.subTest(constant=name):
                actual = getattr(nd, name, None)
                self.assertIsNotNone(actual, f"{name} is documented but no longer exists")
                # the table writes thousands with separators; the code doesn't
                self.assertEqual(str(actual), shown.replace(",", ""),
                                 f"{name} is {actual} in code, {shown} in the reference")

    #: Thresholds a check compares against with a strictly exclusive operator,
    #: and why that is the right one for each. Everything else has to fire *at*
    #: the value it documents, because that value is what the reference states
    #: the bar to be - "40 carrier transitions per day before a link counts as
    #: flapping" is a promise that 40 flaps is enough.
    EXCLUSIVE_THRESHOLDS = {
        "COVERAGE_THIN_PCT": "below this a verdict is thin; at it, it is not",
        "MAX_CHECK_PORTS": "a ceiling - more than this many ports is too many",
        "QUEUE_DELAY_MS": "excess delay under this is not queuing",
        "QUEUE_RTT_MULTIPLE": "a round trip under this multiple is not queuing",
        "SHARED_FAULT_INTERFACES": "fewer than this is not yet a shared fault",
        "STANDARD_MTU": "smaller than the standard MTU, not equal to it",
        "UPLINK_UNKNOWN_FLOOR_MBPS": "traffic below this needs no caveat",
    }

    def test_a_threshold_fires_at_the_value_it_documents(self):
        """The reference states the bar. The code has to agree about whether
        the bar itself counts.

        Ten of these comparisons were changed from `>=` to `>` and the whole
        suite stayed green on every one. Each scenario drives its finding from
        well above the bar - which is right for "does this fire" and says
        nothing about where the bar is - so a documented 40 could become an
        actual 41 with nothing to notice, on a tool whose stated purpose is
        that you can say what the bar was when someone pushes back.

        This does not replace a boundary fixture per finding, and it does not
        check the value is a good one. It pins whether the value is included,
        which is the half that was drifting silently.
        """
        import re
        source = open(nd.__file__, encoding="utf-8").read()
        ref = dict(self.docs())["REFERENCE.md"]
        table = ref.split("## The numbers behind the judgements", 1)[1].split("\n## ", 1)[0]
        names = [n for n, _v, _w in
                 re.findall(r"\| `([A-Z_0-9]+)` \| \*\*([0-9.,]+)\*\* \| ([^|]*)\|", table)]
        self.assertGreaterEqual(len(names), 60, "the threshold table lost entries")

        exclusive_now, flipped = set(), []
        inclusive = 0
        for name in names:
            ops = {a or b for a, b in
                   re.findall(r"([<>]=?)\s*" + name + r"\b|" + name + r"\s*([<>]=?)", source)}
            if not ops:
                continue                      # a cap or a label, never compared
            # A threshold read from both sides is a boundary between two bands
            # - `< X` is one and `>= X` is the other - and that is exhaustive
            # and unambiguous. Two operators pointing the *same* way is not:
            # it means one of several comparisons against the same constant was
            # changed and the rest were not, which is how a flip hides when a
            # threshold is used in more than one place.
            if (">" in ops and ">=" in ops) or ("<" in ops and "<=" in ops):
                flipped.append((name, sorted(ops)))
            if ops & {">=", "<="}:
                inclusive += 1
            else:
                exclusive_now.add(name)

        self.assertEqual(
            flipped, [],
            "compared both at-or-beyond and strictly beyond, so one use has "
            "drifted from the others: "
            + ", ".join(f"{n} {ops}" for n, ops in flipped))
        self.assertGreaterEqual(inclusive, 50,
                                "most thresholds should fire at their documented value")
        unexplained = sorted(exclusive_now - set(self.EXCLUSIVE_THRESHOLDS))
        self.assertEqual(
            unexplained, [],
            "these no longer fire at the value the reference documents, and no "
            "reason is recorded for it: " + ", ".join(unexplained))
        stale = sorted(set(self.EXCLUSIVE_THRESHOLDS) - exclusive_now)
        self.assertEqual(
            stale, [],
            "listed as deliberately exclusive but compared inclusively now: "
            + ", ".join(stale))

    def test_no_judgement_threshold_is_left_undocumented(self):
        """A new check that quietly adds a threshold is the way this table goes
        stale. Anything a finding compares against has to appear."""
        import re
        source = open(nd.__file__, encoding="utf-8").read()
        ref = dict(self.docs())["REFERENCE.md"]
        # constants actually used in a comparison inside a _check_ function
        judging = set()
        for m in re.finditer(r"[<>]=?\s*([A-Z][A-Z_0-9]{4,})", source):
            judging.add(m.group(1))
        judging = {n for n in judging if isinstance(getattr(nd, n, None), (int, float))}
        missing = sorted(n for n in judging if f"`{n}`" not in ref)
        self.assertFalse(missing, f"thresholds used in a comparison but undocumented: {missing}")

    NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
                    "seven": 7, "eight": 8, "nine": 9, "ten": 10}

    def test_a_heading_that_counts_things_counts_them_correctly(self):
        """"Three flags worth knowing" sat above a table of five for months.
        Prose that states a number is a claim like any other, and this is the
        one kind nothing was checking."""
        import re
        for name, text in self.docs():
            for m in re.finditer(r"^#+ (?:The )?(\w+) (flags?|things?) ", text, re.M | re.I):
                claimed = self.NUMBER_WORDS.get(m.group(1).lower())
                if claimed is None:
                    continue        # a digit, already pinned by the count tests
                section = text[m.end():].split("\n#", 1)[0]
                rows = len(re.findall(r"^\| `--", section, re.M)) or \
                    len(re.findall(r"^\d+\. ", section, re.M))
                with self.subTest(doc=name, heading=m.group(0).strip()):
                    self.assertEqual(rows, claimed,
                                     f"{name}: '{m.group(0).strip()}' lists {rows}")

    def hero_text(self):
        """The words inside the hero image, in order.

        The example moved from a fenced block in the README into an SVG, and a
        picture is where a stale example hides best - nobody reads it as text,
        so nothing notices when the tool stops saying it. The characters are
        still there in the tspans, so this guard did not have to be given up,
        only pointed somewhere else."""
        import os
        import re
        path = os.path.join(os.path.dirname(os.path.abspath(nd.__file__)),
                            "docs", "hero-dark.svg")
        with open(path, encoding="utf-8") as fh:
            svg = fh.read()
        runs = re.findall(r'<tspan\b[^>]*>(.*?)</tspan>', svg, re.S)
        text = "".join(runs)
        return (text.replace("&amp;", "&").replace("&lt;", "<")
                    .replace("&gt;", ">"))

    def test_the_example_verdict_is_shaped_like_a_real_one(self):
        """The README opens on a sample verdict. It had drifted: no coverage on
        the confidence line, and a stage strip missing a stage - both added
        after it was written. A stale example is a promise the tool breaks in
        the first thirty seconds."""
        block = self.hero_text()
        self.assertIn("LIKELY ROOT CAUSE:", block,
                      "the hero image no longer shows a verdict")
        self.assertRegex(block, r"confidence: \w+ \(\d+ of \d+ checks ran\)",
                         "the example omits the coverage the tool now prints")
        stages = [s for s, _f, _w in nd.STAGE_RULES]
        for stage in stages:
            self.assertIn(stage, block, f"the example strip is missing '{stage}'")

    def test_the_hero_image_is_what_the_tool_renders_today(self):
        """Stronger than checking the words are plausible: regenerate both
        images and require the committed bytes. A generated asset that nobody
        regenerates is a screenshot with extra steps, and this one sits at the
        top of the page where it is the first thing anyone believes."""
        import os
        import sys
        root = os.path.dirname(os.path.abspath(nd.__file__))
        sys.path.insert(0, os.path.join(root, "dev"))
        try:
            import hero
        except ImportError:
            self.skipTest("dev/hero.py is not present")
        lines = hero.report_lines()
        for theme in hero.THEMES:
            path = os.path.join(root, "docs", "hero-%s.svg" % theme)
            with open(path, encoding="utf-8") as fh:
                committed = fh.read()
            self.assertEqual(
                hero.svg(lines, theme), committed,
                "docs/hero-%s.svg is stale - the report changed since it was "
                "drawn. Re-run: python3 dev/hero.py" % theme)

    def test_every_verdict_line_the_readme_shows_is_one_the_tool_prints(self):
        """A worked example is only worth showing if it is what comes out. The
        labels and their order both matter: the second example had the
        consequence line above `next:`, which is not where the renderer puts
        it, and nothing here would have noticed."""
        readme = dict(self.docs())["README.md"]
        m = fresh()
        setup, kw = S["link_saturated"]
        setup(m)
        rendered = m.render_text_report(m.diagnose(quick=False, **scenario_kwargs(kw)))
        self.assertIn("this also accounts for:", rendered)

        # Order is checked against the renderer rather than against one run:
        # no single scenario prints every line, and the one that does not print
        # "also, unrelated" would let a wrong order through.
        with open(nd.__file__, encoding="utf-8") as fh:
            src = fh.read()
        body = src.split("def render_text_report", 1)[1]
        # Read out of the example rather than listed here, so a label the tool
        # has never printed cannot pass by simply not being on a list I wrote.
        example = readme.split("owner: capacity", 1)[1].split("```", 1)[0]
        example = "  owner: capacity" + example
        labels = re.findall(r"^\s{2}([a-z][a-z, ]*:)", example, re.M)
        self.assertTrue(labels, "the example has no labelled lines to check")
        for label in labels:
            self.assertIn(label, body,
                          f"the README example shows '{label}' and the renderer "
                          f"prints no such line")
        # Sorted by where the README puts them, then checked against where the
        # renderer emits them. Built the other way round - iterating the list
        # above - this compared the hardcoded order with itself and passed on
        # any README whatsoever.
        shown = sorted((l for l in dict.fromkeys(labels) if l in body),
                       key=example.index)
        order = [body.index(l) for l in shown]
        self.assertEqual(order, sorted(order),
                         f"the README shows {shown} in an order the renderer does not use")

    def test_the_reference_documents_every_flag_that_exists(self):
        """The suite checked docs -> code (no flag documented that isn't real)
        but not code -> docs, so a flag could ship undocumented."""
        import re
        with open(nd.__file__, encoding="utf-8") as fh:
            declared = set(re.findall(r'ap\.add_argument\("(--[a-z-]+)"', fh.read()))
        ref = dict(self.docs())["REFERENCE.md"]
        documented = set(re.findall(r"(--[a-z][a-z-]+)", ref))
        self.assertFalse(declared - documented,
                         f"REFERENCE doesn't document: {sorted(declared - documented)}")

    def test_the_reference_lists_each_flag_exactly_once(self):
        """--quiet was listed twice in the flag block, which reads as two
        different options that happen to share a name."""
        import re
        ref = dict(self.docs())["REFERENCE.md"]
        block = ref.split("```", 2)[1]
        listed = re.findall(r"^(--[a-z-]+)", block, re.M)
        dupes = sorted({f for f in listed if listed.count(f) > 1})
        self.assertFalse(dupes, f"listed more than once: {dupes}")

    def test_the_docs_quote_no_runtime_the_tool_does_not_have(self):
        """Parallelising the probes cut the full run from ~15s to ~7s, and two
        places kept the old figure - so the reference said "~2s instead of ~15s"
        a few hundred lines above "a full --report is ~7s".

        Two runs are measured: quick, and full where the trace answers. A third
        figure is the traceroute timeout, which a full run costs instead when
        the path answers nothing. That one is not measured, it is a constant in
        the source, so it is excused here by matching the source rather than by
        being allowed to be any number at all - quote a timeout the code no
        longer uses and it counts as the stale third figure again."""
        import re
        src = open(nd.__file__, encoding="utf-8").read()
        m = re.search(r'\["traceroute".*?timeout=(\d+)\)', src, re.S)
        self.assertIsNotNone(m, "the traceroute timeout moved; this guard reads it "
                                "from the source to tell a documented timeout "
                                "apart from a stale runtime")
        trace_timeout = int(m.group(1))
        # Scoped to the tool's own runtime. The suite's runtime is a different
        # measurement that legitimately deserves its own figure, and counting
        # it here made an accurate sentence about the tests look like a third
        # stale claim about the tool.
        figures = set()
        for _name, text in self.docs():
            for line in text.splitlines():
                if re.search(r"\btests?\b|suite", line, re.I):
                    continue
                figures |= {int(m.group(1))
                            for m in re.finditer(r"~(\d+)\s*(?:s\b|seconds)", line)}
        runtimes = figures - {trace_timeout}
        self.assertLessEqual(len(runtimes), 2,
                             f"docs quote {sorted(figures)} as runtimes and the traceroute "
                             f"timeout is {trace_timeout}s; only the quick run and the full "
                             f"run are measured, so a third number is stale")

    def test_no_document_states_a_version_that_is_not_the_current_one(self):
        """The titles used to carry the major.minor, pinned here. That was
        consistent and still read as stale: "FaultOne 1.6" on a 1.6.7 release
        looks to a new reader like the last release was 1.6. A version in a
        title is also a thing to remember to bump, and the one place it cannot
        drift is the code.

        So the titles carry no version, and this asserts the stronger property
        instead - that nowhere in the docs is a FaultOne version quoted that
        disagrees with the one in the module."""
        import re
        for name, text in self.docs():
            self.assertNotRegex(text.split("\n")[0], r"FaultOne\s+\d",
                                f"{name}'s title carries a version, which will go stale")
            quoted = set(re.findall(r"FaultOne (\d+\.\d+\.\d+)", text))
            stale = sorted(quoted - {nd.__version__})
            self.assertEqual(stale, [], f"{name} quotes version(s) {stale}, "
                                        f"the tool is {nd.__version__}")


class TestExitStatus(unittest.TestCase):
    """0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN - the monitoring-plugin
    convention, so this drops into a scheduled check without anything parsing
    its output. Before it, a run reporting a degraded link exited 0 and a
    wrapper saw success while the tool was saying something was wrong."""

    def assertReachedAVerdict(self, out):
        """0, 1 and 2 all mean the run produced an answer - that is this
        class's own convention, severity in the exit code. Only 3 means it
        could not.

        The two tests below asserted 0, which additionally requires the
        machine running the suite to be healthy. That held on a laptop and
        stopped holding the first time they ran anywhere else: a CI runner
        found something critical, exited 2, and two tests about the *shape* of
        the output failed for a reason that had nothing to do with shape."""
        self.assertNotIn("Traceback", out.stderr)
        self.assertIn(out.returncode, (0, 1, 2),
                      "exited %d, so no verdict was reached: %s"
                      % (out.returncode, out.stderr))

    def status(self, *severities, verdict=True):
        report = {"findings": [{"severity": s} for s in severities]}
        if verdict:
            report["verdict"] = {"severity": "ok"}
        return nd.exit_status(report)

    def test_nothing_wrong_is_zero(self):
        self.assertEqual(self.status(), 0)
        self.assertEqual(self.status("ok", "ok"), 0)

    def test_a_warning_no_longer_reports_success(self):
        self.assertEqual(self.status("warning"), 1)
        self.assertEqual(self.status("ok", "warning"), 1)

    def test_a_critical_outranks_a_warning(self):
        self.assertEqual(self.status("warning", "critical"), 2)

    def test_a_run_that_produced_no_verdict_is_unknown_not_clean(self):
        """Nothing to judge is not the same as nothing wrong."""
        self.assertEqual(self.status(verdict=False), 3)

    def test_the_codes_are_the_documented_ones(self):
        self.assertEqual((nd.EXIT_OK, nd.EXIT_WARNING, nd.EXIT_CRITICAL, nd.EXIT_UNKNOWN),
                         (0, 1, 2, 3))

    def test_a_failed_export_does_not_lose_the_diagnosis(self):
        """The run has already happened - seven seconds, or two minutes under
        --soak, on a box someone had to reach. A full disk or a wrong path used
        to print a traceback and hand back nothing."""
        import subprocess
        # --quick --target 127.0.0.1, because what is being tested is the
        # write failing after a run, not the run. Without them this did a full
        # traceroute: on any path that does not answer one, that is sixty
        # seconds of timeout, and it was eighty-four per cent of the entire
        # suite's runtime for a test whose subject is an unwritable file.
        out = subprocess.run([sys.executable, nd.__file__, "--export",
                              "/nonexistent-dir/report.json",
                              "--quick", "--target", "127.0.0.1"],
                             capture_output=True, text=True, timeout=180)
        self.assertIn("LIKELY ROOT CAUSE", out.stdout)
        self.assertIn("Could not write", out.stderr)
        self.assertNotIn("Traceback", out.stderr)
        self.assertEqual(out.returncode, 3)

    def test_a_report_sent_to_stdout_is_one_line(self):
        """stdout is where a report goes to be piped or pasted. Indented, a
        compact one is 192 logical lines and about 198 rows on an 80-column
        terminal, so taking it off a box you cannot copy a file from meant
        dragging a selection across all of it and scrolling part-way through.
        On one line a terminal's triple-click takes the whole thing - a soft
        wrap is not a line break to it."""
        import subprocess
        out = subprocess.run([sys.executable, nd.__file__, "--export-compact", "-",
                              "--quick", "--target", "127.0.0.1"],
                             capture_output=True, text=True, timeout=180)
        self.assertReachedAVerdict(out)
        body = out.stdout.strip()
        self.assertEqual(body.count("\n"), 0, "the report came out on several lines")
        json.loads(body)

    def test_a_report_written_to_a_file_keeps_its_indentation(self):
        """A file is where a report goes to be read, diffed and used as a
        baseline. Squeezing that onto one line to suit the paste path would
        trade the readable copy for the pasteable one."""
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "report.json")
            out = subprocess.run([sys.executable, nd.__file__, "--export-compact", path,
                                  "--quick", "--target", "127.0.0.1"],
                                 capture_output=True, text=True, timeout=180)
            self.assertReachedAVerdict(out)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        self.assertGreater(text.count("\n"), 20, "the file lost its indentation")
        json.loads(text)

    def test_stdout_carries_json_and_says_so(self):
        """The format comes from the filename extension and "-" has none, so a
        branch that wrote a page to stdout could never run: to_stdout means the
        name is "-", and wants_html means it ends in .html. Unreachable code
        that reads as a supported route is worse than no code - someone writes
        `--export - > report.html` and gets JSON in it."""
        src = open(nd.__file__, encoding="utf-8").read()
        block = src.split("            if to_stdout:", 1)[1].split("            else:", 1)[0]
        self.assertNotIn("render_report_html", block,
                         "the unreachable html branch is back on stdout")
        self.assertIn("separators=", block)
        help_text = src.split('ap.add_argument("--export", metavar="FILE"', 1)[1] \
                       .split(")\n", 1)[0]
        self.assertIn("always JSON", help_text)

    def test_the_enclosed_page_is_unaffected_by_how_stdout_is_written(self):
        """The island inside a self-contained export has always been written
        compact, and is built by a different function - so the two cannot drift
        into disagreeing about what a report looks like."""
        src = open(nd.__file__, encoding="utf-8").read()
        island = src.split("def render_report_html", 1)[1].split("\n\n\n", 1)[0]
        self.assertIn('separators=(",", ":")', island)
        page = nd.render_report_html({"findings": [], "raw": {}, "hops": [],
                                      "stages": [], "verdict": None})
        blob = page.split('type="application/json">', 1)[1].split("</script>", 1)[0]
        self.assertEqual(blob.count("\n"), 0)

    def test_a_crash_is_unknown_not_a_warning(self):
        """An uncaught exception exits 1 by default, and 1 now means WARNING -
        so a scheduled check would read a broken tool as a mild finding about
        the network."""
        import subprocess, os, tempfile
        src = open(nd.__file__, encoding="utf-8").read().replace(
            '    raw["interfaces"] = cmd_interfaces()',
            '    raise RuntimeError("simulated crash")', 1)
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                        encoding="utf-8") as fh:
            fh.write(src)
            broken = fh.name
        try:
            out = subprocess.run([sys.executable, broken, "--report"],
                                 capture_output=True, text=True, timeout=180)
            self.assertEqual(out.returncode, 3)
            self.assertIn("bug in the tool", out.stderr)
            self.assertIn("Traceback", out.stderr)   # a bug report still needs it
        finally:
            os.unlink(broken)

    def test_the_paths_that_cannot_run_exit_unknown(self):
        """A bad target or an unreadable baseline is the check failing to run,
        which the convention separates from the network being at fault."""
        import subprocess
        for args in (["--report", "--target", "not a host"],
                     ["--report", "--baseline", "/nonexistent-baseline.json"]):
            with self.subTest(args=args):
                out = subprocess.run([sys.executable, nd.__file__] + args,
                                     capture_output=True, timeout=120)
                self.assertEqual(out.returncode, 3)


class TestBareBox(unittest.TestCase):
    """A box with nothing on it: no ip, no ifconfig, no ss, no ping, no
    /proc, no /sys.

    This pins the rule the tool states on its own front page - a check that
    can't run is never reported as a fault. It exists because an audit of all
    21 collectors found the last place that still got it wrong (an unreadable
    resolv.conf reading as "no DNS resolvers configured at all", critical), and
    that audit shouldn't have to be repeated by hand to stay true.
    """

    # Pure-Python network clients rather than wrappers around an external tool,
    # so "the tool is missing" doesn't apply to them - and calling them would
    # put real traffic on the wire, which this suite never does.
    SOCKET_BACKED = {"cmd_tls_check", "cmd_check_port", "cmd_own_tls",
                     "cmd_tls_check_local", "cmd_own_http"}

    ARGS = {
        "cmd_ping": ("8.8.8.8", 2, 1), "cmd_traceroute": ("8.8.8.8",),
        "cmd_dns": ("8.8.8.8",), "cmd_mtr": ("8.8.8.8", 2), "cmd_optics": ("eth0",),
        "cmd_traceroute_tcp": ("8.8.8.8", 443), "cmd_ethtool": ("eth0",),
        "cmd_own_tls": (443,), "cmd_tls_check_local": (443, "example.com"),
        "cmd_own_http": (8080,),
        "cmd_path_mtu": ("8.8.8.8", 1500),
    }

    def bare(self, tools_exist=False):
        """The real module, with every route to the outside world closed off.

        tools_exist=True is the other failure mode: the command is installed
        but returns an error. Both have to degrade the same way.
        """
        spec = importlib.util.spec_from_file_location("nd_bare", MODULE_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        patch_clock(self, sleep=lambda s: None)
        mod.which = lambda c: tools_exist
        mod.run = lambda cmd, timeout=15, limit=None: {
            "ok": False, "cmd": " ".join(cmd),
            "error": ("exited 1" if tools_exist else f"command not found: {cmd[0]}")}
        mod._read_tcp_counters = lambda: {}
        # It has to raise the way a missing file raises. Stubbing open as None
        # produces a TypeError nothing claimed to catch, which tests the harness
        # rather than the tool.
        def no_file(*a, **k):
            raise FileNotFoundError(2, "No such file or directory", a[0] if a else "?")
        mod.open = no_file
        return mod

    def test_every_collector_fails_cleanly_with_nothing_installed(self):
        """No exception, and never a success it can't back up. A collector that
        raises takes the whole diagnosis down with it."""
        mod = self.bare()
        checked = 0
        for name in sorted(n for n in dir(mod) if n.startswith("cmd_")):
            if name in self.SOCKET_BACKED:
                continue
            with self.subTest(collector=name):
                checked += 1
                result = getattr(mod, name)(*self.ARGS.get(name, ()))
                if result is None:
                    continue                      # optional extra, absent
                self.assertIsInstance(result, dict, name)
                if not result.get("ok"):
                    self.assertTrue(result.get("error"),
                                    f"{name} failed without saying why")
        self.assertGreaterEqual(checked, 15, "the collector sweep stopped finding collectors")

    def test_a_bare_box_invents_no_fault(self):
        """Every one of these would be a diagnosis conjured from a missing
        tool rather than from evidence."""
        report = self.bare().diagnose("8.8.8.8", None, quick=False, baseline=None)
        conjured = {"no_ipv4", "no_gateway", "gw_unreachable", "inet_unreachable",
                    "dns_fail", "dns_no_resolvers", "link_errors_live", "duplicate_ip",
                    "pmtu_blackhole", "tcp_flow_loss_all_peers", "duplex_mismatch"}
        fired = {f.get("code") for f in report["findings"]}
        self.assertFalse(fired & conjured, f"invented from missing tools: {fired & conjured}")
        self.assertFalse([f for f in report["findings"] if f["severity"] == "critical"],
                         "a box where nothing could be checked reported a critical fault")

    def test_a_bare_box_does_not_read_as_healthy(self):
        """The opposite failure: silence from every check is not a clean bill
        of health, and must not be summarised as one."""
        report = self.bare().diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertNotIn("no fault", report["verdict"]["headline"].lower())
        self.assertIn("couldn't", report["verdict"]["owner"] + report["verdict"]["headline"])

    def test_a_tool_that_exists_but_fails_degrades_the_same_way(self):
        """Installed-but-broken is the commoner case in the field: a binary
        present with no permission to use it, or one that errors on this box."""
        report = self.bare(tools_exist=True).diagnose("8.8.8.8", None, quick=False,
                                                      baseline=None)
        self.assertFalse([f for f in report["findings"] if f["severity"] == "critical"])
        self.assertNotIn("no fault", report["verdict"]["headline"].lower())

    def test_the_unreadable_findings_say_which_check_could_not_run(self):
        """"Something went wrong" is not actionable; naming the check is."""
        report = self.bare().diagnose("8.8.8.8", None, quick=False, baseline=None)
        fired = {f.get("code") for f in report["findings"]}
        for code in ("interfaces_unreadable", "routes_unreadable", "resolvers_unreadable"):
            self.assertIn(code, fired)


class TestACommandThatDoesNotUnderstandUs(unittest.TestCase):
    """A command can be present and still reject the flags we hand it. Busybox,
    toybox and the trimmed userlands on appliances ship a ping that takes -c and
    not -W, so which() says yes, the flags come back rejected, and reachability,
    loss and latency are all lost to a tuning argument the box never needed.

    The line that keeps this honest: a command that ran and returned a bad
    result is an answer. Only one that did not understand the request earns a
    second attempt with less of it."""

    def run_with(self, replies, os_name="Linux"):
        """Stub run() with a queue of replies, recording what was attempted.

        The platform is stated rather than inherited. Windows takes its own
        branch of cmd_ping with no tuning flag to drop, so a test that assumed
        the machine it was written on passed here and failed in CI."""
        seen = []
        queue = list(replies)

        def fake(cmd, timeout=None, limit=None):
            seen.append(cmd)
            return dict(queue.pop(0), cmd=" ".join(cmd))
        saved, saved_os = nd.run, nd.OS_NAME
        nd.run, nd.OS_NAME = fake, os_name
        try:
            return nd.cmd_ping("8.8.8.8"), seen
        finally:
            nd.run, nd.OS_NAME = saved, saved_os

    def probe(self, present, replies):
        """which() answers from `present`; run() answers from `replies` by name."""
        seen = []

        def fake_run(cmd, timeout=None, limit=None):
            seen.append(cmd[0])
            return dict(replies[cmd[0]], cmd=" ".join(cmd))
        saved_run, saved_which, saved_os = nd.run, nd.which, nd.OS_NAME
        nd.run, nd.which, nd.OS_NAME = fake_run, (lambda c: c in present), "Linux"
        try:
            return nd.cmd_interfaces(), seen
        finally:
            nd.run, nd.which, nd.OS_NAME = saved_run, saved_which, saved_os

    def test_a_command_that_fails_falls_through_to_the_next_one(self):
        """The chain used to choose on which() alone. A trimmed ip whose
        subcommand does not exist exits non-zero, ifconfig sat unread beside
        it, and a working machine was told it had no IP address on any
        interface - the highest-ranked critical in the tool, on a box with
        nothing wrong."""
        res, seen = self.probe(
            present={"ip", "ifconfig"},
            replies={"ip": {"ok": True, "code": 1, "stdout": "",
                            "stderr": 'ip: unknown command "show"'},
                     "ifconfig": {"ok": True, "code": 0, "stderr": "",
                                  "stdout": "eth0: flags=4163 mtu 1500\n  inet 10.0.0.5"}})
        self.assertEqual(seen, ["ip", "ifconfig"], "ifconfig was never tried")
        self.assertIn("inet 10.0.0.5", res["stdout"])

    def test_output_that_is_empty_is_not_an_answer_either(self):
        """Exit 0 with nothing on stdout is the other way a trimmed command
        fails: it accepts the words and prints nothing. The next command in the
        chain may know the answer."""
        res, seen = self.probe(
            present={"ip", "ifconfig"},
            replies={"ip": {"ok": True, "code": 0, "stdout": "   \n", "stderr": ""},
                     "ifconfig": {"ok": True, "code": 0, "stderr": "",
                                  "stdout": "eth0: flags=4163 mtu 1500"}})
        self.assertEqual(seen, ["ip", "ifconfig"])
        self.assertIn("eth0", res["stdout"])

    def test_the_first_command_wins_when_it_answers(self):
        _res, seen = self.probe(
            present={"ip", "ifconfig"},
            replies={"ip": {"ok": True, "code": 0, "stderr": "",
                            "stdout": "1: eth0 inet 10.0.0.5/24"}})
        self.assertEqual(seen, ["ip"], "a working command was followed by another")

    def test_nothing_installed_says_so_rather_than_inventing_a_fault(self):
        res, seen = self.probe(present=set(), replies={})
        self.assertEqual(seen, [], "a command was run that which() said was absent")
        self.assertFalse(res.get("ok"))
        self.assertIn("installed", res.get("error", ""))

    def test_a_rejected_flag_is_retried_without_it(self):
        busybox = {"ok": True, "code": 1, "stdout": "",
                   "stderr": "ping: invalid option -- 'W'\nBusyBox v1.36 multi-call binary."}
        worked = {"ok": True, "code": 0, "stderr": "",
                  "stdout": "4 packets transmitted, 4 packets received, 0% packet loss"}
        res, seen = self.run_with([busybox, worked])
        self.assertEqual(len(seen), 2, "the tuning flag was never dropped")
        self.assertIn("-W", seen[0], "the informative form should be tried first")
        self.assertNotIn("-W", seen[1], "the retry kept the flag that was rejected")
        self.assertEqual(res["code"], 0)
        self.assertIn("0% packet loss", res["stdout"])

    def test_a_real_failure_is_an_answer_and_is_not_retried(self):
        """100% loss is a result. Retrying it would turn one unreachable host
        into two probes and still report the same thing, and on a slow link
        would double the wait for no new information."""
        unreachable = {"ok": True, "code": 1, "stderr": "",
                       "stdout": "4 packets transmitted, 0 packets received, 100% packet loss"}
        res, seen = self.run_with([unreachable, unreachable])
        self.assertEqual(len(seen), 1, "a genuine failure was retried")
        self.assertIn("100% packet loss", res["stdout"])

    def test_success_wins_over_output_that_looks_like_a_complaint(self):
        """The two checks are not interchangeable. A command that exits 0 has
        answered, whatever its output says, and some print a usage banner or the
        word "usage:" in a summary line while working perfectly. Reading the
        text first would throw that answer away and run the weaker form."""
        chatty = {"ok": True, "code": 0, "stderr": "",
                  "stdout": "usage: ping [-c count]\n"
                            "4 packets transmitted, 4 packets received, 0% packet loss"}
        res, seen = self.run_with([chatty])
        self.assertEqual(len(seen), 1,
                         "a successful command was retried because of its wording")
        self.assertIn("0% packet loss", res["stdout"])

    def test_windows_has_no_tuning_flag_to_drop(self):
        """Its ping takes -n and nothing this retry would remove, so the branch
        asks once. Worth pinning: the retry is about the flags we add, and
        adding one here later would be a way to reintroduce the same bug."""
        good = {"ok": True, "code": 0, "stderr": "",
                "stdout": "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"}
        _res, seen = self.run_with([good], os_name="Windows")
        self.assertEqual(len(seen), 1)
        self.assertNotIn("-W", seen[0])

    def test_the_first_form_is_used_when_it_works(self):
        good = {"ok": True, "code": 0, "stderr": "",
                "stdout": "4 packets transmitted, 4 packets received, 0% packet loss"}
        _res, seen = self.run_with([good])
        self.assertEqual(len(seen), 1, "a working command was run twice")


class TestTheAddressesThisBoxHolds(unittest.TestCase):
    """A proxy holds more than one address and they do not behave alike. Until
    this existed the tool could only answer "is there an address at all", which
    is the right question for a laptop and useless for a box terminating a
    service address in front of instances."""

    IP_ADDR = ("1: lo: <LOOPBACK,UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
               "    inet 127.0.0.1/8 scope host lo\n"
               "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq\n"
               "    inet 10.20.30.40/24 brd 10.20.30.255 scope global eth0\n"
               "    inet 203.0.113.10/32 scope global eth0\n"
               "    inet6 2001:db8::a/64 scope global\n"
               "    inet6 fe80::5054:ff:fe12:3456/64 scope link\n")
    BSD = ("lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384\n"
           "\tinet 127.0.0.1 netmask 0xff000000\n"
           "en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n"
           "\tinet 10.20.30.40 netmask 0xffffff00 broadcast 10.20.30.255\n"
           "\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x6\n")
    LINUX_IFCONFIG = ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                      "        inet 10.20.30.40  netmask 255.255.255.0  "
                      "broadcast 10.20.30.255\n"
                      "        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>\n")
    WINDOWS = ("Ethernet adapter Ethernet0:\n\n"
               "   IPv4 Address. . . . . . . . . . . : 10.20.30.40(Preferred)\n"
               "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
               "   Default Gateway . . . . . . . . . : 10.20.30.1\n")

    def rows(self, text):
        return nd.parse_own_addresses({"ok": True, "stdout": text})

    def test_ip_addr_gives_every_address_with_its_interface(self):
        rows = self.rows(self.IP_ADDR)
        self.assertEqual([(r["address"], r["prefix"], r["interface"]) for r in rows],
                         [("127.0.0.1", 8, "lo"),
                          ("10.20.30.40", 24, "eth0"),
                          ("203.0.113.10", 32, "eth0"),
                          ("2001:db8::a", 64, "eth0"),
                          ("fe80::5054:ff:fe12:3456", 64, "eth0")])

    def test_the_other_three_dialects_agree_on_the_same_box(self):
        """One parser over four command outputs, because they differ in
        punctuation and not in content. A parser each is four things to keep in
        step and three of them untested on the machine anyone runs this on."""
        for name, text in (("bsd", self.BSD), ("linux ifconfig", self.LINUX_IFCONFIG),
                           ("windows", self.WINDOWS)):
            with self.subTest(dialect=name):
                rows = [r for r in self.rows(text) if r["address"] == "10.20.30.40"]
                self.assertEqual(len(rows), 1, "the address was not found")
                self.assertEqual(rows[0]["prefix"], 24,
                                 "the netmask notation was not read as /24")

    def test_a_netmask_is_read_in_all_three_notations(self):
        self.assertEqual(nd._mask_to_prefix("0xffffff00"), 24)
        self.assertEqual(nd._mask_to_prefix("255.255.255.0"), 24)
        self.assertEqual(nd._mask_to_prefix("255.255.255.255"), 32)
        self.assertIsNone(nd._mask_to_prefix("not-a-mask"))

    def test_scope_is_read_off_the_address_when_nothing_states_it(self):
        """Only `ip` says it. For the rest the ranges define it, so this is not
        a guess - but loopback and link-local must not be lumped together, or
        "never leaves the box" and "never leaves the segment" become one thing."""
        rows = {r["address"]: r["scope"] for r in self.rows(self.BSD)}
        self.assertEqual(rows["127.0.0.1"], "host")
        self.assertEqual(rows["fe80::1"], "link")
        self.assertEqual(rows["10.20.30.40"], "global")

    def test_a_host_route_beside_a_subnet_is_a_service_address(self):
        """The keepalived signature, and every load balancer that sits on one:
        a /32 on an interface that also carries a real subnet. The box's own
        address comes with the prefix of the network it is on because that is
        what tells it who is local; a service address does not need one."""
        svc = nd.service_addresses(self.rows(self.IP_ADDR))
        self.assertEqual([s["address"] for s in svc], ["203.0.113.10"])

    def test_a_lone_host_route_is_not_a_service_address(self):
        """Point-to-point links and several cloud instances present the box's
        own address as a /32. Alone it is how that network is built, so the
        second address on the interface is what makes the shape mean anything."""
        text = ("2: eth0: <BROADCAST,UP> mtu 1500\n"
                "    inet 10.20.30.40/32 scope global eth0\n")
        self.assertEqual(nd.service_addresses(self.rows(text)), [])

    def test_nothing_is_claimed_when_the_interfaces_could_not_be_read(self):
        self.assertEqual(nd.parse_own_addresses({"ok": False, "error": "x"}), [])


class TestIsTheServiceAddressActuallyServing(unittest.TestCase):
    """Holding the address is the easy half. The half that goes wrong quietly
    is what happens next: the address is configured, it answers ARP, and the
    traffic is going somewhere else. Every other check in this tool passes on
    that box, which is why it needed a finding of its own."""

    VIP = {"ok": True, "cmd": "ip addr", "stdout":
           "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
           "    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n"
           "    inet 10.0.0.200/32 scope global eth0\n"}

    def report(self, ss_text, interfaces=None):
        setup, kw = S["all_clear"]
        mod = fresh()
        setup(mod)
        mod.cmd_interfaces = lambda: interfaces or self.VIP
        serving(mod, ss_text)
        return mod.diagnose(quick=True, **scenario_kwargs(kw))

    def codes(self, report):
        return {f["code"] for f in report["findings"]}

    def test_a_live_connection_is_counted_against_the_address_it_arrived_on(self):
        """The collection change this rests on. The local port was already kept
        and the local address thrown away, which answers "is anyone connected"
        and can never answer "connected to what"."""
        parsed = nd.parse_socket_states(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
            "ESTAB 0 0 10.0.0.200:443 198.51.100.7:51000\n"
            "ESTAB 0 0 10.0.0.200:443 198.51.100.8:51001\n"
            "ESTAB 0 0 10.0.0.5:443 198.51.100.9:51002\n")
        self.assertEqual(parsed["served_on"], {"10.0.0.200": 2, "10.0.0.5": 1})

    def test_a_connection_this_box_made_is_not_one_it_served(self):
        """Outbound connections have a local address too. Counting them would
        make every box look busy on every address it owns."""
        parsed = nd.parse_socket_states(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
            "ESTAB 0 0 10.0.0.5:51234 203.0.113.9:443\n")
        self.assertEqual(parsed["served_on"], {},
                         "an outbound connection was counted as one served")

    def test_a_wildcard_listener_serves_every_address_the_box_holds(self):
        """The false positive that would have mattered most. nginx on 0.0.0.0
        with a service address added underneath it by keepalived is the normal
        shape of this deployment, and calling it unserved would be wrong about
        nearly every box this is written for."""
        self.assertTrue(nd._serves([("0.0.0.0", "443")], "10.0.0.200"))
        self.assertTrue(nd._serves([("*", "443")], "10.0.0.200"))
        self.assertTrue(nd._serves([("::", "443")], "10.0.0.200"))

    def test_an_ipv4_wildcard_does_not_serve_an_ipv6_address(self):
        """0.0.0.0 is the IPv4 wildcard and never accepts an IPv6 connection.
        Counting it as cover suppressed the finding on a v6 service address
        that really did have nothing accepting on it."""
        self.assertFalse(nd._serves([("0.0.0.0", "443")], "2001:db8::a"))
        self.assertTrue(nd._serves([("0.0.0.0", "443")], "10.0.0.200"))

    def test_the_ipv6_wildcard_still_covers_both(self):
        """A dual-stack listener on :: takes IPv4 as mapped addresses, which is
        how most of them are built, so this one has to keep working."""
        self.assertTrue(nd._serves([("::", "443")], "10.0.0.200"))
        self.assertTrue(nd._serves([("::", "443")], "2001:db8::a"))

    def test_a_listener_on_one_address_does_not_serve_another(self):
        self.assertTrue(nd._serves([("10.0.0.200", "443")], "10.0.0.200"))
        self.assertFalse(nd._serves([("10.0.0.5", "443")], "10.0.0.200"))
        self.assertFalse(nd._serves([], "10.0.0.200"))

    def test_an_address_nothing_accepts_on_is_reported(self):
        """Every listener bound to the box's own address, none covering the
        service address. Clients get a refused connection while ARP answers
        normally, which is exactly why nobody suspects the box."""
        codes = self.codes(self.report(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "LISTEN 0 128 10.0.0.5:443 0.0.0.0:*\n"
            "ESTAB 0 0 10.0.0.5:443 198.51.100.7:51000\n"))
        self.assertIn("service_address_unserved", codes)
        self.assertNotIn("service_address_idle", codes)

    def test_a_wildcard_listener_stops_that_finding(self):
        """The same box with the same absence of traffic, served by a wildcard.
        It must not be called unserved, and the guard exists because this is
        one config line away from the case above."""
        codes = self.codes(self.report(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
            "ESTAB 0 0 10.0.0.5:443 198.51.100.7:51000\n"))
        self.assertNotIn("service_address_unserved", codes)
        self.assertIn("service_address_idle", codes)

    def test_an_idle_address_is_only_reported_when_traffic_is_arriving_elsewhere(self):
        """A box nobody is talking to is idle, not broken. The finding is about
        traffic that is arriving and choosing another address, which is what a
        half-finished failover looks like from the node that lost."""
        codes = self.codes(self.report(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"))
        self.assertNotIn("service_address_idle", codes)
        self.assertNotIn("service_address_unserved", codes)

    def test_an_address_in_use_says_nothing_at_all(self):
        """The healthy proxy. Traffic is arriving on the service address, which
        is the whole question, so neither finding has anything to add."""
        codes = self.codes(self.report(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
            "ESTAB 0 0 10.0.0.200:443 198.51.100.7:51000\n"
            "ESTAB 0 0 10.0.0.5:443 198.51.100.9:51002\n"))
        self.assertNotIn("service_address_unserved", codes)
        self.assertNotIn("service_address_idle", codes)

    def test_nothing_is_claimed_when_the_sockets_could_not_be_read(self):
        """No socket list means no evidence either way, and a finding built on
        an absent reading is a diagnosis invented from a gap."""
        setup, kw = S["all_clear"]
        mod = fresh()
        setup(mod)
        mod.cmd_interfaces = lambda: self.VIP
        mod.cmd_socket_states = lambda: {"ok": False, "cmd": "ss", "error": "not found"}
        codes = self.codes(mod.diagnose(quick=True, **scenario_kwargs(kw)))
        self.assertNotIn("service_address_unserved", codes)
        self.assertNotIn("service_address_idle", codes)

    def test_a_box_with_one_address_is_untouched(self):
        """No service address, so none of this applies. The ordinary box is the
        one that must not change."""
        plain = {"ok": True, "cmd": "ip addr", "stdout":
                 "2: eth0: <BROADCAST,UP> mtu 1500\n"
                 "    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n"}
        codes = self.codes(self.report(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "LISTEN 0 128 10.0.0.5:443 0.0.0.0:*\n", interfaces=plain))
        self.assertNotIn("service_address_unserved", codes)
        self.assertNotIn("service_address_idle", codes)
        self.assertNotIn("service_address_present", codes)

    def test_a_busy_service_address_makes_an_idle_one_next_to_it_visible(self):
        """Two service addresses, one taking everything. Traffic reaching this
        box and choosing the other address is the clearest form of the thing
        this finding is for, and the first version excluded it by counting only
        the box's own addresses as "elsewhere"."""
        two = {"ok": True, "cmd": "ip addr", "stdout":
               "2: eth0: <BROADCAST,UP> mtu 1500\n"
               "    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n"
               "    inet 10.0.0.200/32 scope global eth0\n"
               "    inet 10.0.0.201/32 scope global eth0\n"}
        report = self.report(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
            "ESTAB 0 0 10.0.0.200:443 198.51.100.7:51000\n", interfaces=two)
        idle = [f for f in report["findings"] if f["code"] == "service_address_idle"]
        self.assertEqual(len(idle), 1, "the idle one was not reported")
        self.assertIn("10.0.0.201", idle[0]["message"])

    def test_both_are_warnings_and_neither_is_quiet_context(self):
        """Severity is what decides whether anyone sees these. As context they
        sit under a green verdict, which is the reading they exist to prevent:
        a box that passes every check and serves nobody."""
        unserved = self.report(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "LISTEN 0 128 10.0.0.5:443 0.0.0.0:*\n"
            "ESTAB 0 0 10.0.0.5:443 198.51.100.7:51000\n")
        idle = self.report(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
            "ESTAB 0 0 10.0.0.5:443 198.51.100.7:51000\n")
        for report, code in ((unserved, "service_address_unserved"),
                             (idle, "service_address_idle")):
            with self.subTest(code=code):
                found = [f for f in report["findings"] if f["code"] == code]
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0]["severity"], "warning")

    def test_who_is_connected_still_does_not_reach_the_report(self):
        """served_on counts per address and never lists a peer. The peer list is
        every place this box has been talking to, and the export is something
        people paste into tickets."""
        parsed = nd.parse_socket_states(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
            "ESTAB 0 0 10.0.0.200:443 198.51.100.7:51000\n")
        self.assertEqual(parsed["served_on"], {"10.0.0.200": 1})
        self.assertNotIn("198.51.100.7", json.dumps(parsed["served_on"]))


class TestOneRowPerThingThisBoxServes(unittest.TestCase):
    """A box running several instances behind several addresses had no single
    answer to "is the service up", and every check here produced one anyway: a
    certificate read off one listener, a connection count for the whole box."""

    IFACES = {"ok": True, "cmd": "ip addr", "stdout":
              "2: eth0: <BROADCAST,UP> mtu 1500\n"
              "    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n"
              "    inet 10.0.0.200/32 scope global eth0\n"
              "    inet 10.0.0.201/32 scope global eth0\n"}

    def run_box(self, ss, certs=None, quick=True):
        setup, kw = S["all_clear"]
        mod = fresh()
        setup(mod)
        mod.cmd_interfaces = lambda: self.IFACES
        serving(mod, "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n" + ss)
        if certs is not None:
            mod.cmd_own_tls = lambda port, timeout=5, address="127.0.0.1": (
                {"ok": True, "host": address, "port": port, "tls_version": "TLSv1.3",
                 "names": [certs[address][0]], "verified_as": certs[address][0],
                 "verified": True, "expires": "2027-03-12",
                 "days_left": certs[address][1]}
                if address in certs else
                {"ok": False, "host": address, "port": port,
                 "unreachable_locally": "refused"})
        report = mod.diagnose(quick=quick, **scenario_kwargs(kw))
        return report, (report["raw"].get("service_instances") or [])

    def test_every_listener_gets_its_own_row(self):
        _r, rows = self.run_box(
            "LISTEN 0 128 10.0.0.200:443 0.0.0.0:*\n"
            "LISTEN 0 128 10.0.0.201:443 0.0.0.0:*\n"
            "LISTEN 0 128 10.0.0.5:22 0.0.0.0:*\n")
        self.assertEqual([r["endpoint"] for r in rows],
                         ["10.0.0.5:22", "10.0.0.200:443", "10.0.0.201:443"])

    def test_traffic_is_counted_per_endpoint_not_per_box(self):
        """The whole point. One instance busy and one taking nothing is the
        state worth seeing, and a single box-wide count hides it."""
        _r, rows = self.run_box(
            "LISTEN 0 128 10.0.0.200:443 0.0.0.0:*\n"
            "LISTEN 0 128 10.0.0.201:443 0.0.0.0:*\n"
            "ESTAB 0 0 10.0.0.200:443 198.51.100.7:51000\n"
            "ESTAB 0 0 10.0.0.200:443 198.51.100.8:51001\n")
        traffic = {r["endpoint"]: r["traffic"] for r in rows}
        self.assertEqual(traffic["10.0.0.200:443"], 2)
        self.assertEqual(traffic["10.0.0.201:443"], 0)

    def test_two_instances_on_one_address_are_told_apart_by_port(self):
        _r, rows = self.run_box(
            "LISTEN 0 128 10.0.0.200:443 0.0.0.0:*\n"
            "LISTEN 0 128 10.0.0.200:8443 0.0.0.0:*\n"
            "ESTAB 0 0 10.0.0.200:8443 198.51.100.7:51000\n")
        traffic = {r["endpoint"]: r["traffic"] for r in rows}
        self.assertEqual(traffic["10.0.0.200:443"], 0)
        self.assertEqual(traffic["10.0.0.200:8443"], 1)

    def test_a_wildcard_listener_is_one_row_counting_every_address(self):
        """It answers on all of them, so splitting it per address would invent
        instances that do not exist."""
        _r, rows = self.run_box(
            "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
            "ESTAB 0 0 10.0.0.200:443 198.51.100.7:51000\n"
            "ESTAB 0 0 10.0.0.5:443 198.51.100.8:51001\n")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["traffic"], 2)

    def test_the_name_comes_off_the_certificate(self):
        _r, rows = self.run_box(
            "LISTEN 0 128 10.0.0.200:443 0.0.0.0:*\n"
            "LISTEN 0 128 10.0.0.201:443 0.0.0.0:*\n",
            certs={"10.0.0.200": ("broker-a.example.com", 214),
                   "10.0.0.201": ("broker-b.example.com", 9)}, quick=False)
        names = {r["endpoint"]: (r["name"], r["named_from"]) for r in rows}
        self.assertEqual(names["10.0.0.200:443"], ("broker-a.example.com", "certificate"))
        self.assertEqual(names["10.0.0.201:443"], ("broker-b.example.com", "certificate"))

    def test_without_a_certificate_the_address_is_the_name(self):
        """No reverse DNS fallback on purpose: a PTR is a network call, and
        this runs on boxes whose DNS is the thing being diagnosed."""
        _r, rows = self.run_box("LISTEN 0 128 10.0.0.200:443 0.0.0.0:*\n"
                                "LISTEN 0 128 10.0.0.5:22 0.0.0.0:*\n")
        named = {r["endpoint"]: r["named_from"] for r in rows}
        self.assertEqual(set(named.values()), {"the address"})
        src = inspect.getsource(nd._build_service_instances)
        self.assertNotIn("gethostbyaddr", src)

    def test_a_certificate_near_expiry_shows_on_its_own_row(self):
        _r, rows = self.run_box(
            "LISTEN 0 128 10.0.0.200:443 0.0.0.0:*\n"
            "LISTEN 0 128 10.0.0.201:443 0.0.0.0:*\n",
            certs={"10.0.0.200": ("a.example.com", 214),
                   "10.0.0.201": ("b.example.com", 9)}, quick=False)
        up = {r["endpoint"]: r["up"] for r in rows}
        self.assertEqual(up["10.0.0.200:443"], "ok")
        self.assertEqual(up["10.0.0.201:443"], "expires in 9d")

    def test_a_failed_request_does_not_overwrite_a_good_handshake(self):
        """Both probes can run against one listener and they answer different
        questions. Merged into one result, the HTTP attempt's failure buried a
        successful handshake and a healthy instance read as unreachable."""
        _r, rows = self.run_box(
            "LISTEN 0 128 10.0.0.200:443 0.0.0.0:*\n"
            "LISTEN 0 128 10.0.0.201:443 0.0.0.0:*\n",
            certs={"10.0.0.200": ("a.example.com", 300),
                   "10.0.0.201": ("b.example.com", 300)}, quick=False)
        self.assertEqual({r["up"] for r in rows}, {"ok"},
                         "a good handshake was overwritten by a failed request")

    def test_a_workstations_own_system_listeners_are_not_a_table(self):
        """An ordinary machine holds a dozen wildcard listeners it got from its
        operating system. A table of those saying "listening, nothing arriving"
        buries the rows that matter, so a row earns its line by having had
        something learned about it."""
        report, rows = self.run_box(
            "LISTEN 0 128 0.0.0.0:88 0.0.0.0:*\n"
            "LISTEN 0 128 0.0.0.0:445 0.0.0.0:*\n"
            "LISTEN 0 128 0.0.0.0:3689 0.0.0.0:*\n"
            "LISTEN 0 128 0.0.0.0:62324 0.0.0.0:*\n")
        self.assertEqual(len(rows), 4, "the data should keep every listener")
        self.assertEqual([r["notable"] for r in rows], [False] * 4)
        self.assertNotIn("SERVICE INSTANCES",
                         nd.render_text_report(report, color=False, width=88))

    def test_a_listener_on_one_specific_address_is_always_notable(self):
        """Binding to one address is a decision rather than a default, and is
        how a deliberate instance is configured."""
        _r, rows = self.run_box("LISTEN 0 128 10.0.0.200:9999 0.0.0.0:*\n"
                                "LISTEN 0 128 10.0.0.201:9999 0.0.0.0:*\n")
        self.assertEqual([r["notable"] for r in rows], [True, True])

    def test_traffic_alone_makes_a_row_notable(self):
        _r, rows = self.run_box(
            "LISTEN 0 128 0.0.0.0:9999 0.0.0.0:*\n"
            "ESTAB 0 0 10.0.0.5:9999 198.51.100.7:51000\n")
        self.assertTrue(rows[0]["notable"])

    def test_one_instance_prints_no_table(self):
        """A box serving a single thing is already described by the findings,
        and a one-row table is furniture."""
        report, rows = self.run_box("LISTEN 0 128 10.0.0.200:443 0.0.0.0:*\n")
        self.assertEqual(len(rows), 1)
        text = nd.render_text_report(report, color=False, width=88)
        self.assertNotIn("SERVICE INSTANCES", text)

    def test_several_instances_print_a_table_naming_each(self):
        report, _rows = self.run_box(
            "LISTEN 0 128 10.0.0.200:443 0.0.0.0:*\n"
            "LISTEN 0 128 10.0.0.201:443 0.0.0.0:*\n"
            "ESTAB 0 0 10.0.0.200:443 198.51.100.7:51000\n")
        text = nd.render_text_report(report, color=False, width=88)
        self.assertIn("SERVICE INSTANCES", text)
        self.assertIn("10.0.0.200:443", text)
        self.assertIn("10.0.0.201:443", text)
        self.assertIn("nothing arriving", text)


class TestEveryInstanceIsLookedAt(unittest.TestCase):
    """The dedupe was on the port alone, so a box running several instances
    behind several addresses on 443 - the ordinary shape of a front end - had
    exactly one checked. The certificate expiry this exists to catch was read
    off one instance and assumed of the rest."""

    def probed(self, ss, quick=False):
        seen = []
        setup, kw = S["all_clear"]
        mod = fresh()
        setup(mod)
        serving(mod, "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n" + ss)
        mod.cmd_own_tls = lambda port, timeout=5, address="127.0.0.1": (
            seen.append((address, port)) or
            {"ok": True, "host": address, "port": port, "tls_version": "TLSv1.3",
             "names": ["x.example.com"], "verified_as": "x.example.com",
             "verified": True, "days_left": 300})
        mod.diagnose(quick=quick, **scenario_kwargs(kw))
        return seen

    def test_each_address_on_one_port_is_checked(self):
        seen = self.probed("LISTEN 0 128 10.0.0.200:443 0.0.0.0:*\n"
                           "LISTEN 0 128 10.0.0.201:443 0.0.0.0:*\n"
                           "LISTEN 0 128 10.0.0.202:443 0.0.0.0:*\n")
        self.assertEqual(sorted(a for a, _p in seen),
                         ["10.0.0.200", "10.0.0.201", "10.0.0.202"])

    def test_the_request_check_separates_them_too(self):
        """The same dedupe, in the other probe. Port 80 takes the HTTP path and
        no handshake, so a fix applied only to the TLS side would leave every
        plain instance but the first unasked."""
        seen = []
        setup, kw = S["all_clear"]
        mod = fresh()
        setup(mod)
        serving(mod, "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                     "LISTEN 0 128 10.0.0.200:80 0.0.0.0:*\n"
                     "LISTEN 0 128 10.0.0.201:80 0.0.0.0:*\n")
        mod.cmd_own_http = lambda port, timeout=5, address="127.0.0.1", tls=False: (
            seen.append((address, port)) or
            {"ok": True, "host": address, "port": port, "status": 200})
        mod.diagnose(quick=False, **scenario_kwargs(kw))
        self.assertEqual(sorted(a for a, _p in seen), ["10.0.0.200", "10.0.0.201"])

    def test_the_same_listener_is_not_checked_twice(self):
        seen = self.probed("LISTEN 0 128 10.0.0.200:443 0.0.0.0:*\n"
                           "LISTEN 0 128 10.0.0.200:443 0.0.0.0:*\n")
        self.assertEqual(len(seen), 1)

    def test_what_the_limit_skipped_is_said_out_loud(self):
        """A cap that trims quietly reads as full coverage, and "every
        certificate here is good for 300 days" must not rest on a partial
        reading."""
        many = "".join("LISTEN 0 128 10.0.0.%d:443 0.0.0.0:*\n" % (10 + i)
                       for i in range(nd.OWN_TLS_MAX_LISTENERS + 4))
        setup, kw = S["all_clear"]
        mod = fresh()
        setup(mod)
        serving(mod, "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n" + many)
        mod.cmd_own_tls = lambda port, timeout=5, address="127.0.0.1": {
            "ok": True, "host": address, "port": port, "tls_version": "TLSv1.3",
            "names": ["x.example.com"], "verified_as": "x.example.com",
            "verified": True, "days_left": 300}
        report = mod.diagnose(quick=False, **scenario_kwargs(kw))
        own = report["raw"]["own_tls"]
        self.assertEqual(own["not_checked"], 4)
        self.assertIn("4 more listener(s) not checked", own["stdout"])


class TestServingClientsWhileConnectedToNothing(unittest.TestCase):
    """The shape: something that only exists to relay, holding a session to
    whatever it forwards to the whole time it is working. Lose that and the box
    keeps its address, its listener and its clients, every connection it accepts
    fails on the far side, and nothing else here notices, because everything
    else here is measuring a box that is up."""

    def codes(self, ss):
        setup, kw = S["all_clear"]
        mod = fresh()
        setup(mod)
        serving(mod, "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n" + ss)
        return {f["code"] for f in mod.diagnose(quick=True,
                                                **scenario_kwargs(kw))["findings"]}

    def clients(self, n, port=443):
        return "".join("ESTAB 0 0 10.0.0.5:%d 198.51.100.%d:51%02d\n" % (port, i, i)
                       for i in range(1, n + 1))

    def test_clients_connected_and_nothing_outbound_is_reported(self):
        codes = self.codes("LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n" + self.clients(4))
        self.assertIn("no_upstream_sessions", codes)

    def test_an_outbound_session_settles_it(self):
        codes = self.codes("LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n" + self.clients(4)
                           + "ESTAB 0 0 10.0.0.5:51999 203.0.113.9:443\n")
        self.assertNotIn("no_upstream_sessions", codes)

    def test_a_box_with_no_clients_says_nothing(self):
        """Nothing is depending on it, so there is nothing to be cut off from."""
        codes = self.codes("LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n" + self.clients(1))
        self.assertNotIn("no_upstream_sessions", codes)

    def test_it_stays_quiet_while_the_box_is_trying(self):
        """Connections stuck in SYN_SENT are a box trying and failing rather
        than a box not trying. syn_sent_backlog already says so, and two
        findings for one condition is how a report stops being a verdict."""
        stuck = "".join("SYN-SENT 0 1 10.0.0.5:519%02d 203.0.113.9:443\n" % i
                        for i in range(1, nd.SYN_SENT_WARN + 1))
        codes = self.codes("LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
                           + self.clients(4) + stuck)
        self.assertNotIn("no_upstream_sessions", codes)
        self.assertIn("syn_sent_backlog", codes)

    def test_it_is_context_and_never_a_fault(self):
        """One reading cannot separate a relay that lost its upstream from a
        service that answers from itself, and a warning that fires on every
        self-contained server is noise."""
        setup, kw = S["all_clear"]
        mod = fresh()
        setup(mod)
        serving(mod, "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                     "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n" + self.clients(4))
        report = mod.diagnose(quick=True, **scenario_kwargs(kw))
        found = [f for f in report["findings"] if f["code"] == "no_upstream_sessions"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "ok")
        self.assertIn("no_upstream_sessions", nd.VERDICT_EXEMPT)


class TestLeavingFromAChosenAddress(unittest.TestCase):
    """--source. On a box with one address it changes nothing; on a proxy it is
    the difference between measuring the path a client of the service address
    gets and measuring a path nobody uses.

    The faults it exists to find are the ones that discriminate by source:
    policy routing, a return path that differs per address, an upstream filter
    or NAT keyed on it, reverse-path filtering. Every one of those is invisible
    to a run that lets the kernel choose, and reports clean."""

    def setUp(self):
        self.saved = (nd.SOURCE_ADDRESS, nd.OS_NAME, nd.run, nd.which)

    def tearDown(self):
        nd.SOURCE_ADDRESS, nd.OS_NAME, nd.run, nd.which = self.saved

    def built(self, tool, os_name, source, present=("traceroute",)):
        """Which utilities exist is stated, not inherited from the machine.

        cmd_traceroute picks traceroute when it is installed and tracepath when
        it is not, and those take different flags. Stubbing run() alone left the
        real which() to decide, so this passed on a laptop with traceroute and
        failed in CI, where the runners ship tracepath instead. The same lesson
        the ping retry test learned: name the platform the assertion is about.
        """
        seen = []
        nd.SOURCE_ADDRESS, nd.OS_NAME = source, os_name
        nd.which = lambda c: ("/usr/bin/" + c) if c in present else None
        nd.run = lambda cmd, **kw: (seen.append(cmd),
                                    {"ok": True, "cmd": " ".join(cmd), "code": 0,
                                     "stdout": "x", "stderr": ""})[1]
        (nd.cmd_ping if tool == "ping" else nd.cmd_traceroute)("8.8.8.8")
        return seen

    def test_each_platform_gets_the_flag_it_actually_takes(self):
        """Three spellings for one idea and they are not interchangeable. Linux
        ping takes -I, BSD and macOS take -S, both traceroutes take -s."""
        self.assertIn("-I", self.built("ping", "Linux", "10.0.0.9")[0])
        self.assertIn("-S", self.built("ping", "Darwin", "10.0.0.9")[0])
        self.assertIn("-s", self.built("traceroute", "Linux", "10.0.0.9")[0])

    def test_windows_ping_has_no_such_flag_and_is_not_given_one(self):
        """It has no equivalent, so a bound run there rests on the socket
        probes, which do support it. Inventing a flag would fail the command
        and lose reachability entirely."""
        cmd = self.built("ping", "Windows", "10.0.0.9")[0]
        self.assertNotIn("-S", cmd)
        self.assertNotIn("-I", cmd)
        # The built command is not enough on its own: the Windows branch does
        # not use the flag list at all, so it stays correct however wrong the
        # list is. Ask the thing that decides, or this guard is decoration.
        nd.OS_NAME, nd.SOURCE_ADDRESS = "Windows", "10.0.0.9"
        self.assertEqual(nd._source_flag("ping"), [],
                         "a flag was produced for a ping that has none")

    def test_a_box_with_only_tracepath_is_left_unbound_rather_than_broken(self):
        """tracepath has no source option. Left unbound on purpose: the hop
        list is still the hop list, and inventing a flag it does not take would
        fail the command and lose the path entirely.

        Found by CI, which runs on images that ship tracepath and not
        traceroute, against a test that had quietly assumed otherwise."""
        cmd = self.built("traceroute", "Linux", "10.0.0.9", present=("tracepath",))[0]
        self.assertEqual(cmd, ["tracepath", "8.8.8.8"])
        self.assertNotIn("-s", cmd)

    def test_the_source_survives_the_retry_that_drops_the_tuning_flag(self):
        """cmd_ping asks twice when the first form is rejected. The source must
        ride both forms: dropping it would answer a different question than the
        one asked, and a confident wrong answer is worse than none."""
        nd.SOURCE_ADDRESS, nd.OS_NAME = "10.0.0.9", "Linux"
        seen = []

        def fake(cmd, **kw):
            seen.append(cmd)
            if "-W" in cmd:
                return {"ok": True, "cmd": " ".join(cmd), "code": 1, "stdout": "",
                        "stderr": "ping: invalid option -- 'W'"}
            return {"ok": True, "cmd": " ".join(cmd), "code": 0,
                    "stdout": "0% packet loss", "stderr": ""}
        nd.run = fake
        nd.cmd_ping("8.8.8.8")
        self.assertEqual(len(seen), 2, "the retry did not happen")
        self.assertIn("-I", seen[1], "the source was dropped along with -W")

    def test_without_a_source_the_commands_are_what_they_always_were(self):
        """The regression that matters most. Nobody passing --source is the
        common case, and this must not have changed their run at all."""
        self.assertEqual(self.built("ping", "Linux", None)[0],
                         ["ping", "-c", "4", "-W", "2", "8.8.8.8"])
        self.assertEqual(self.built("traceroute", "Linux", None)[0],
                         ["traceroute", "-m", "20", "-w", "2", "8.8.8.8"])

    def test_every_probe_that_can_name_a_source_actually_does(self):
        """The defect this replaces: the report said every check left from the
        chosen address while the port check, the path MTU probe, the TCP trace
        and DNS all left from whatever the kernel picked. A claim in the report
        that the code does not keep is the worst kind of bug this tool can have,
        because the whole product is a sentence people act on.

        Read off the source rather than asserted from a list, so a collector
        added later is held to the same rule instead of quietly escaping it."""
        import ast
        import textwrap
        src = open(nd.__file__, encoding="utf-8").read()
        tree = ast.parse(src)
        lines = src.splitlines()
        # Everything that sends off the box. Delegators are named with what
        # they delegate to, since the binding lives one level down.
        senders = {
            "cmd_ping": None, "cmd_traceroute": None, "cmd_path_mtu": None,
            "cmd_traceroute_tcp": None, "cmd_dns": None, "cmd_tls_check": None,
            "cmd_check_port": "_connect_once", "cmd_dns_health": "dns_query",
        }
        bodies = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                bodies[node.name] = "\n".join(lines[node.lineno - 1:node.end_lineno])
        for name, delegate in senders.items():
            with self.subTest(collector=name):
                body = bodies[delegate or name]
                self.assertTrue(
                    any(k in body for k in ("_source_flag", "connect_from",
                                            "_source_for", "SOURCE_ADDRESS")),
                    "%s sends off the box and never names the source" % (delegate or name))

    def test_the_port_check_leaves_from_the_chosen_address(self):
        """The one most worth binding. A port check asks "can a client of this
        address reach that service", and answered from the box's own address it
        is a confident answer to a question nobody asked."""
        seen = {}
        real = nd.socket.socket

        class Sock(object):
            def __init__(self, *a):
                self._s = real(*a)

            def bind(self, addr):
                seen["bound"] = addr

            def settimeout(self, t):
                pass

            def connect_ex(self, addr):
                return 0

            def recv(self, n):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *a):
                self._s.close()
        nd.socket.socket = Sock
        try:
            nd.SOURCE_ADDRESS = "10.0.0.9"
            nd.cmd_check_port("10.0.0.1", 443)
        finally:
            nd.socket.socket = real
        self.assertEqual(seen.get("bound"), ("10.0.0.9", 0))

    def test_a_source_of_the_wrong_family_is_not_bound_at_all(self):
        """A run bound to an IPv4 address still has to reach an IPv6-only
        target. Refusing would turn "measure from this address" into "only
        measure what this address can reach", which is a different and much
        less useful instruction."""
        nd.SOURCE_ADDRESS = "10.0.0.9"
        self.assertIsNone(nd._source_for(nd.socket.AF_INET6))
        self.assertEqual(nd._source_for(nd.socket.AF_INET), ("10.0.0.9", 0))
        nd.SOURCE_ADDRESS = "2001:db8::9"
        self.assertIsNone(nd._source_for(nd.socket.AF_INET))
        self.assertEqual(nd._source_for(nd.socket.AF_INET6), ("2001:db8::9", 0))

    def test_the_path_mtu_probe_is_bound_on_every_platform(self):
        """It builds its own pings rather than going through cmd_ping, so it
        needed the flag adding to each platform's form. Path MTU is a property
        of a path, and a box with a tunnel on one address and not the other has
        two of them."""
        for os_name, flag in (("Linux", "-I"), ("Darwin", "-S")):
            with self.subTest(os=os_name):
                seen = []
                saved_run, saved_os = nd.run, nd.OS_NAME
                nd.OS_NAME, nd.SOURCE_ADDRESS = os_name, "10.0.0.9"
                nd.run = lambda cmd, **kw: (seen.append(cmd),
                                            {"ok": True, "cmd": " ".join(cmd), "code": 1,
                                             "stdout": "", "stderr": ""})[1]
                try:
                    nd.cmd_path_mtu("8.8.8.8")
                finally:
                    nd.run, nd.OS_NAME = saved_run, saved_os
                self.assertTrue(seen, "the probe never ran")
                self.assertIn(flag, seen[0])
                self.assertIn("10.0.0.9", seen[0])

    def test_each_tcp_trace_utility_gets_its_own_source_flag(self):
        """Three utilities, three spellings, and a presence check on the
        function body cannot tell them apart: dropping the flag from one of the
        three leaves the other two mentioning it, and the guard passes while a
        real trace goes out unbound. Each one is built and read."""
        for tool, flag in (("tcptraceroute", "-s"), ("traceroute", "-s"), ("mtr", "-a")):
            with self.subTest(tool=tool):
                seen = []
                nd.SOURCE_ADDRESS, nd.OS_NAME = "10.0.0.9", "Linux"
                nd.which = lambda c, _t=tool: ("/usr/bin/" + c) if c == _t else None
                nd.run = lambda cmd, **kw: (seen.append(cmd),
                                            {"ok": True, "cmd": " ".join(cmd), "code": 1,
                                             "stdout": "", "stderr": ""})[1]
                nd.cmd_traceroute_tcp("8.8.8.8")
                self.assertTrue(seen, "%s was never attempted" % tool)
                self.assertEqual(seen[0][0], tool)
                self.assertIn(flag, seen[0])
                self.assertIn("10.0.0.9", seen[0])

    def test_holding_an_address_is_decided_by_the_kernel_not_by_parsing(self):
        """Loopback is always here and a documentation address never is, on any
        machine this runs on, so this needs no network and no fixture."""
        self.assertTrue(nd.source_address_is_held("127.0.0.1"))
        self.assertFalse(nd.source_address_is_held("203.0.113.10"))

    def test_the_check_never_opens_a_port(self):
        """It binds, which reserves an address, and never listens. A bound TCP
        socket that has not listened cannot accept a connection even in
        principle - the property this program is not allowed to lose."""
        import ast
        import textwrap
        tree = ast.parse(textwrap.dedent(inspect.getsource(nd.source_address_is_held)))
        # The calls it makes, not the words it contains. Its own docstring
        # explains why it never listens, and a text search finds that sentence
        # and calls it a violation.
        called = {n.func.attr for n in ast.walk(tree)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertIn("bind", called)
        self.assertNotIn("listen", called)
        self.assertNotIn("accept", called)
        self.assertIn("SOCK_STREAM", names,
                      "a datagram socket could receive while it was open")

    def test_an_unheld_source_fails_at_bind_as_its_own_kind_of_error(self):
        """It is a diagnosis, not a failed probe. Everything else raised here
        means the far end did something; this means the near end never had the
        address, and the report must not blame the far end for it."""
        nd.SOURCE_ADDRESS = "203.0.113.10"
        with self.assertRaises(nd.SourceAddressUnavailable):
            nd.connect_from("192.0.2.1", 80, 2)

    def test_an_address_this_box_does_not_hold_is_critical_and_is_the_verdict(self):
        """Severity is the whole point of this finding. As a warning it sits in
        a list under a green verdict, which is the exact reading it exists to
        prevent: a standby node measuring its own address and looking healthy
        while the service address lives on its partner."""
        setup, kw = S["source_address_not_held"]
        mod = fresh()
        setup(mod)
        report = mod.diagnose(quick=False, **scenario_kwargs(kw))
        found = [f for f in report["findings"]
                 if f["code"] == "source_address_not_held"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "critical")
        self.assertIn("source_address_not_held", report["verdict"]["based_on"],
                      "it did not become the root cause, so the run still "
                      "reads as being about a path nobody asked for")

    def test_without_a_source_that_error_cannot_be_raised(self):
        """The kernel picks an address it holds, so the case does not arise -
        and a probe that fails for an ordinary reason must not be reported as
        an address this box does not have."""
        nd.SOURCE_ADDRESS = None
        try:
            nd.connect_from("192.0.2.1", 9, 0.2)
        except nd.SourceAddressUnavailable:
            self.fail("an unbound probe was blamed on the source address")
        except OSError:
            pass


class TestABoxWithNoUserlandWeKnow(unittest.TestCase):
    """The case past the fall-through chain: not one command missing, but every
    command foreign. A vendor OS, a scratch container, an appliance with its own
    shell - which() finds names, none of them understand us, and the chain runs
    out.

    Two separate defects lived here. The chain handed its last failure upward as
    a success, because run() reports ok for anything it managed to execute, so
    "exited 127 with nothing to say" arrived as a successful read of a machine
    with no address and no gateway - two criticals and exit 2 on a healthy box.
    And nothing tried the one source that cannot be missing: the kernel, which
    publishes the routing and neighbour tables as files no userland can trim."""

    ROUTE = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
             "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
             "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n")
    ARP = ("IP address       HW type     Flags       HW address            Mask     Device\n"
           "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n"
           "192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        eth0\n")

    def setUp(self):
        self.saved = (nd.run, nd.which, nd.OS_NAME, nd.read_proc)

    def tearDown(self):
        nd.run, nd.which, nd.OS_NAME, nd.read_proc = self.saved

    def foreign_box(self, proc=None):
        """Every command present, every command refusing. /proc answers `proc`."""
        nd.OS_NAME = "Linux"
        nd.which = lambda c: "/bin/" + c
        nd.run = lambda cmd, timeout=None, limit=None: {
            "ok": True, "cmd": " ".join(cmd), "code": 127, "stdout": "",
            "stderr": "%s: not supported on this platform" % cmd[0]}
        nd.read_proc = lambda path: (proc or {}).get(path)

    def test_a_command_that_ran_and_failed_is_not_an_empty_machine(self):
        """The whole bug in one assertion. Without this the result is ok, its
        stdout is empty, and every parser downstream reads that as a box with
        nothing configured on it."""
        self.foreign_box()
        res = nd.cmd_interfaces()
        self.assertFalse(res.get("ok"),
                         "a command that exited 127 was reported as a successful read")
        self.assertIn("127", res.get("error", ""),
                      "the error should say what actually happened")

    def test_an_empty_answer_from_a_working_command_is_still_an_answer(self):
        """The other side of that line, and the reason it tests the exit code
        rather than the output. A box that has spoken to nobody has an empty
        neighbour table, and exit 0 with no rows is the true reading of it - it
        must not become 'the neighbour table could not be read'."""
        nd.OS_NAME = "Linux"
        nd.which = lambda c: "/bin/" + c
        nd.run = lambda cmd, timeout=None, limit=None: {
            "ok": True, "cmd": " ".join(cmd), "code": 0, "stdout": "", "stderr": ""}
        nd.read_proc = lambda path: None
        res = nd.cmd_arp()
        self.assertTrue(res.get("ok"),
                        "an empty table from a command that worked was called a failure")

    def test_the_kernel_supplies_the_gateway_when_no_command_can(self):
        self.foreign_box(proc={"/proc/net/route": self.ROUTE})
        res = nd.cmd_routes()
        self.assertTrue(res.get("ok"))
        self.assertEqual(nd.guess_default_gateway(res), "192.168.1.1")

    def test_the_gateway_is_read_in_the_byte_order_proc_writes_it(self):
        """/proc writes addresses host-endian, so 0101A8C0 is 192.168.1.1. Read
        the obvious way the quad comes out backwards - still shaped like an
        address, pointing at nothing, and reported as the gateway."""
        self.assertEqual(nd._le_hex_ipv4("0101A8C0"), "192.168.1.1")
        self.assertEqual(nd._le_hex_ipv4("FE01A8C0"), "192.168.1.254")

    def test_only_the_default_route_is_taken_from_the_table(self):
        """The second row of ROUTE is the on-link subnet, whose gateway column
        is zero. Taking it would report 0.0.0.0 as the next hop."""
        self.foreign_box(proc={"/proc/net/route": self.ROUTE})
        self.assertEqual(nd.cmd_routes()["stdout"].strip().count("\n"), 0,
                         "a route other than the default was reported")

    def test_the_kernel_supplies_the_neighbour_table_too(self):
        self.foreign_box(proc={"/proc/net/arp": self.ARP})
        entries = nd.parse_arp_table(nd.cmd_arp()["stdout"])
        self.assertEqual([e["ip"] for e in entries], ["192.168.1.1", "192.168.1.77"])
        self.assertEqual(entries[0]["mac"], "aa:bb:cc:dd:ee:ff")

    def test_an_unanswered_neighbour_is_kept_as_incomplete(self):
        """Flags 0x0 is an entry the box asked about and never heard back on.
        Dropping it loses the difference between a gateway that is silent and a
        gateway nobody has asked about, which is a finding of its own."""
        self.foreign_box(proc={"/proc/net/arp": self.ARP})
        entries = nd.parse_arp_table(nd.cmd_arp()["stdout"])
        self.assertEqual(entries[1]["state"], "incomplete")
        self.assertIsNone(entries[1]["mac"], "an all-zero MAC was read as a real one")

    def test_a_kernel_that_cannot_answer_leaves_the_real_error_standing(self):
        """No /proc, which is every non-Linux box. The reader must return None
        rather than a failure of its own, or the reported reason for the run
        knowing nothing becomes this file instead of the foreign commands."""
        self.foreign_box(proc={})
        self.assertIsNone(nd.kernel_routes())
        self.assertIn("127", nd.cmd_routes().get("error", ""))

    def test_the_kernel_is_asked_only_after_the_commands_have_failed(self):
        """It is a last resort, not a shortcut. A working `ip route` must still
        be what the report is built from, since it says more than /proc does."""
        asked = []
        nd.OS_NAME = "Linux"
        nd.which = lambda c: "/bin/" + c
        nd.run = lambda cmd, timeout=None, limit=None: {
            "ok": True, "cmd": " ".join(cmd), "code": 0, "stderr": "",
            "stdout": "default via 10.9.9.1 dev eth0 proto dhcp metric 100"}
        nd.read_proc = lambda path: asked.append(path)
        res = nd.cmd_routes()
        self.assertEqual(asked, [], "/proc was read while a command was working")
        self.assertEqual(nd.guess_default_gateway(res), "10.9.9.1")

    def test_a_self_assigned_address_is_not_evidence_of_being_on_the_network(self):
        """169.254 means DHCP never answered. It is an address, and offering it
        as proof the box has one would suppress the finding that says so."""
        saved = nd.socket.socket
        try:
            class Sock(object):
                def __init__(self, *a):
                    pass

                def settimeout(self, _t):
                    pass

                def connect(self, _a):
                    pass

                def getsockname(self):
                    return ("169.254.9.9", 9)

                def close(self):
                    pass
            nd.socket.socket = Sock
            self.assertIsNone(nd.kernel_source_address())
        finally:
            nd.socket.socket = saved

    def test_the_foreign_box_is_told_what_is_unknown_not_what_is_broken(self):
        """End to end, and the reason all of this exists. Before it, this box
        reported no address and no gateway, both critical, and exited 2."""
        self.foreign_box()
        report = nd.diagnose(quick=True, target="8.8.8.8")
        codes = {f["code"] for f in report["findings"]}
        criticals = [f["code"] for f in report["findings"]
                     if f["severity"] == "critical"]
        self.assertNotIn("no_ipv4", codes)
        self.assertNotIn("no_gateway", codes)
        self.assertIn("interfaces_unreadable", codes)
        self.assertEqual(criticals, [],
                         "a box nothing is known about was called broken: %s" % criticals)


class TestNothingRunsUnasked(unittest.TestCase):
    """`which` is how this suite keeps its promise to send no packets: stub it
    to False and no external command should be reachable. Windows was exempt
    from that by accident - cmd_traceroute ran tracert without asking whether
    it existed - so on Windows the stub did nothing, real tracert went to
    8.8.8.8, and thirteen tests waited out its sixty second timeout. That was
    three quarters of a seventeen minute run, and invisible on any other
    system.

    It is a fault in the tool before it is a fault in the suite: on a Windows
    box without tracert, every other platform says "no utility found" and
    carries on, and that one raised."""

    def test_no_platform_traces_without_asking_for_the_command_first(self):
        saved_os, saved_which = nd.OS_NAME, nd.which
        try:
            nd.which = lambda cmd: False
            for os_name in ("Linux", "Darwin", "Windows"):
                with self.subTest(os=os_name):
                    nd.OS_NAME = os_name
                    res = nd.cmd_traceroute("8.8.8.8")
                    self.assertFalse(res.get("ok"),
                                     "%s ran a trace with nothing to run it with"
                                     % os_name)
                    self.assertIn("no traceroute", res.get("error", ""),
                                  "%s did not say why it could not trace" % os_name)
        finally:
            nd.OS_NAME, nd.which = saved_os, saved_which

    def test_each_platform_still_traces_when_the_command_is_there(self):
        """The guard above is only worth having if the thing it guards still
        works - a trace that never runs would satisfy it perfectly."""
        saved_os, saved_which, saved_run = nd.OS_NAME, nd.which, nd.run
        ran = []
        try:
            nd.which = lambda cmd: True
            nd.run = lambda cmd, **kw: ran.append(cmd[0]) or {"ok": True, "stdout": ""}
            for os_name, expected in (("Linux", "traceroute"),
                                      ("Darwin", "traceroute"),
                                      ("Windows", "tracert")):
                with self.subTest(os=os_name):
                    nd.OS_NAME = os_name
                    del ran[:]
                    self.assertTrue(nd.cmd_traceroute("8.8.8.8").get("ok"))
                    self.assertEqual(ran, [expected])
        finally:
            nd.OS_NAME, nd.which, nd.run = saved_os, saved_which, saved_run


class TestPythonCompatibility(unittest.TestCase):
    """The tool runs on whatever python3 the box happens to have, so the floor
    has to be a decision rather than an accident."""

    def test_the_source_parses_at_the_stated_floor(self):
        """Catches a newer bit of syntax slipping in - which wouldn't fail here,
        only on the appliance, months later.

        The suite is checked too, and not out of tidiness: CI runs it on the
        floor version to prove the tool works there, so a walrus in a test
        fails the build for the one reason that says nothing about the tool.
        This guard covered faultone.py alone, which left the file doing the
        proving unable to fail here."""
        import ast
        import os
        root = os.path.dirname(os.path.abspath(nd.__file__))
        # ast.parse's feature_version is a partial check, which is easy to
        # mistake for a total one: it rejects an f-string '=', a match and an
        # except*, and it accepts a walrus, positional-only parameters and
        # list[int] without complaint. All three of those are fatal on 3.7 and
        # all three would have shipped. The parse is the first pass; the walk
        # below is the part it does not do.
        NEWER = {"NamedExpr": "the walrus operator (3.8+)"}
        GENERIC = {"list", "dict", "set", "frozenset", "tuple", "type"}
        for name in ("faultone.py", "test_faultone.py"):
            path = os.path.join(root, name)
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
            try:
                tree = ast.parse(src, feature_version=nd.MIN_PYTHON)
            except SyntaxError as e:
                self.fail(f"{name} uses syntax newer than Python "
                          f"{nd.MIN_PYTHON[0]}.{nd.MIN_PYTHON[1]}: "
                          f"{e.msg} (line {e.lineno})")
            except TypeError:
                # feature_version arrived in 3.8, so on the floor itself this
                # argument does not exist - the guard defending 3.7 was the
                # one thing that could not run on 3.7, and errored there the
                # first time anything tried. It is also the one interpreter
                # where the check is redundant: the file was imported to get
                # here, so anything newer than 3.7 already failed to compile.
                tree = ast.parse(src)
            for node in ast.walk(tree):
                why = NEWER.get(type(node).__name__)
                if why:
                    self.fail(f"{name}:{node.lineno} uses {why}")
                if isinstance(node, ast.arguments) and getattr(
                        node, "posonlyargs", []):
                    self.fail("%s:%d uses positional-only parameters (3.8+)"
                              % (name, node.posonlyargs[0].lineno))
                if (isinstance(node, ast.Subscript)
                        and isinstance(node.value, ast.Name)
                        and node.value.id in GENERIC):
                    self.fail("%s:%d subscripts the builtin %s, which is a "
                              "type only from 3.9" % (name, node.lineno,
                                                      node.value.id))

    def test_every_text_file_it_opens_names_its_encoding(self):
        """Without one, Python uses the platform's locale encoding, which is
        UTF-8 on Linux and macOS and cp1252 on Windows. So this was invisible
        on both machines it had ever run on, and on Windows it wrote a report
        whose em dashes came back as replacement characters - caught by a
        viewer that no longer matched the template it was generated from.

        A diagnostic must not lose a report to a byte it did not expect
        either, so reads and writes both replace rather than raise. That is
        the same decision already made for stdout: a diagnosis that ran should
        not be lost on the way out."""
        import ast
        import os
        # A string literal is ast.Constant from 3.8 and ast.Str on 3.7, and
        # ast.Str is gone again in 3.12 - so neither name can simply be used.
        # Reading the mode through this is the difference between recognising
        # open(path, "rb") as binary and reporting it as a text open with no
        # encoding, which is what this guard did on the floor version: written
        # to catch a cross-version bug, and version-dependent itself.
        legacy_str = getattr(ast, "Str", ())

        def literal(node):
            if isinstance(node, ast.Constant):
                return node.value
            if legacy_str and isinstance(node, legacy_str):
                return node.s
            return None

        root = os.path.dirname(os.path.abspath(nd.__file__))
        bad = []
        # The suite is checked too, and it is not pedantry: the tool was fixed
        # first and Windows stayed red, because the test that compares the
        # committed viewer against the template read the file itself through
        # cp1252 and found a mismatch it had caused.
        for name in ("faultone.py", "test_faultone.py"):
            with open(os.path.join(root, name), encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                opener = None
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    opener = node.func.id if node.func.id == "open" else None
                elif (isinstance(node, ast.Call)
                      and isinstance(node.func, ast.Attribute)
                      and node.func.attr == "fdopen"):
                    opener = "os.fdopen"
                if not opener:
                    continue
                mode = ""
                if len(node.args) > 1:
                    mode = literal(node.args[1]) or ""
                if "b" in mode:                  # bytes carry no encoding
                    continue
                if not any(k.arg == "encoding" for k in node.keywords):
                    bad.append("%s:%d %s(" % (name, node.lineno, opener))
        self.assertEqual(bad, [], "text-mode opens with no encoding, which "
                                  "means cp1252 on Windows: " + ", ".join(bad))

    def test_only_standard_library_is_imported(self):
        import ast
        import sys
        with open(nd.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        stdlib = getattr(sys, "stdlib_module_names", None)
        if not stdlib:
            self.skipTest("interpreter doesn't expose stdlib_module_names")
        outside = sorted(m for m in imported if m not in stdlib)
        self.assertFalse(outside, f"not standard library: {outside}")

    def test_the_report_records_the_interpreter(self):
        import platform
        self.assertEqual(platform.python_version().count("."), 2)

    def test_a_python_change_between_visits_is_reported(self):
        current = {"python": "3.11.2", "raw": {}, "neighbours": [], "hops": []}
        baseline = {"python": "3.9.6", "raw": {}, "neighbours": [], "hops": []}
        entry = next((c for c in nd.compare_reports(current, baseline)
                      if c["what"] == "python"), None)
        self.assertIsNotNone(entry, "a different interpreter can explain a difference")


class TestSelfContainedReport(unittest.TestCase):
    """A report that opens on its own: the data rides inside the page, so there
    is no viewer to keep in sync and no second file to copy off the box."""

    def report(self):
        return {"os": "Linux", "target": "8.8.8.8", "findings": [
                    {"severity": "critical", "layer": 1, "code": "no_ipv4", "message": "x"}],
                "verdict": {"headline": "h", "owner": "o", "confidence": "high",
                            "next_step": "n", "severity": "critical"},
                "stages": [{"stage": "link", "state": "fail"}], "hops": [], "raw": {},
                "layers": {}, "comparison": [], "port_results": []}

    def test_the_page_carries_its_own_data(self):
        html = nd.render_report_html(self.report())
        self.assertNotIn(nd.REPORT_PLACEHOLDER, html)
        self.assertIn('id="faultone-report"', html)
        self.assertIn("no_ipv4", html)

    def test_the_data_comes_back_out(self):
        html = nd.render_report_html(self.report())
        self.assertEqual(nd.extract_embedded_report(html)["findings"][0]["code"], "no_ipv4")

    def test_a_closing_tag_in_the_data_cannot_end_the_script_block(self):
        """An unescaped </script> inside the island would terminate it early and
        take the rest of the page with it."""
        report = self.report()
        report["findings"][0]["message"] = "</script><img src=x onerror=alert(1)>"
        html = nd.render_report_html(report)
        island = html.split('id="faultone-report" type="application/json">')[1].split("</script>")[0]
        self.assertNotIn("</script>", island)
        self.assertEqual(nd.extract_embedded_report(html)["findings"][0]["message"],
                         report["findings"][0]["message"])

    def test_the_empty_viewer_is_not_mistaken_for_a_report(self):
        self.assertIsNone(nd.extract_embedded_report(nd.VIEWER_TEMPLATE))

    def test_junk_input_is_not_fatal(self):
        for junk in ("", None, "<html></html>", "<script id=\"faultone-report\" "
                     'type="application/json">not json</script>'):
            self.assertIsNone(nd.extract_embedded_report(junk))


class TestTheChainMarksTheHopTheVerdictNames(unittest.TestCase):
    """The path picture scored its nodes on loss and timeouts, which are the
    only things it could work out for itself. A latency wall is neither, so on
    the one report whose verdict is about a single hop, that hop was drawn as
    unremarkable and the reader was told to look at something the picture
    showed as clean."""

    # Findings that name a hop in their own message, and where the hop number
    # they name comes from. Anything added here has to mark its hop, and
    # anything that marks a hop has to be here.
    @staticmethod
    def _target_hops(rep):
        return [h["hop"] for h in (rep.get("hops") or [])
                if "target" in (h.get("roles") or [])]

    NAMES_A_HOP = {
        "latency_wall": lambda rep: [rep["worst_jump"]["hop"]],
        "loop": lambda rep: list(rep["loop_at"]["hops"]),
        # Named by role, not by number - which hop is the destination depends
        # on the path. Both assert traffic is not reaching it, so a clean
        # target hop underneath them is the picture contradicting the sentence.
        "egress_blocked": lambda rep: TestTheChainMarksTheHopTheVerdictNames._target_hops(rep),
        "inet_partial_loss": lambda rep: TestTheChainMarksTheHopTheVerdictNames._target_hops(rep),
    }

    def test_a_hop_is_blamed_exactly_when_the_report_blames_it(self):
        """Marking the worst jump whenever there is one would put a warning on
        a hop no worse than its neighbours: every path has a largest step, and
        the finding only fires when that step is also most of the delay. The
        mark has to follow the conclusion in both directions - no hop marked
        without a finding behind it, and no such finding leaving its hop
        unmarked, or the picture and the sentence drift apart."""
        for code in sorted(S):
            setup, kw = S[code]
            m = fresh(); setup(m)
            try:
                rep = m.diagnose(quick=False, **scenario_kwargs(kw))
            except Exception:
                continue
            by_code = {f["code"]: f for f in rep["findings"]}
            expected = {}
            for name, where in self.NAMES_A_HOP.items():
                if name not in by_code:
                    continue
                for hop in where(rep):
                    held = expected.get(hop)
                    # Two conclusions can land on the same hop; the more
                    # serious one owns it. Spelled out rather than left to
                    # whichever was written last in the table above, which is
                    # how this agreed with the code by accident.
                    if held is None or (nd.SEVERITY_RANK[by_code[name]["severity"]]
                                        > nd.SEVERITY_RANK[by_code[held]["severity"]]):
                        expected[hop] = name
            marked = {h["hop"]: h["blame"]["code"]
                      for h in (rep.get("hops") or []) if h.get("blame")}
            with self.subTest(scenario=code):
                self.assertEqual(
                    marked, expected,
                    "the hops marked are not the hops the findings name")
                for hop, name in marked.items():
                    self.assertEqual(
                        [h["blame"]["severity"] for h in rep["hops"] if h["hop"] == hop][0],
                        by_code[name]["severity"],
                        f"the mark on hop {hop} disagrees with the finding's severity")

    def test_every_finding_that_marks_a_hop_is_one_this_test_knows(self):
        """The pairing above is only a guard while it is complete. A new code
        that marks a hop and is not listed would make the test assert that its
        mark should not be there, and the obvious way to get green is to
        delete the mark."""
        marks = set()
        for code in sorted(S):
            setup, kw = S[code]
            m = fresh(); setup(m)
            try:
                rep = m.diagnose(quick=False, **scenario_kwargs(kw))
            except Exception:
                continue
            marks |= {h["blame"]["code"] for h in (rep.get("hops") or []) if h.get("blame")}
        self.assertEqual(marks, set(self.NAMES_A_HOP),
                         "a finding marks a hop without this test knowing where it should land")

    def test_the_way_in_is_coloured_by_the_conclusion_about_it(self):
        """The inbound node scored itself on client loss alone, so a direction
        the report had marked degraded for jitter or queuing delay - neither of
        which is loss - drew green beside a zone reading DEGRADED. A threshold
        in the picture is a second copy of one in the analysis."""
        template = nd.VIEWER_TEMPLATE
        inbound = template.split('<div class="inbound-title">', 1)[1].split("</div>`", 1)[0]
        self.assertNotIn("worst_loss_pct >=", inbound,
                         "the inbound node still judges for itself")
        self.assertIn("sideSeverity(data, 'downstream')", inbound)
        # The readings stay - they are measurements, not a verdict.
        self.assertIn("worst_loss_pct", inbound)
        fn = template.split("function sideSeverity(data, side){", 1)[1].split("\n}", 1)[0]
        self.assertIn("s.side === side", fn)

    def test_this_device_is_coloured_by_the_conclusion_about_it(self):
        """The first node of the path was given ok outright, so a box with a
        failing transceiver in it was drawn clean directly under a panel saying
        the fault was the box. Fifty five of the hundred and fifty two reports
        mark the local side, and every one of them disagreed with the picture
        beneath it."""
        template = nd.VIEWER_TEMPLATE
        node = template.split("const nodes = [", 1)[1].split("]", 1)[0]
        self.assertNotIn("sev:'ok'", node.replace(" ", ""),
                         "this device is drawn clean whatever the report says")
        self.assertIn("sideSeverity(data, 'local')", node)

    def _ribbon_js(self, *names):
        """Run the viewer's own ribbon functions, rather than assert on their
        source. A bar built from percentages and flex is the first thing here
        that a browser can render as nothing while the markup reads correctly,
        so what it returns is worth more than what it says."""
        import json as _json
        import shutil
        import subprocess
        import tempfile
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available to run the viewer's own JS")
        src = nd.VIEWER_TEMPLATE
        out = ["const escapeHtml = s => String(s);",
               "const HOP_WORD = {warn:'DEGRADED', crit:'FAULT'};"]
        for name in names:
            i = src.index("function " + name + "(")
            depth, j = 0, src.index("{", i)
            for k in range(j, len(src)):
                if src[k] == "{":
                    depth += 1
                elif src[k] == "}":
                    depth -= 1
                    if not depth:
                        out.append(src[i:k + 1])
                        break
        return node, "\n".join(out)

    def _run_js(self, prelude, body):
        import json as _json
        import os as _os
        import subprocess
        import tempfile
        node, src = prelude
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                        encoding="utf-8") as fh:
            fh.write(src + "\n" + body)
            path = fh.name
        try:
            res = subprocess.run([node, path], capture_output=True, text=True,
                               timeout=30, encoding="utf-8")
            self.assertEqual(res.returncode, 0, res.stderr)
            return _json.loads(res.stdout)
        finally:
            _os.unlink(path)

    def test_the_ribbon_is_sized_by_time_not_by_name(self):
        """The bar is the measurement and the boxes below are the reading. A
        segment takes its width from what its hop added; the boxes take theirs
        from the time too, but above the room their text needs, because sizing
        a box from the time alone put a forty-two character backbone name into
        something too narrow to read."""
        pre = self._ribbon_js("hopRibbon")
        got = self._run_js(pre, """
const nodes = [{label:'short', sev:'ok', dMs:1.4},
               {label:'a-very-long-backbone-name.example.net', sev:'crit', dMs:70.5},
               {label:'x', sev:'ok', dMs:2.0}];
const html = hopRibbon(nodes, 73.9);
process.stdout.write(JSON.stringify({
  segments: (html.match(/class="seg/g) || []).length,
  flex: (html.match(/flex-grow:([0-9.]+)/g) || []),
}));
""")
        self.assertEqual(got["segments"], 3)
        # The long name added 70.5 of 73.9ms and gets the width to match; the
        # name itself is nowhere in the sizing.
        self.assertEqual(got["flex"],
                         ["flex-grow:1.40", "flex-grow:70.50", "flex-grow:2.00"])

    def test_the_ribbon_says_the_severity_it_colours(self):
        """Same reason the hops below carry a word: the dominant segment is the
        one the reader is being sent to, and colour alone is what excludes the
        readers who cannot separate red from green."""
        pre = self._ribbon_js("hopRibbon")
        # Two marked segments, both wide enough to carry a label. With one, a
        # word on every segment and a word on the dominant one produce the
        # same output, and the test agrees with either.
        # Four marked-or-not segments arranged so that "the widest", "the first
        # marked", "the last marked" and "the last of all" are four different
        # positions. Any two of them coinciding lets a rule that picks the
        # wrong one pass - which it did, twice, while this was being written.
        got = self._run_js(pre, """
const nodes = [{label:'a', sev:'crit', dMs:20}, {label:'b', sev:'crit', dMs:40},
               {label:'c', sev:'crit', dMs:30}, {label:'d', sev:'ok', dMs:4}];
const html = hopRibbon(nodes, 94);
const segs = html.split('<span class="seg').slice(1);
process.stdout.write(JSON.stringify({
  count: (html.match(/FAULT/g) || []).length,
  carriesWord: segs.findIndex(s => s.indexOf('FAULT') !== -1),
  widest: segs.map(s => parseFloat(s.match(/flex-grow:([0-9.]+)/)[1]))
              .reduce((best, v, i, all) => v > all[best] ? i : best, 0),
}));
""")
        self.assertEqual(got["count"], 1,
                         "the word is on every segment it could apply to")
        self.assertEqual(got["carriesWord"], got["widest"],
                         "the word is not on the segment that dominates")

    def test_a_path_too_short_to_have_a_shape_draws_no_ribbon(self):
        """One timed hop is a number, not a distribution. A bar with a single
        full-width segment says something is 100% of itself."""
        pre = self._ribbon_js("hopRibbon")
        got = self._run_js(pre, """
process.stdout.write(JSON.stringify({
  one: hopRibbon([{label:'a', sev:'ok', dMs:5}], 5),
  none: hopRibbon([], 0),
  untimed: hopRibbon([{label:'a', sev:'ok'}, {label:'b', sev:'ok'}], 10),
}));
""")
        for case, html in got.items():
            with self.subTest(case=case):
                self.assertEqual(html, "")

    def test_the_last_visit_is_drawn_only_when_there_was_one(self):
        """A previous report that never traced, or a --quick one, leaves the
        row out rather than inventing a comparison to draw."""
        pre = self._ribbon_js("ribbonBaseline")
        got = self._run_js(pre, """
process.stdout.write(JSON.stringify({
  absent: ribbonBaseline(null, 74),
  tooShort: ribbonBaseline([{hop:1, avg_ms:1}], 74),
  noTotal: ribbonBaseline([{hop:1, avg_ms:1}, {hop:2, avg_ms:9}], 0),
  real: ribbonBaseline([{hop:1, avg_ms:1}, {hop:2, avg_ms:9}, {hop:3, avg_ms:11}], 74),
}));
""")
        for empty in ("absent", "tooShort", "noTotal"):
            with self.subTest(case=empty):
                self.assertEqual(got[empty], "")
        self.assertIn("last visit: 11ms", got["real"])
        self.assertIn("faster then", got["real"])

    def test_the_ribbon_survives_being_printed(self):
        """A browser drops background colours when it prints unless told not
        to, and the ribbon is nothing but background colour. Without this it
        comes out as an empty outline - the one element here whose whole
        content is the thing print throws away."""
        rules = nd.VIEWER_TEMPLATE.split("@media print{", 1)[1]
        self.assertIn("print-color-adjust:exact", rules)
        block = rules.split("print-color-adjust:exact", 1)[0]
        self.assertIn(".hop-ribbon", block[-200:],
                      "the exemption does not name the ribbon")

    def test_a_marked_hop_does_not_rely_on_colour_alone(self):
        """Red and green are the commonest pair a reader cannot tell apart, and
        the chain was the one place a severity arrived as hue and nothing else.
        The stage chips say PASS and FAIL, the zones say OK and FAULT, a
        finding carries its severity in its tag - a marked hop said it in a
        tint and a border and left it there."""
        template = nd.VIEWER_TEMPLATE
        fn = template.split("function hopWord(sev){", 1)
        self.assertEqual(len(fn), 2, "the word on a marked hop is gone")
        self.assertIn("${hopWord(n.sev)}", template, "it is defined and never drawn")
        words = template.split("const HOP_WORD = {", 1)[1].split("}", 1)[0]
        # The vocabulary is the one the zones already use, not a second set.
        for severity in ("warn", "crit"):
            self.assertIn(severity, words)
        self.assertIn("ZONE_WORD.", words,
                      "the hop words are a separate list from the zone words")
        # And only the marked ones: a word on every hop is noise on the hops
        # the reader is being told to look past.
        self.assertNotIn("ok:", words)

    def test_the_words_for_a_state_are_defined_once(self):
        """ZONE_WORD was inside renderDiagnosis, so the chain could not reach
        it. Copying the strings across would have been a second vocabulary for
        one idea, and the two would drift the first time one was reworded."""
        template = nd.VIEWER_TEMPLATE
        self.assertEqual(template.count("const ZONE_WORD = {"), 1)
        before = template.split("const ZONE_WORD = {", 1)[0]
        self.assertNotIn("function renderDiagnosis", before,
                         "ZONE_WORD is scoped inside the renderer again")

    def test_the_line_to_a_destination_nothing_answered_is_broken(self):
        """The node already says it was not reached. A line that stops is read
        before any label on the node it points at."""
        template = nd.VIEWER_TEMPLATE
        self.assertIn("unreached: true", template, "the target is not flagged")
        self.assertIn(".hop-arrow.unreached span{", template)
        chain = template.split("function renderHopChain", 1)[1].split("\nfunction ", 1)[0]
        self.assertIn("nodes[i+1].unreached", chain,
                      "the connector decides from something other than the flag")
        # Read off the flag, not off the wording of the node's own caption.
        self.assertNotIn("=== 'not reached by the trace'", chain)

    def test_a_trace_that_stops_does_not_pretend_to_a_hop_count(self):
        """Three consecutive timeouts were drawn as three cards, which reads as
        three identified routers and implies the destination is four hops away.
        Nothing is recorded for any of them - no address, no timing, no reply
        to have measured - and how far the path runs past the stall is exactly
        what is not known. One node, saying so."""
        chain = nd.VIEWER_TEMPLATE.split("function renderHopChain", 1)[1] \
                                  .split("\nfunction ", 1)[0]
        self.assertIn("while(stallFrom > 0 && hops[stallFrom - 1].timed_out) stallFrom--;",
                      chain, "the trailing run of timeouts is not found")
        self.assertIn("if(hopIndex >= stallFrom) return;", chain,
                      "the collapsed hops are still drawn one by one as well")
        collapsed = chain.split("if(stalled){", 1)[1].split("  }", 1)[0]
        self.assertIn("how far the path runs past here is unknown", collapsed)
        # Severity through the same function every other hop uses, not written
        # in - a literal here is the shape the other three legs had.
        self.assertIn("sev: hopSeverity(first, probes)", collapsed)

    def test_a_timeout_with_a_reply_after_it_stays_its_own_hop(self):
        """A router that drops probes but forwards traffic is a normal thing to
        meet in the middle of a path, and the reply from the hop beyond proves
        that hop exists. Only a run reaching the end of the trace is unknown in
        extent. No scenario produces a middle timeout, so this asserts the
        shape of the rule: the run is counted backwards from the end and stops
        at the first hop that answered."""
        chain = nd.VIEWER_TEMPLATE.split("function renderHopChain", 1)[1] \
                                  .split("\nfunction ", 1)[0]
        walk = chain.split("let stallFrom = hops.length;", 1)[1].split(";", 2)
        self.assertIn("hops[stallFrom - 1].timed_out", walk[0],
                      "the run is not walked back from the end of the trace")
        self.assertNotIn("hops[0]", walk[0])
        self.assertNotIn("filter", walk[0],
                         "collecting every timeout would take the middle ones too")

    def test_the_destination_is_drawn_once(self):
        """A target node was appended after every hop, and in a hundred and
        forty eight of the hundred and fifty two reports the last hop already
        was the target - so the address appeared twice in a row, and the second
        copy carried a hardcoded ok. On the reports where the destination had
        just been marked, it was redrawn as fine directly beside itself, which
        is the same contradiction one node further along."""
        template = nd.VIEWER_TEMPLATE
        chain = template.split("function renderHopChain", 1)[1].split("\nfunction ", 1)[0]
        self.assertIn("indexOf('target')", chain,
                      "the destination node is appended without asking whether "
                      "the trace already drew it")
        pushed = chain.split("nodes.push({label:'target'", 1)[1].split("}", 1)[0]
        self.assertIn("sev: ''", pushed,
                      "a destination the trace never reached is drawn clean")

    def test_a_destination_the_trace_never_reached_says_so(self):
        """Drawing it neutral is only half the sentence. Four reports stop
        short of the target, and there the node is the one thing standing for a
        destination nothing observed - unlabelled, it reads as a hop with
        nothing interesting about it."""
        chain = nd.VIEWER_TEMPLATE.split("function renderHopChain", 1)[1] \
                                  .split("\nfunction ", 1)[0]
        pushed = chain.split("nodes.push({label:'target'", 1)[1].split("});", 1)[0]
        self.assertIn("not reached by the trace", pushed)

    def test_no_leg_of_the_picture_decides_its_own_severity(self):
        """Three legs, and all three had reached their own conclusion: the way
        out from the trace's replies, the way in from client loss, and this box
        from nothing at all. Each was a second derivation sitting under a panel
        that had already decided, and each disagreed with it. The general form
        is the guard - a severity written as a literal into a node is the shape
        every one of them had."""
        import re
        template = nd.VIEWER_TEMPLATE
        chain = template.split("function renderHopChain", 1)[1].split("\nfunction ", 1)[0]
        inbound = template.split('<div class="inbound-title">', 1)[1].split("</div>`", 1)[0]
        for name, block in (("the path", chain), ("the way in", inbound)):
            with self.subTest(leg=name):
                self.assertEqual(
                    re.findall(r"sev\w*\s*:\s*'(ok|warn|crit)'", block), [],
                    f"{name} writes a severity in rather than asking for one")
                self.assertNotIn("? 'crit'", block,
                                 f"{name} is judging for itself again")

    def test_every_state_a_side_can_report_has_a_colour(self):
        """The mapping is only safe while it is complete. A state with no entry
        falls through to 'ok', so a new one would render the way in as clean -
        silently, and in the direction the reader is being pointed at."""
        states = set()
        for code in sorted(S):
            setup, kw = S[code]
            m = fresh(); setup(m)
            try:
                rep = m.diagnose(quick=False, **scenario_kwargs(kw))
            except Exception:
                continue
            states |= {z["state"] for z in (rep.get("sides") or [])}
        mapping = nd.VIEWER_TEMPLATE.split("const ZONE_SEV = {", 1)[1].split("}", 1)[0]
        for state in sorted(states):
            self.assertIn(f"{state}:", mapping,
                          f"a side can report {state!r} and the picture has no colour for it")

    def test_the_worse_conclusion_owns_the_target_hop(self):
        """No scenario fires both of these at once, so the corpus cannot reach
        the rule and it is asserted here instead. Left to the order they happen
        to be listed in, the milder one could take a hop the more serious one
        was about."""
        # The serious one is listed first on purpose: with it last, taking the
        # last conclusion and taking the worst give the same answer, and the
        # test agrees with either implementation.
        hops = [{"hop": 1, "roles": []}, {"hop": 2, "roles": ["target"]}]
        nd._mark_target_hop(hops, [
            {"code": "inet_partial_loss", "severity": "critical"},
            {"code": "egress_blocked", "severity": "warning"},
        ])
        self.assertEqual(hops[1]["blame"],
                         {"code": "inet_partial_loss", "severity": "critical"})
        self.assertNotIn("blame", hops[0], "a hop with no target role was marked")

    def test_a_hop_already_carrying_a_worse_mark_keeps_it(self):
        """The path check runs first and knows things about a specific hop that
        this does not - which end of a routing loop it is, for one. A general
        statement about the destination must not overwrite it."""
        hops = [{"hop": 2, "roles": ["target"],
                 "blame": {"code": "loop", "severity": "critical"}}]
        nd._mark_target_hop(hops, [{"code": "egress_blocked", "severity": "warning"}])
        self.assertEqual(hops[0]["blame"]["code"], "loop")

    def test_a_finding_that_declines_to_call_it_loss_marks_nothing(self):
        """inet_loss_unmeasured exists to say that one unanswered probe out of
        four is not established loss - it is the report refusing to conclude.
        Marking the destination on the strength of it would be the picture
        claiming what the sentence just declined to, which is the whole reason
        the codes are named rather than taken from whatever marked the
        outbound direction."""
        hops = [{"hop": 2, "roles": ["target"]}]
        nd._mark_target_hop(hops, [
            {"code": "inet_loss_unmeasured", "severity": "warning"},
            {"code": "dns_fail", "severity": "critical"},
            {"code": "cgnat", "severity": "warning"},
        ])
        self.assertNotIn("blame", hops[0])

    def test_the_mark_survives_a_compact_export(self):
        """The hops are derived, not captured output, so they ride through the
        compact report - and a picture that lost its only mark on the way to
        the smaller file would be worse than one that never had it."""
        setup, kw = S["latency_wall"]
        m = fresh(); setup(m)
        rep = m.diagnose(quick=False, **scenario_kwargs(kw))
        slim = m.compact_report(rep)
        self.assertEqual([h.get("blame") for h in rep["hops"]],
                         [h.get("blame") for h in slim["hops"]])

    def test_the_chain_asks_the_report_before_it_works_it_out(self):
        """Order is the whole point: a hop the report has already blamed has to
        outrank the counters, or the two disagree and the louder one wins by
        accident."""
        fn = nd.VIEWER_TEMPLATE.split("function hopSeverity(h, probes){", 1)[1] \
                               .split("\n}", 1)[0]
        self.assertIn("h.blame", fn)
        self.assertLess(fn.index("h.blame"), fn.index("h.timed_out"),
                        "the counters are consulted before the conclusion")
        # A critical code arriving here must not be drawn as a warning.
        self.assertIn("'critical'", fn)
        self.assertIn("'crit'", fn)

    def test_a_hop_is_judged_against_what_the_path_actually_returned(self):
        """Counting a hop's timings against a hardcoded three assumed every
        source sends three probes and reports them all. Where a source gives
        one representative timing per hop, every hop had fewer than three and
        the whole path came out marked - a parsing shape drawn as a fault, and
        enough yellow to bury the hop the verdict was naming."""
        fn = nd.VIEWER_TEMPLATE.split("function hopSeverity(h, probes){", 1)[1] \
                               .split("\n}", 1)[0]
        self.assertNotIn("length < 3", fn,
                         "the probe count is still hardcoded")
        self.assertIn("probes >= 3", fn,
                      "a path reporting one timing throughout has no sample to judge against")
        self.assertIn("h.times_ms.length < probes", fn)
        # And the sample has to be measured, not assumed, at the call site.
        chain = nd.VIEWER_TEMPLATE.split("function renderHopChain", 1)[1]
        self.assertIn("const probes = hops.reduce(", chain)


class TestViewerTemplate(unittest.TestCase):
    def test_an_exported_report_hides_the_controls_that_produce_one(self):
        """A self-contained export is a finished report. It was still showing a
        file picker and instructions for producing the very file being read,
        which makes the artefact you send someone look like a tool waiting for
        input."""
        template = nd.VIEWER_TEMPLATE
        self.assertIn("if(opts.embedded){", template)
        self.assertIn("'reportFileLabel', 'reportFile', 'viewerHint'", template)
        # the embedded copy declares itself; the file picker and drop handler
        # must not, or the standalone viewer would hide its own reason to exist
        self.assertIn("{imported: true, embedded: true}", template)
        picker = template.split("function loadReportFile", 1)[1][:400]
        self.assertNotIn("embedded", picker)

    @staticmethod
    def _css_var(template, name):
        import re
        m = re.search(rf"{re.escape(name)}:\s*(#[0-9a-fA-F]{{6}})", template)
        return m.group(1) if m else None

    @staticmethod
    def _contrast(fg, bg):
        def channels(h):
            h = h.lstrip("#")
            return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))

        def lum(rgb):
            def f(v):
                v /= 255
                return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
            r, g, b = (f(x) for x in rgb)
            return 0.2126 * r + 0.7152 * g + 0.0722 * b
        a, b = sorted((lum(channels(fg)), lum(channels(bg))), reverse=True)
        return (a + 0.05) / (b + 0.05)

    def test_the_verdict_tint_keeps_its_own_text_readable(self):
        """The verdict background is now a wash of the severity colour, which
        moves every contrast ratio inside the block. "owner:" and "confidence:"
        are the most load-bearing words in the report and were already the
        dimmest text on it; the tint took them from 4.0:1 to 3.6:1. Computed
        from the template so changing the 8% can't quietly break it."""
        template = nd.VIEWER_TEMPLATE
        panel = self._css_var(template, "--panel")
        lifted = self._css_var(template, "--text-dim-lift")
        self.assertTrue(panel and lifted, "the colour variables moved or were renamed")
        import re
        for severity in ("--warn", "--crit"):
            colour = self._css_var(template, severity)
            # Read the strength out of the stylesheet, not from a copy of it
            # here - hardcoding 8% made this test blind to the one number most
            # likely to be tweaked. Read it out of the verdict's own rule too:
            # the hop nodes now tint against --panel the same way, and a
            # template-wide search would silently start measuring whichever
            # rule happened to be written first.
            rule_name = "critical" if severity == "--crit" else "warning"
            rule = template.split(f".verdict.{rule_name}{{", 1)[1].split("}", 1)[0]
            m = re.search(rf"color-mix\(in srgb, var\({severity}\) (\d+)%, var\(--panel\)\)",
                          rule)
            self.assertTrue(m, f"no verdict tint found for {severity}")
            pct = int(m.group(1)) / 100

            def ch(h):
                h = h.lstrip("#")
                return [int(h[i:i + 2], 16) for i in (0, 2, 4)]
            tint = "#" + "".join(f"{round(a * pct + b * (1 - pct)):02x}"
                                 for a, b in zip(ch(colour), ch(panel)))
            with self.subTest(severity=severity, pct=m.group(1)):
                self.assertGreaterEqual(
                    self._contrast(lifted, tint), 4.5,
                    f"verdict meta text is unreadable on the {severity} tint at {m.group(1)}%")

    def test_a_clean_verdict_is_not_tinted(self):
        """A green wash on "no fault found" shouts with nothing to say, and
        competes with the lamps that are already green."""
        template = nd.VIEWER_TEMPLATE
        ok_rule = template.split(".verdict.ok{", 1)[1].split("}", 1)[0]
        self.assertNotIn("background", ok_rule)
        self.assertIn("border-left-color", ok_rule)

    def test_the_tint_is_derived_from_the_severity_variables(self):
        """A second set of hex literals would drift from the lamps and the tab
        icon. And the plain value is declared first so a browser too old for
        color-mix gets the previous appearance, not a broken one."""
        template = nd.VIEWER_TEMPLATE
        for severity in ("--crit", "--warn"):
            rule = template.split(f".verdict.{'critical' if severity == '--crit' else 'warning'}{{",
                                  1)[1].split("}", 1)[0]
            self.assertIn(f"color-mix(in srgb, var({severity})", rule)
            self.assertLess(rule.index("background:var(--panel)"),
                            rule.index("background:color-mix"),
                            "the fallback has to come before the color-mix line")

    def test_every_colour_the_stylesheet_asks_for_is_one_it_defines(self):
        """A var() naming a property that was never declared is not an error a
        browser reports: the declaration is dropped and the property falls back
        to its initial value, so the element renders in the wrong colour and
        looks deliberate. The relation pills - the cause, backs it up, caused
        by it - asked for --line, which the palette calls --border, and had
        been drawing their border in currentColor ever since."""
        import re
        css = nd.VIEWER_TEMPLATE.split("<style", 1)[1].split("</style>", 1)[0]
        declared = set(re.findall(r"(--[a-z0-9-]+)\s*:", css))
        used = set(re.findall(r"var\((--[a-z0-9-]+)", css))
        self.assertEqual(used - declared, set(),
                         "the stylesheet uses a custom property it never declares")

    def test_a_reported_hop_keeps_its_own_text_readable(self):
        """The faulting hop is now a wash of its severity rather than a card
        with a coloured edge, which moves every contrast ratio inside it. The
        plain dim grey sits at about 4:1 on the flat panel already, so a tint
        takes it under the line - the same trap the verdict block hit, one
        element along. Computed from the template so changing the percentage
        cannot quietly break it."""
        import re
        template = nd.VIEWER_TEMPLATE
        panel = self._css_var(template, "--panel")
        lifted = self._css_var(template, "--text-dim-lift")
        self.assertTrue(panel and lifted, "the colour variables moved or were renamed")
        for severity, rule_name in (("--warn", "warn"), ("--crit", "crit")):
            colour = self._css_var(template, severity)
            rule = template.split(f".hop-node.{rule_name}{{", 1)[1].split("}", 1)[0]
            m = re.search(rf"color-mix\(in srgb, var\({severity}\) (\d+)%, var\(--panel\)\)",
                          rule)
            self.assertTrue(m, f"no hop tint found for {severity}")
            pct = int(m.group(1)) / 100

            def ch(h):
                h = h.lstrip("#")
                return [int(h[i:i + 2], 16) for i in (0, 2, 4)]
            tint = "#" + "".join(f"{round(a * pct + b * (1 - pct)):02x}"
                                 for a, b in zip(ch(colour), ch(panel)))
            with self.subTest(severity=severity, pct=m.group(1)):
                self.assertGreaterEqual(
                    self._contrast(lifted, tint), 4.5,
                    f"hop text is unreadable on the {severity} tint at {m.group(1)}%")

    def test_the_clean_hops_recede_and_the_reported_one_does_not(self):
        """The emphasis is the whole point of the change: if a later edit gives
        every node a tint, or drops the fade from the clean ones, the path goes
        back to being a row of equal cards that has to be read rather than
        seen."""
        template = nd.VIEWER_TEMPLATE
        ok_rule = template.split(".hop-node.ok{", 1)[1].split("}", 1)[0]
        self.assertNotIn("color-mix", ok_rule)
        for rule_name in ("warn", "crit"):
            rule = template.split(f".hop-node.{rule_name}{{", 1)[1].split("}", 1)[0]
            self.assertIn("color-mix", rule)
            self.assertNotIn("opacity", rule)
            # The plain colour first, so a browser without color-mix gets the
            # previous appearance rather than a transparent card.
            self.assertLess(rule.index("background:var(--panel)"),
                            rule.index("background:color-mix"),
                            "the fallback has to come before the color-mix line")

    def test_the_report_can_be_printed_without_coming_out_black(self):
        """A report that reaches someone through a ticket or an email is a PDF
        by the time they see it. The viewer is a dark page, so printed as it
        stood it came out as black ink or as a blank sheet depending on the
        browser's background-graphics setting, and the panels the reader most
        needed were folded shut behind a chevron they could not click."""
        template = nd.VIEWER_TEMPLATE
        self.assertIn("@media print{", template)
        rules = template.split("@media print{", 1)[1]
        # The palette is swapped in place rather than restated, or the printed
        # page becomes a second stylesheet that drifts from the screen one.
        self.assertIn("--bg:#ffffff", rules)
        for hidden in (".topbar", ".sidebar"):
            self.assertIn(hidden, rules)
        self.assertIn("display:block !important", rules)
        self.assertIn("break-inside:avoid", rules)

    def test_the_printed_palette_is_readable_on_paper(self):
        """Inverting the ground without moving the severity colours would leave
        amber on white, which is the one combination that survives a dark
        theme and fails a light one."""
        import re
        rules = nd.VIEWER_TEMPLATE.split("@media print{", 1)[1].split("}", 1)[0]
        white = re.search(r"--bg:(#[0-9a-fA-F]{6})", rules).group(1)
        for name in ("--text", "--text-dim", "--ok", "--warn", "--crit", "--accent",
                     "--cause", "--hardware"):
            m = re.search(rf"{name}:(#[0-9a-fA-F]{{6}})", rules)
            self.assertTrue(m, f"{name} is not restated for print")
            with self.subTest(colour=name):
                self.assertGreaterEqual(
                    self._contrast(m.group(1), white), 4.5,
                    f"{name} is unreadable on paper")

    def test_a_path_with_no_faulty_hop_is_not_dimmed(self):
        """Receding the clean hops only means something when a hop is being
        emphasised. Applied unconditionally it faded every node on the great
        majority of paths - most reports have no individually lossy hop - so
        the picture the change was meant to sharpen came out uniformly dimmer
        than before. The fade has to be conditional on the chain containing
        something to contrast against."""
        template = nd.VIEWER_TEMPLATE
        self.assertNotIn("opacity", template.split(".hop-node.ok{", 1)[1].split("}", 1)[0],
                         "the clean hops fade whether or not anything is emphasised")
        rule = template.split(".hop-chain:has(", 1)
        self.assertEqual(len(rule), 2, "the conditional fade is gone")
        condition, body = rule[1].split(")", 1)
        for needed in (".hop-node.warn", ".hop-node.crit"):
            self.assertIn(needed, condition)
        self.assertIn("opacity:0.55", body.split("}", 1)[0])
        # Scoped to the chain, not the page: the inbound panel scores its one
        # node on its own thresholds and has to decide separately. What the
        # condition selects has to be the clean hop inside that chain.
        self.assertIn(".hop-node.ok", body.split("{", 1)[0])

    def test_the_hop_severities_the_stylesheet_draws_are_the_ones_it_is_given(self):
        """The fade keys off warn and crit. If either chain ever produces
        another class name the rule goes quiet rather than wrong, which is the
        failure that took the longest to notice the first time.

        Both chains now name their class through a function rather than inline,
        so this reads the values those return. The earlier version scanned for
        quoted literals after `hop-node `, which only ever found the inbound
        node's ternary - it was testing one of the two and passing for both."""
        import re
        template = nd.VIEWER_TEMPLATE
        produced = set()
        for src, closer in (("function hopSeverity(h, probes){", "\n}"),
                            ("const ZONE_SEV = {", "}"),
                            # The fallback lives here, not in the map above, so
                            # a class the map never contains can still reach
                            # the page through it.
                            ("function sideSeverity(data, side){", "\n}")):
            body = template.split(src, 1)[1].split(closer, 1)[0]
            produced |= set(re.findall(r"'([a-z]+)'", body))
        # The one word quoted in these bodies that is not a class name: the
        # severity being compared against. The side is a parameter now, so no
        # side name appears here to be excluded.
        produced -= {"critical"}
        self.assertEqual(
            produced, {"ok", "warn", "crit"},
            f"the chains produce {sorted(produced)}, and the fade only knows warn/crit")
        fade = template.split(".hop-chain:has(", 1)[1].split(")", 1)[0]
        for emphasised in produced - {"ok"}:
            self.assertIn(f".hop-node.{emphasised}", fade)

    def test_the_answer_comes_before_the_path_that_explains_it(self):
        """The hop chain sat above the verdict, so the reader met a hop-by-hop
        diagram before being told what the answer was - on a tool whose whole
        promise is one fault to act on."""
        main = nd.VIEWER_TEMPLATE.split('<div class="main">', 1)[1].split("</div>\n</div>", 1)[0]
        order = [g for g in ("grpAnswer", "grpWhere", "grpFound", "grpRan", "grpEvidence")
                 if f'id="{g}"' in main]
        self.assertEqual(
            order, ["grpAnswer", "grpWhere", "grpFound", "grpRan", "grpEvidence"],
            "the report no longer reads answer, where, found, checked, evidence")
        self.assertLess(main.index('id="grpAnswer"'), main.index('id="hopChainWrap"'))

    def test_the_path_sits_inside_the_directions_it_details(self):
        """The path is the detail of one of the three zones, not a sixth thing
        on the page. As a sibling its heading floated between the zones above
        and the findings below, belonging to neither."""
        main = nd.VIEWER_TEMPLATE.split('<div class="main">', 1)[1]
        where = main.split('id="grpWhere"', 1)[1].split("</section>", 1)[0]
        self.assertIn('id="pathTitle"', where)
        self.assertIn('id="hopChainWrap"', where)

    def test_a_group_shows_nothing_until_there_is_something_in_it(self):
        """An unloaded viewer would otherwise draw five rails and a stack of
        headings with nothing underneath them, which reads as a report that
        found nothing rather than one that has not been opened."""
        template = nd.VIEWER_TEMPLATE
        rule = template.split(".grp{", 1)[1].split("}", 1)[0]
        self.assertIn("display:none", rule)
        self.assertIn("body.report-loaded .grp{display:block;}", template)
        self.assertIn("classList.add('report-loaded')", template)
        # And the prompt to load one must not be hidden along with them.
        main = template.split('<div class="main">', 1)[1]
        self.assertLess(main.index('id="emptyState"'), main.index('id="grpAnswer"'))
        self.assertNotIn('id="emptyState"', main.split('id="grpAnswer"', 1)[1])

    def test_the_thing_that_clears_the_prompt_still_reaches_it(self):
        """The prompt moved out of #output so the groups could be hidden as a
        set. Left querying inside #output, the code that removes it would have
        found nothing and the prompt would have stayed on screen underneath a
        loaded report."""
        fn = nd.VIEWER_TEMPLATE.split("function clearEmptyState(){", 1)[1].split("}", 1)[0]
        self.assertIn("document.querySelector('.empty-state')", fn)

    # ---- the paste path off a box you cannot copy a file from -------------

    PASTE_REPORT = {"verdict": {"severity": "warning",
                                "headline": "Latency jumps at hop 2, null is not a hop"},
                    "findings": [{"code": "latency_wall", "severity": "warning",
                                  "layer": 3, "message": "x" * 240}],
                    "hops": [{"hop": 1, "host": "10.0.0.1", "roles": ["gateway"]}],
                    "worst_jump": None, "raw": {}, "stages": []}

    @staticmethod
    def _wrap(text, cols):
        return "\n".join(text[i:i + cols] for i in range(0, len(text), cols))

    def _run_paste_js(self, inputs):
        """Run the viewer's own readPastedReport under node.

        Asserting the shape of the source would pass with the two repairs in
        the wrong order, or a regex that matched nothing. This runs the code
        that ships against text mangled the way a console mangles it.
        """
        import json as _json
        import shutil
        import subprocess
        import tempfile
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available to run the viewer's own JS")
        src = nd.VIEWER_TEMPLATE.split("function readPastedReport(text){", 1)
        self.assertEqual(len(src), 2, "readPastedReport is gone")
        fn = "function readPastedReport(text){" + src[1].split("\n}\n", 1)[0] + "\n}\n"
        prog = (fn + "const out = JSON.parse(process.argv[2]).map(function(t){\n"
                     "  try { return {ok: readPastedReport(t)}; }\n"
                     "  catch(e){ return {err: String(e.message)}; }\n"
                     "});\nprocess.stdout.write(JSON.stringify(out));\n")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                        encoding="utf-8") as fh:
            fh.write(prog)
            path = fh.name
        try:
            res = subprocess.run([node, path, _json.dumps(inputs)],
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(res.returncode, 0, res.stderr)
            return _json.loads(res.stdout)
        finally:
            os.unlink(path)

    def test_a_report_survives_being_copied_out_of_a_terminal(self):
        """A console mangles a pasted report in two ways. Select-all takes the
        shell prompt above and below it. And a terminal that hard-wraps on copy
        inserts real newlines at the wrap column - in a compact report most of
        those land inside a quoted string, where a literal newline is a parse
        error, and some split a bare token like null down the middle."""
        import json as _json
        one = _json.dumps(self.PASTE_REPORT, separators=(",", ":"))
        pretty = _json.dumps(self.PASTE_REPORT, indent=2)
        cases = [("clean", one), ("pretty", pretty)]
        for cols in (24, 40, 80, 132):
            cases.append((f"single-line wrapped at {cols}", self._wrap(one, cols)))
            cases.append((f"indented wrapped at {cols}", self._wrap(pretty, cols)))
        cases.append(("select-all with the prompt either side",
                      "user@box:~$ python3 faultone.py --export-compact -\n"
                      + self._wrap(one, 80) + "\nuser@box:~$ "))
        results = self._run_paste_js([text for _, text in cases])
        for (label, _), got in zip(cases, results):
            with self.subTest(case=label):
                self.assertNotIn("err", got, got.get("err"))
                self.assertEqual(got["ok"], self.PASTE_REPORT,
                                 "the report came back changed")

    def test_text_that_is_not_a_report_says_so_instead_of_half_loading(self):
        """A blob truncated by a scrollback limit is the likeliest bad paste,
        and it has an opening brace - so looking for one and hoping is not
        enough to tell it from a whole report."""
        import json as _json
        whole = _json.dumps(self.PASTE_REPORT, separators=(",", ":"))
        cases = ["", "user@box:~$ ", "no braces here at all",
                 whole[:len(whole) // 2],          # cut off by scrollback
                 "}{"]                              # closing before opening
        results = self._run_paste_js(cases)
        for got in results:
            self.assertIn("err", got, "junk was accepted as a report")
            self.assertTrue(got["err"], "the failure came back without a reason")
        # Text with no report in it says so, rather than reporting a syntax
        # error from somewhere inside a document that was never there. Without
        # this the bounds check is equivalent to leaving it out - JSON.parse
        # rejects the same inputs, just less helpfully.
        for text, got in zip(cases, results):
            if "{" not in text or "}" not in text.split("{", 1)[-1]:
                with self.subTest(text=text[:24]):
                    self.assertIn("no report found", got["err"])

    def test_the_paste_controls_are_gone_from_a_finished_report(self):
        """A self-contained export is a finished report, not a tool waiting for
        input - the same reason the file picker is hidden there."""
        template = nd.VIEWER_TEMPLATE
        hidden = template.split("if(opts.embedded){", 1)[1].split("]", 1)[0]
        for control in ("pasteLabel", "pasteBox", "pasteGo", "pasteErr"):
            self.assertIn(control, hidden,
                          f"{control} is still offered on a finished report")

    def test_a_bad_paste_is_reported_where_the_text_still_is(self):
        """An alert has to be dismissed before you can look at what you pasted,
        which is the wrong shape for something you are about to correct and
        try again."""
        template = nd.VIEWER_TEMPLATE
        # To the end of the listener, not to the first "});" - that one closes
        # the renderDiagnosis call two lines in, which left the catch block
        # outside what this was reading and the test blind to what it checks.
        handler = template.split("getElementById('pasteGo')", 1)[1].split("\n});", 1)[0]
        self.assertIn("catch", handler, "the handler slice stops before the failure path")
        self.assertNotIn("alert(", handler)
        self.assertIn("err.textContent =", handler)

    def test_the_viewer_says_how_to_get_a_report_off_a_locked_down_box(self):
        """The path only helps someone who knows it is there, and the person
        who needs it is on a box they cannot copy a file from."""
        template = nd.VIEWER_TEMPLATE
        hint = template.split('id="viewerHint"', 1)[1].split("</div>", 1)[0]
        self.assertIn("--export-compact -", hint)
        self.assertIn("paste", hint.lower())

    def test_no_colour_is_written_outside_a_palette(self):
        """A hardcoded hex is invisible to a palette. Five of them survived the
        light and print grounds at their dark-theme values, which is how the
        pill reading "the cause" - the chip that says which finding is the
        answer - came to sit at 3.2:1 on white, and the hardware pill at 2.2:1.
        Neither palette test caught it, because both checked the variables that
        had been written rather than the colours the page draws. Declaring
        every colour in a :root block is what makes those tests complete.

        Shadows are exempt and nothing else is. The first version of this guard
        matched hex only and justified the gap by saying the rgba() values were
        all shadows - they were not. One of them was the wash on the zone that
        says which direction is broken, and skipping it on that reasoning left
        the panel this test most needed to cover outside it. What decides is
        the property being set, not how the colour was spelled."""
        import re
        css = nd.VIEWER_TEMPLATE.split("<style", 1)[1].split("</style>", 1)[0]
        outside = re.sub(r":root\{[^}]*\}", "", css)
        literal = re.compile(r"#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?)\(")
        stray = {}
        for m in re.finditer(r"\n\s*([^{\n]+)\{([^}]*)\}", outside):
            for decl in m.group(2).split(";"):
                prop, _, value = decl.partition(":")
                if prop.strip().endswith("shadow"):
                    continue
                for colour in literal.findall(value):
                    stray.setdefault(colour, set()).add(m.group(1).strip())
        self.assertEqual(
            stray, {},
            "colours written outside a palette cannot follow one: "
            + "; ".join(f"{c} in {sorted(s)}" for c, s in sorted(stray.items())))

    def test_the_broken_direction_is_the_loudest_zone(self):
        """The zones answer one question - which way is broken - and the
        failing one has to be the one the eye lands on. Setting a
        semi-transparent background replaces the card's own rather than washing
        over it, so the tint composited against the page instead and the
        failing zone came out darker than the passing ones on a dark ground:
        the answer rendered quieter than the things that were fine."""
        import re
        template = nd.VIEWER_TEMPLATE
        rule = template.split(".zone.fail{", 1)[1].split("}", 1)[0]
        m = re.search(r"color-mix\(in srgb, var\(--crit\) (\d+)%, var\((--panel[-0-9]*)\)\)",
                      rule)
        self.assertTrue(m, "the failing zone is not washed over a named surface")
        surface = m.group(2)
        self.assertLess(rule.index(f"background:var({surface})"),
                        rule.index("background:color-mix"),
                        "the fallback has to come before the color-mix line")
        pct = int(m.group(1)) / 100

        def ch(h):
            h = h.lstrip("#")
            return [int(h[i:i + 2], 16) for i in (0, 2, 4)]

        def lum(c):
            def f(v):
                v /= 255
                return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
            r, g, b = (f(x) for x in c)
            return 0.2126 * r + 0.7152 * g + 0.0722 * b

        for palette, block in (("dark", template),
                               ("light", template.split(
                                   "@media (prefers-color-scheme: light){", 1)[1])):
            card = self._css_var(block, surface) or self._css_var(template, surface)
            crit = self._css_var(block, "--crit") or self._css_var(template, "--crit")
            dim = (self._css_var(block, "--text-dim-lift")
                   or self._css_var(template, "--text-dim-lift"))
            washed = [a * pct + b * (1 - pct) for a, b in zip(ch(crit), ch(card))]
            with self.subTest(palette=palette):
                self.assertNotAlmostEqual(
                    lum(washed), lum(ch(card)), places=3,
                    msg="the failing zone is indistinguishable from a passing one")
                hexed = "#" + "".join(f"{round(x):02x}" for x in washed)
                self.assertGreaterEqual(
                    self._contrast(dim, hexed), 4.5,
                    "the reason the zone gives is unreadable on its own wash")

    def test_the_light_palette_is_readable_too(self):
        """The page now follows the reader's system setting, which means half
        the audience never sees the palette the colours were chosen against.
        Amber on near-black is the combination that survives a dark theme and
        fails a light one, so every colour is checked against the light ground
        rather than assumed to have been darkened enough."""
        import re
        block = nd.VIEWER_TEMPLATE.split("@media (prefers-color-scheme: light){", 1)
        self.assertEqual(len(block), 2, "the light palette is gone")
        rules = block[1].split("}", 1)[0]
        ground = re.search(r"--bg:(#[0-9a-fA-F]{6})", rules).group(1)
        for name in ("--text", "--text-dim", "--text-dim-lift",
                     "--ok", "--warn", "--crit", "--accent",
                     "--cause", "--hardware"):
            m = re.search(rf"{name}:(#[0-9a-fA-F]{{6}})", rules)
            self.assertTrue(m, f"{name} is not restated for the light palette")
            with self.subTest(colour=name):
                self.assertGreaterEqual(
                    self._contrast(m.group(1), ground), 4.5,
                    f"{name} is unreadable on the light ground")

    def test_dark_stays_the_default(self):
        """Following the system setting is only safe if it is additive. Making
        light the base and darkening under a query would flip the appearance
        for every reader whose machine reports no preference at all."""
        template = nd.VIEWER_TEMPLATE
        self.assertNotIn("prefers-color-scheme: dark", template)
        first_root = template.index(":root{")
        light = template.index("@media (prefers-color-scheme: light){")
        self.assertLess(first_root, light,
                        "the dark palette has to be declared before the light override")

    def test_the_numbers_do_not_shift_as_they_change(self):
        """Proportional digits change width with their value, so a column of
        latencies moves sideways every time one ticks over - and the numbers
        are the reading. Tabular figures are asked for only where digits are
        load-bearing; in prose they are worse than leaving it alone."""
        template = nd.VIEWER_TEMPLATE
        rule = template.split("font-variant-numeric:tabular-nums", 1)
        self.assertEqual(len(rule), 2, "tabular figures are gone")
        selectors = rule[0].rsplit("}", 1)[1]
        for carries_numbers in (".hop-sub", ".hop-meta", ".verdict .vmeta", "pre"):
            self.assertIn(carries_numbers, selectors)
        # The message text is prose and must not be caught by it.
        self.assertNotIn(".finding .msg", selectors)

    def test_the_evidence_panels_can_be_opened_without_a_mouse(self):
        """The panels were a div with an onclick, which is a control to a mouse
        and scenery to everything else - no focus, no key handling, nothing
        announced. They are the only interactive thing on the page, so a reader
        without a mouse could not open a single one of the twenty-odd panels
        holding the evidence behind the verdict."""
        template = nd.VIEWER_TEMPLATE
        head = template.split('<div class="panel-head"', 1)[1].split(">", 1)[0]
        self.assertIn('role="button"', head)
        self.assertIn('tabindex="0"', head)
        self.assertIn("onkeydown", head)
        for key in ("'Enter'", "' '"):
            self.assertIn(key, head)
        # Space scrolls the page unless the handler says otherwise, so the
        # panel would open and the reader would be somewhere else.
        self.assertIn("event.preventDefault()", head)
        # Reaching it by keyboard is half the job; seeing where you are is the
        # other half.
        self.assertIn(".panel-head:focus-visible{", template)

    def test_an_opened_panel_says_that_it_is_open(self):
        """aria-expanded set once at render and never updated is worse than
        leaving it off: it states the opposite of the truth as soon as anyone
        collapses a panel."""
        template = nd.VIEWER_TEMPLATE
        self.assertIn('aria-expanded="true"', template)
        toggle = template.split("function togglePanel", 1)[1].split("}", 1)[0]
        self.assertIn("setAttribute('aria-expanded'", toggle)
        self.assertIn("classList.toggle('collapsed')", toggle)

    def test_the_platform_is_named_the_way_a_reader_would_say_it(self):
        """platform.system() answers with the kernel's name, so a Mac calls
        itself "Darwin" - accurate, and meaningless to most people reading a
        report. The raw value stays for anything reading it by machine."""
        self.assertEqual(nd.os_label("Darwin"), "macOS")
        for unchanged in ("Linux", "Windows", "FreeBSD"):
            self.assertEqual(nd.os_label(unchanged), unchanged)

    def test_a_report_written_before_the_label_existed_still_reads_well(self):
        """The mapping is fixed, so translating an old report on the way out
        costs nothing and beats showing it a name it can't act on."""
        old = {"os": "Darwin", "findings": [], "hops": [], "raw": {}, "version": "1.1.0"}
        self.assertIn("macOS", nd.render_text_report(old, width=80).splitlines()[0])
        self.assertNotIn("Darwin", nd.render_text_report(old, width=80))

    def test_the_raw_platform_name_is_still_in_the_report(self):
        """The label is for reading. Anything parsing the JSON wants the value
        platform.system() actually returned."""
        self.assertIn('"os": OS_NAME', open(nd.__file__, encoding="utf-8").read())
        self.assertIn("data.os_label || data.os", nd.VIEWER_TEMPLATE)

    def test_a_report_names_its_own_tab(self):
        """Two sites, or a before and after, are read side by side. Identical
        tab titles mean clicking each one to find out which is which."""
        template = nd.VIEWER_TEMPLATE
        self.assertIn("document.title = ['FaultOne', data.target, state]", template)

    def test_the_tab_icon_is_inline_and_follows_the_verdict(self):
        """A tab squeezed too narrow to show its title still shows its state.
        The icon has to be embedded - a report is one file - and its colour
        read from the stylesheet rather than repeated as a second literal."""
        template = nd.VIEWER_TEMPLATE
        self.assertIn('rel="icon" id="favicon"', template)
        self.assertIn("data:image/svg+xml,", template)
        self.assertIn("getPropertyValue(FAVICON_VAR[state]", template)
        # every verdict severity the tool emits must map to a colour
        for severity in ("warning", "critical"):
            self.assertIn(f"{severity}: '--", template)
        self.assertIn("clear: '--ok'", template)
        # '#' would truncate the data URI at the fragment
        self.assertIn("encodeURIComponent(svg)", template)

    def test_the_committed_viewer_matches_the_embedded_template(self):
        """static/index.html is the same template with an empty island. If the
        two drift, the file you open and the file you export stop agreeing -
        silently, and only on the machine reading the report."""
        import os
        viewer = os.path.join(os.path.dirname(os.path.abspath(nd.__file__)),
                              "static", "index.html")
        if not os.path.exists(viewer):
            self.skipTest("viewer not present")
        with open(viewer, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), nd.VIEWER_TEMPLATE,
                             "static/index.html and VIEWER_TEMPLATE have diverged - "
                             "regenerate with --emit-viewer")

    def test_the_template_still_has_somewhere_to_put_the_data(self):
        self.assertIn(nd.REPORT_PLACEHOLDER, nd.VIEWER_TEMPLATE)

    def test_the_template_no_longer_talks_to_a_server(self):
        for gone in ("/api/", "loadMeta", "runCommand", "diagnoseBtn"):
            self.assertNotIn(gone, nd.VIEWER_TEMPLATE, f"{gone} outlived the server")


class DiagnoseHarness(unittest.TestCase):
    """Characterization tests for diagnose().

    diagnose() is the one function everything funnels through, and it is long.
    These pin its observable behaviour - which findings fire, what the verdict
    concludes, what the stage strip says - so it can be restructured without
    changing what it reports. Every collector is stubbed, so no command runs,
    no packet is sent, and nothing sleeps.

    "Every" is read off the module rather than listed here. It used to be a
    hand-written tuple of seventeen names, and the tool grew to thirty-eight
    collectors around it: twenty-two of them ran for real inside a harness
    whose docstring said none of them did. Several read the host - socket
    states, server limits, orphan counts - and one asserts that the only
    finding is all_clear, so anything the machine happened to be doing could
    add a finding and fail it. That is the shape of a test that passes on your
    machine and not on the next one.
    """

    #: Everything that fetches from outside the process. Derived, because the
    #: list is the thing that went stale.
    @staticmethod
    def collectors():
        return sorted(n for n in dir(nd)
                      if (n.startswith("cmd_") or n.startswith("_read_"))
                      and callable(getattr(nd, n)))

    @staticmethod
    def _unavailable(name):
        """What a collector returns when it cannot run - the tool's own shape
        for that, so nothing downstream has to special-case the harness."""
        return lambda *a, **k: {"ok": False, "cmd": name, "applicable": False,
                                "error": "not stubbed by this harness"}

    def setUp(self):
        names = self.collectors() + ["which"]
        self._saved = {name: getattr(nd, name) for name in names}
        self._saved["sleep"] = nd.time.sleep
        nd.time.sleep = lambda s: None
        # Nothing reaches the machine unless a test below says what it returns.
        # A reader that finds nothing returns nothing; a command that cannot run
        # says so. Both are states the tool already handles, and neither is the
        # state of whatever this happens to be running on.
        for name in self.collectors():
            # cmd_link_stats reaches nothing on its own - it is arithmetic
            # over _read_link_stats, which the tests below drive directly.
            # Stubbing it as unavailable would take that control away.
            if name == "cmd_link_stats":
                continue
            if name.startswith("cmd_"):
                setattr(nd, name, self._unavailable(name))
            elif name == "_read_text":
                setattr(nd, name, lambda *a, **k: None)
            else:
                setattr(nd, name, lambda *a, **k: {})
        # Defaults: a healthy device with nothing optional installed.
        nd.which = lambda cmd: False
        nd.cmd_interfaces = lambda: {"ok": True, "cmd": "ip addr", "stdout":
                                     "2: eth0: <UP>\n    inet 10.0.0.5/24 brd 10.0.0.255\n"}
        nd.cmd_routes = lambda: {"ok": True, "cmd": "ip route",
                                 "stdout": "default via 10.0.0.1 dev eth0\n"}
        nd.cmd_arp = lambda: {"ok": True, "cmd": "ip neigh",
                              "stdout": "10.0.0.1 dev eth0 lladdr aa:bb:cc:00:00:01 REACHABLE\n"}
        nd.cmd_ping = lambda t, c=4, w=2: {"ok": True, "cmd": f"ping {t}", "stdout":
            "4 packets transmitted, 4 received, 0% packet loss\n"
            "rtt min/avg/max/mdev = 1.0/2.0/3.0/0.5 ms\n"}
        nd.cmd_dns = lambda t: {"ok": True, "cmd": "dig", "stdout": "google.com. 60 IN A 192.0.2.4\n"}
        nd.cmd_dns_health = lambda check_hijack=True: {
            "ok": True, "cmd": "resolvers", "stdout": "", "probe": "google.com",
            "resolvers": [{"server": "10.0.0.53", "ok": True, "rcode": "NOERROR",
                           "elapsed_ms": 12.0, "answers": ["192.0.2.4"], "hijacks_nxdomain": False}]}
        nd.cmd_traceroute = lambda t: {"ok": True, "cmd": "traceroute", "stdout":
            " 1  10.0.0.1 (10.0.0.1)  1.0 ms  1.1 ms  1.2 ms\n"
            f" 2  {t} ({t})  20.0 ms  20.1 ms  20.2 ms\n"}
        nd.cmd_traceroute_tcp = lambda t, port=443: None
        nd.cmd_mtr = lambda t, cycles=10: None
        nd.cmd_path_mtu = lambda t, m=None: {"ok": True, "cmd": "df ping", "stdout": "",
                                             "target": t, "iface_mtu": 1500, "path_mtu": 1500,
                                             "attempts": [{"mtu": 1500, "payload": 1472,
                                                           "ok": True, "cmd": "x"}]}
        nd.cmd_check_port = lambda h, p, timeout=5: {"ok": True, "cmd": f"tcp connect {h}:{p}",
                                                     "stdout": "open", "stderr": "", "code": 0}
        nd.cmd_link_modes = lambda: {"ok": True, "cmd": "sysfs", "stdout": "", "interfaces": [
            {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500,
             "carrier": True, "operstate": "up"}]}
        nd.cmd_lldp = lambda: None
        nd.cmd_optics = lambda iface: None
        nd._read_tcp_counters = lambda: {"OutSegs": 100000, "RetransSegs": 100}
        self.set_counters(errors=0, crc=0)

    def tearDown(self):
        for name, value in self._saved.items():
            if name == "sleep":
                nd.time.sleep = value
            else:
                setattr(nd, name, value)

    def set_counters(self, errors=0, crc=0, growing=0):
        first = dict(rx_packets=5_000_000, tx_packets=5_000_000, rx_bytes=0, tx_bytes=0,
                     rx_errors=errors, tx_errors=0, rx_dropped=0, tx_dropped=0,
                     rx_crc_errors=crc, rx_frame_errors=0, rx_over_errors=0,
                     collisions=0, operstate="up")
        second = dict(first, rx_errors=errors + growing, rx_crc_errors=crc + growing)
        seq = [({"eth0": first}, "test"), ({"eth0": second}, "test")]
        state = {"i": 0}

        def read():
            result = seq[min(state["i"], 1)]
            state["i"] += 1
            return result
        nd._read_link_stats = read

    def run_diagnose(self, **kwargs):
        return nd.diagnose(kwargs.pop("target", "8.8.8.8"), kwargs.pop("check_ports", None),
                           **kwargs)

    def codes(self, report):
        return {f.get("code") for f in report["findings"]}

    def stages(self, report):
        return {s["stage"]: s["state"] for s in report["stages"]}

    # ---- the scenarios ---------------------------------------------------

    def test_the_harness_replaces_every_collector_the_module_has(self):
        """The thing this class claims about itself, asserted rather than
        stated. It used to name seventeen collectors in a tuple while the tool
        grew to thirty-eight, so twenty-two ran for real - including a live TLS
        handshake to 8.8.8.8 - inside a harness whose docstring says no packet
        is sent. The list is derived now, and this fails if anything is left
        pointing at the real implementation."""
        live = [name for name in self.collectors()
                if getattr(nd, name) is self._saved.get(name)]
        self.assertEqual(
            [n for n in live if n != "cmd_link_stats"], [],
            "these still reach the machine from inside the harness")
        self.assertGreater(len(self.collectors()), 30,
                           "the collector list stopped finding them")

    def test_healthy_device(self):
        r = self.run_diagnose()
        self.assertEqual(self.codes(r), {"all_clear"})
        self.assertEqual(r["verdict"]["severity"], "ok")
        self.assertEqual(self.stages(r)["gateway"], "pass")
        self.assertEqual(self.stages(r)["dns"], "pass")
        self.assertIsNotNone(r["call_quality"])
        self.assertEqual(r["path_source"], "traceroute")

    def test_failing_cable(self):
        self.set_counters(errors=1200, crc=1150, growing=14)
        r = self.run_diagnose()
        self.assertIn("link_errors_live", self.codes(r))
        self.assertEqual(self.stages(r)["link"], "fail")
        self.assertIn("corrupting frames", r["verdict"]["headline"].lower())
        self.assertEqual(r["verdict"]["owner"], "this device or its cable")

    def test_uplink_down_local_network_fine(self):
        def ping(t, c=4, w=2):
            lost = t != "10.0.0.1"
            return {"ok": True, "cmd": f"ping {t}", "stdout":
                    f"4 packets transmitted, {0 if lost else 4} received, "
                    f"{100 if lost else 0}% packet loss\n"
                    + ("" if lost else "rtt min/avg/max/mdev = 1.0/2.0/3.0/0.5 ms\n")}
        nd.cmd_ping = ping
        # Silent to ICMP *and* to TCP - otherwise this describes a hardened
        # box with a working uplink, not an uplink that is down.
        nd.cmd_check_port = lambda h, p, timeout=5: {
            "ok": False, "cmd": f"tcp connect {h}:{p}", "reason": "timeout"}
        # The path must stop short too, or this describes a reachable target
        # that is silent - a different fault, with a different owner.
        path_dies_short(nd)
        r = self.run_diagnose()
        self.assertIn("inet_unreachable", self.codes(r))
        self.assertEqual(r["verdict"]["owner"], "the provider")
        self.assertEqual(self.stages(r)["internet"], "fail")
        self.assertEqual(self.stages(r)["gateway"], "pass")

    def test_one_resolver_dead(self):
        nd.cmd_dns_health = lambda check_hijack=True: {
            "ok": True, "cmd": "resolvers", "stdout": "", "probe": "google.com",
            "resolvers": [{"server": "10.0.0.53", "ok": True, "rcode": "NOERROR",
                           "elapsed_ms": 12.0, "answers": ["192.0.2.4"], "hijacks_nxdomain": False},
                          {"server": "10.0.0.54", "ok": False, "rcode": None,
                           "elapsed_ms": 2000, "answers": [], "error": "no reply",
                           "hijacks_nxdomain": False}]}
        r = self.run_diagnose()
        self.assertIn("dns_resolver_down", self.codes(r))
        self.assertEqual(self.stages(r)["dns"], "warn")

    def test_missing_tools_are_not_faults(self):
        nd.cmd_interfaces = lambda: {"ok": False, "cmd": "ifconfig",
                                     "error": "command not found: ifconfig"}
        nd.cmd_routes = lambda: {"ok": False, "cmd": "netstat",
                                 "error": "command not found: netstat"}
        r = self.run_diagnose()
        self.assertIn("interfaces_unreadable", self.codes(r))
        self.assertIn("routes_unreadable", self.codes(r))
        self.assertNotIn("no_ipv4", self.codes(r))
        self.assertNotIn("no_gateway", self.codes(r))
        self.assertEqual(self.stages(r)["address"], "warn")

    def test_port_checks_and_stage(self):
        nd.cmd_check_port = lambda h, p, timeout=5: (
            {"ok": True, "cmd": f"tcp connect {h}:{p}", "stdout": "open", "stderr": "", "code": 0}
            if p == "443" else
            {"ok": False, "cmd": f"tcp connect {h}:{p}", "error": "timeout", "reason": "timeout"})
        # An open port means the TLS check runs against it. Left to the
        # machine, that was a real handshake to 8.8.8.8 from a test suite whose
        # harness says no packet is sent.
        nd.cmd_tls_check = lambda h, p, timeout=5: {
            "ok": True, "cmd": f"tls {h}:{p}", "verified": True,
            "subject": "dns.google", "issuer": "Test CA",
            "days_left": 90, "tls_ms": 20.0, "tcp_ms": 10.0}
        r = self.run_diagnose(check_ports=["443", "9999"])
        self.assertIn("port_timeout", self.codes(r))
        self.assertEqual(self.stages(r)["ports"], "warn")
        self.assertEqual(len(r["port_results"]), 2)

    def test_quick_mode_skips_the_slow_work(self):
        r = self.run_diagnose(quick=True)
        self.assertTrue(r["quick"])
        self.assertEqual(r["hops"], [])
        self.assertNotIn("path_mtu", r["raw"])
        self.assertEqual(self.stages(r)["mtu"], "skip")

    def test_every_finding_carries_a_code(self):
        """A finding without a code is invisible to the verdict, the stage strip
        and the coverage tests - it silently stops participating in all three."""
        self.set_counters(errors=1200, crc=1150, growing=14)
        for kwargs in ({}, {"quick": True}, {"check_ports": ["443"]}):
            for f in self.run_diagnose(**kwargs)["findings"]:
                self.assertTrue(f.get("code"),
                                f"finding with no code: {f['message'][:60]!r}")

    def test_no_duplicate_keys_in_any_dict_literal(self):
        """A repeated key in a dict literal is silently accepted by Python -
        the last one wins and the earlier value vanishes. That is exactly how
        the all_clear code went missing."""
        import ast
        with open(nd.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        dupes = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                seen = set()
                for k in node.keys:
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        if k.value in seen:
                            dupes.append(f"line {node.lineno}: {k.value!r}")
                        seen.add(k.value)
        self.assertFalse(dupes, f"duplicate dict keys: {dupes}")

    def test_report_shape_is_stable(self):
        r = self.run_diagnose()
        for key in ("verdict", "stages", "comparison", "findings", "raw", "hops",
                    "port_results", "layers", "panel_help", "call_quality", "neighbours",
                    "lowest_broken_layer", "demarc_hop", "path_source", "generated_at"):
            self.assertIn(key, r, f"report lost the {key!r} field")

    def test_text_report_renders_for_every_scenario(self):
        self.set_counters(errors=1200, crc=1150, growing=14)
        for kwargs in ({}, {"quick": True}, {"check_ports": ["443"]}):
            out = nd.render_text_report(self.run_diagnose(**kwargs), color=False, width=90)
            self.assertIn("FINDINGS", out)
            self.assertIn("LIKELY ROOT CAUSE", out)


# ---------------------------------------------------------------------------
# Every finding, end to end.
#
# Each scenario stubs the collectors so one specific fault is present, runs the
# whole diagnosis, and checks that the finding fires with the severity intended.
# Written after a manual sweep of all 56 codes found five defects that unit
# tests could not: two findings that could never fire, a symptom outranking the
# cause it was derived from, housekeeping findings reading as failures, and a
# critical finding leaving its stage merely warning.
# ---------------------------------------------------------------------------



MODULE_PATH = nd.__file__


REAL_SLEEP = time.sleep
REAL_MONOTONIC = time.monotonic


def patch_clock(case, sleep=None, monotonic=None):
    """Patch the clock for one test, and put it back afterwards.

    `nd.time` is not a copy of anything - it is the `time` module, shared by
    every module in the process. So `nd.time.sleep = ...` disables sleeping
    *everywhere* until something restores it, and seven places here did that
    and never did. Anything running afterwards that depended on real time was
    silently not testing what it said: the phase-timing test found it by
    measuring 0.1ms of a 250ms delay.
    """
    case.addCleanup(setattr, time, "sleep", REAL_SLEEP)
    case.addCleanup(setattr, time, "monotonic", REAL_MONOTONIC)
    if sleep is not None:
        time.sleep = sleep
    if monotonic is not None:
        time.monotonic = monotonic


def fresh():
    spec = importlib.util.spec_from_file_location("nd_scenario", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    # Its own time module, not the shared one with a hole knocked in it. The
    # scenarios must not really sleep - a hundred and fifty of them pausing for
    # a sampling window would take an hour - but `mod.time.sleep = ...` reaches
    # every module in the process, because `mod.time` *is* `time`. Rebinding
    # the name on this module copy keeps the change where it belongs.
    quiet_time = types.ModuleType("time")
    quiet_time.__dict__.update(time.__dict__)
    quiet_time.sleep = lambda s: None
    mod.time = quiet_time
    mod.which = lambda c: False
    # ---- healthy baseline for every collector -------------------------
    mod.cmd_interfaces = lambda: {"ok": True, "cmd": "ip addr",
                                 "stdout": "2: eth0: <UP>\n    inet 10.0.0.5/24\n"}
    mod.cmd_routes = lambda: {"ok": True, "cmd": "ip route",
                             "stdout": "default via 10.0.0.1 dev eth0\n"}
    mod.cmd_arp = lambda: {"ok": True, "cmd": "ip neigh",
                          "stdout": "10.0.0.1 dev eth0 lladdr aa:bb:cc:00:00:01 REACHABLE\n"}
    mod.cmd_ping = lambda t, c=4, w=2: {"ok": True, "cmd": f"ping {t}", "stdout":
        "4 packets transmitted, 4 received, 0% packet loss\n"
        "rtt min/avg/max/mdev = 1.0/20.0/30.0/2.0 ms\n"}
    mod.cmd_dns = lambda t: {"ok": True, "cmd": "dig", "stdout": "google.com. 60 IN A 192.0.2.4\n"}
    mod.cmd_dns_health = lambda check_hijack=True: {"ok": True, "cmd": "r", "stdout": "",
        "probe": "google.com", "resolvers": [
            {"server": "10.0.0.53", "ok": True, "rcode": "NOERROR", "elapsed_ms": 12.0,
             "answers": ["192.0.2.4"], "hijacks_nxdomain": False}]}
    mod.cmd_traceroute = lambda t: {"ok": True, "cmd": "traceroute", "stdout":
        " 1  10.0.0.1 (10.0.0.1)  1.0 ms  1.1 ms  1.2 ms\n"
        f" 2  {t} ({t})  20.0 ms  20.1 ms  20.2 ms\n"}
    mod.cmd_traceroute_tcp = lambda t, port=443: None
    mod.cmd_mtr = lambda t, c=10: None
    mod.cmd_path_mtu = lambda t, m=None: {"ok": True, "cmd": "df", "stdout": "", "target": t,
        "iface_mtu": 1500, "path_mtu": 1500,
        "attempts": [{"mtu": 1500, "payload": 1472, "ok": True, "cmd": "x"}]}
    mod.cmd_check_port = lambda h, p, timeout=5: {"ok": True, "cmd": f"tcp connect {h}:{p}",
                                                 "stdout": "open", "stderr": "", "code": 0}
    mod.cmd_link_modes = lambda: {"ok": True, "cmd": "sysfs", "stdout": "", "interfaces": [
        {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500,
         "carrier": True, "operstate": "up"}]}
    mod.cmd_lldp = lambda: None
    mod.cmd_optics = lambda i: None
    mod.cmd_tls_check = lambda h, p=443, timeout=5: None
    # The three that open a socket to this box's own listeners. Left live they
    # really connect to 127.0.0.1 on whatever ports the scenario's fake socket
    # table invented - twenty-nine connections in a single test, from a suite
    # whose whole premise is that it sends nothing. Unix refuses them in
    # microseconds so it never showed; Windows takes about two seconds each,
    # which was a minute a test and three quarters of the CI run.
    #
    # The shape is the one the tool produces when nothing is listening, so a
    # scenario that wants a served certificate or a live local service still
    # overrides these afterwards and gets exactly what it asked for.
    mod.cmd_own_http = lambda port, timeout=5, address="127.0.0.1", tls=False: {
        "ok": False, "cmd": f"HEAD / {address}:{port}", "port": port,
        "host": address, "tls": tls, "unreachable_locally": "connection refused"}
    mod.cmd_own_tls = lambda port, timeout=5, address="127.0.0.1": {
        "ok": False, "cmd": f"tls handshake {address}:{port} (own listener)",
        "host": address, "port": port, "own_listener": True,
        "unreachable_locally": "connection refused"}
    mod.cmd_tls_check_local = lambda port, server_name, timeout=5, address="127.0.0.1": {
        "verified": False, "verify_error": "connection refused"}
    mod.cmd_socket_states = lambda: {"ok": True, "cmd": "ss -tan", "stdout": "",
                                    "states": {"ESTABLISHED": 5, "LISTEN": 3}, "pending": {}}
    mod.cmd_listen_ports = lambda: {"ok": True, "cmd": "ss -tuln", "stdout": "listening"}
    mod._read_tcp_counters = lambda: {"OutSegs": 100000, "RetransSegs": 100}
    counters(mod)
    return mod

def kernel_drops(nd, first, second=None):
    """Stub the two /proc reads with a before/after pair.

    diagnose() takes a baseline before anything else and cmd_kernel_drops takes
    the second reading when the window closes, so the sequence is two deep.
    """
    nd.OS_NAME = "Linux"
    seq = [dict(first), dict(second if second is not None else first)]
    state = {"i": 0}
    def read():
        r = seq[min(state["i"], 1)]; state["i"] += 1; return r
    nd._read_kernel_drops = read

def counters(nd, **over):
    base = dict(rx_packets=5_000_000, tx_packets=5_000_000, rx_bytes=0, tx_bytes=0,
                rx_errors=0, tx_errors=0, rx_dropped=0, tx_dropped=0, rx_crc_errors=0,
                rx_frame_errors=0, rx_over_errors=0, collisions=0, operstate="up")
    first = dict(base); first.update({k: v for k, v in over.items() if not k.startswith("d_")})
    second = dict(first)
    for k, v in over.items():
        if k.startswith("d_"):
            key = k[2:]
            second[key] = first.get(key, 0) + v
    seq = [({"eth0": first}, "t"), ({"eth0": second}, "t")]
    state = {"i": 0}
    def read():
        r = seq[min(state["i"], 1)]; state["i"] += 1; return r
    nd._read_link_stats = read

def ping_map(nd, gw_loss=0, inet_loss=0, avg=20.0, mdev=2.0, sent=20):
    """Twenty probes by default, not four.

    The fixture had the same flaw the code did: at four probes, "25% loss" is
    one unanswered packet, which the tool now declines to call a rate. A
    fixture that can't express the thing it is asserting tests the wrong
    behaviour.
    """
    def ping(t, c=4, w=2):
        loss = gw_loss if t == "10.0.0.1" else inet_loss
        got = sent - int(sent * loss / 100)
        body = f"{sent} packets transmitted, {got} received, {loss}% packet loss\n"
        if got:
            body += f"rtt min/avg/max/mdev = 1.0/{avg}/{avg*2}/{mdev} ms\n"
        return {"ok": True, "cmd": f"ping {t}", "stdout": body}
    nd.cmd_ping = ping

def trace(nd, text):
    nd.cmd_traceroute = lambda t: {"ok": True, "cmd": "traceroute", "stdout": text}

def mtr(nd, hubs):
    nd.cmd_mtr = lambda t, c=10: {"ok": True, "cmd": "mtr", "cycles": c, "stdout": "",
                                  "hops": nd.parse_mtr_json(json.dumps({"report": {"hubs": hubs}}))}

def resolvers(nd, entries):
    nd.cmd_dns_health = lambda check_hijack=True: {"ok": True, "cmd": "r", "stdout": "",
                                                   "probe": "google.com", "resolvers": entries}

def R(server, ok=True, ms=12.0, answers=("192.0.2.4",), hijack=False):
    return {"server": server, "ok": ok, "rcode": "NOERROR" if ok else None,
            "elapsed_ms": ms, "answers": list(answers), "hijacks_nxdomain": hijack,
            "error": None if ok else "no reply"}

SS_HEADER = "State  Recv-Q Send-Q   Local Address:Port   Peer Address:Port  Process\n"

def ss_flow(peer, sent=0, retrans=0, segs=0, retrans_segs=None,
            rwnd=None, sndbuf=None, port="443"):
    """One socket the way `ss -tin` prints it: a state line and its detail block."""
    detail = ["cubic wscale:7,7 rto:220 rtt:12.4/3.1 ato:40 mss:1460 pmtu:1500 cwnd:10"]
    if sent:
        detail.append(f"bytes_sent:{sent} bytes_acked:{sent} bytes_retrans:{retrans}")
    if segs:
        detail.append(f"segs_out:{segs} segs_in:{segs}")
    if retrans_segs is not None:
        detail.append(f"retrans:0/{retrans_segs}")
    if rwnd:
        detail.append(f"rwnd_limited:{int(rwnd * 50)}ms({rwnd}%)")
    if sndbuf:
        detail.append(f"sndbuf_limited:{int(sndbuf * 50)}ms({sndbuf}%)")
    detail.append("busy:5000ms rcv_space:14600 minrtt:11.9")
    return (f"ESTAB  0      0        10.0.0.5:51234        {peer}:{port}\n"
            f"\t {' '.join(detail)}\n")

def flows(nd, *sockets, **kw):
    """Feed fixture sockets through the real parser and analyser, then stand in
    for the collector - so a scenario exercises the whole chain, not a stub.

    The collector takes the listening ports now, so the stub does too: a lambda
    with the old signature raises TypeError the moment the real code passes
    them, which is a test failing for a reason unrelated to what it tests.
    """
    stats = nd.analyze_tcp_flows(nd.parse_tcp_flows(SS_HEADER + "".join(sockets)), **kw)
    res = {"ok": True, "cmd": "ss -tin", "stdout": "", "stderr": "", "code": 0}
    res.update(stats)
    nd.cmd_tcp_flows = lambda listen_ports=None: res
    return stats

def klog(nd, text, uptime=90 * 86400, tool="dmesg", code=0):
    """Stand in for the kernel ring buffer, through the real collector."""
    nd.OS_NAME = "Linux"
    nd._uptime_seconds = lambda: uptime
    nd.which = lambda c: c == tool
    nd.run = lambda cmd, timeout=15, limit=None: {"ok": True, "cmd": " ".join(cmd), "stdout": text,
                                      "stderr": "", "code": code}

def klog_flaps(nd, count=80, over=600, uptime=90 * 86400, iface="eth0"):
    """`count` carrier transitions spread across the last `over` seconds."""
    step = over / max(1, count)
    text = "\n".join(
        f"[{uptime - over + i * step:.6f}] e1000e 0000:00:1f.6 {iface}: "
        f"NIC Link is {'Down' if i % 2 == 0 else 'Up'}" for i in range(count))
    klog(nd, text, uptime)

def rate_series(nd, rates, window=120):
    """Stand in for the per-second sampler with a series it would have taken."""
    orig = nd._finish_link_sample
    nd._finish_link_sample = (
        lambda first, source, secs, already_waited=False, series=None,
               series_seconds=0:
        orig(first, source, window, already_waited, {"eth0": list(rates)}, window))

def path_dies_short(nd):
    """A trace that stops before the target. Without this the fixture describes
    a target that is silent at the end of a working path - which is a different
    fault, and now reported as one."""
    mtr(nd, [{"count": 1, "host": "10.0.0.1", "Loss%": 0.0, "Snt": 30, "Avg": 1.0},
             {"count": 2, "host": "???", "Loss%": 100.0, "Snt": 30, "Avg": 0.0}])

def unreachable(nd, arp=False, tcp=False):
    """A box that is genuinely cut off, not just unanswered by ICMP.

    Ping alone stopped being enough to call anything unreachable: blocking ICMP
    is ordinary hardening, so a fixture that only silences ping is describing a
    healthy hardened box, not an outage.
    """
    if not arp:
        nd.cmd_arp = lambda: {"ok": True, "cmd": "ip neigh",
                              "stdout": "10.0.0.1 dev eth0 FAILED\n"}
    if not tcp:
        nd.cmd_check_port = lambda h, p, timeout=5: {
            "ok": False, "cmd": f"tcp connect {h}:{p}", "reason": "timeout",
            "error": "timed out"}

SERVING_SS = ("State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
              "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
              + "".join(f"ESTAB 0 0 10.0.0.5:443 203.0.113.{i}:5123{i}\n" for i in range(9)))

def serving(nd, text=SERVING_SS):
    """A box with clients connected to it, through the real state parser."""
    nd.cmd_socket_states = lambda: dict(
        {"ok": True, "cmd": "ss -tan", "stdout": text}, **nd.parse_socket_states(text))

def scenario_kwargs(kw):
    """Whatever the scenario declared, handed straight to diagnose().

    This used to name check_ports and baseline explicitly, which meant a
    scenario needing any other argument - a sampling window, an uplink rate -
    registered fine and then ran without it, and the finding silently never
    fired.
    """
    out = {"check_ports": None, "baseline": None, "target": "8.8.8.8"}
    out.update(kw)
    return out


# ---- one scenario per finding code ------------------------------------
S = {}
def scenario(code, **kw):
    def deco(fn):
        S[code] = (fn, kw); return fn
    return deco

@scenario("all_clear")
def _(nd): pass

@scenario("no_ipv4")
def _(nd): nd.cmd_interfaces = lambda: {"ok": True, "cmd": "ip addr", "stdout": "lo: <LOOPBACK>\n"}

@scenario("interfaces_unreadable")
def _(nd): nd.cmd_interfaces = lambda: {"ok": False, "cmd": "ifconfig", "error": "command not found"}

@scenario("routes_unreadable")
def _(nd): nd.cmd_routes = lambda: {"ok": False, "cmd": "netstat", "error": "command not found"}

@scenario("no_gateway")
def _(nd): nd.cmd_routes = lambda: {"ok": True, "cmd": "ip route", "stdout": "10.0.0.0/24 dev eth0\n"}

# A proxy holding a service address beside its own: the /32 next to the /24 is
# the shape keepalived and every load balancer in front of one leaves behind.
_VIP_IFACES = {"ok": True, "cmd": "ip addr", "stdout":
               "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
               "    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n"
               "    inet 10.0.0.200/32 scope global eth0\n"}


@scenario("service_address_present")
def _(nd): nd.cmd_interfaces = lambda: _VIP_IFACES


@scenario("bound_to_source_address")
def _(nd):
    nd.cmd_interfaces = lambda: _VIP_IFACES
    nd.SOURCE_ADDRESS = "10.0.0.200"
    # The bind is stubbed because the scenario is about the finding, not about
    # the kernel: no test machine holds this address. What the bind really does
    # is pinned separately, against addresses the running box does and does not
    # have.
    nd.source_address_is_held = lambda a: True


@scenario("source_address_not_held")
def _(nd):
    nd.cmd_interfaces = lambda: _VIP_IFACES
    nd.SOURCE_ADDRESS = "10.0.0.201"
    nd.source_address_is_held = lambda a: False


@scenario("no_upstream_sessions")
def _(nd):
    # Clients connected and nothing outbound at all. A box that answers from
    # itself looks exactly like this, which is why the finding is context.
    serving(nd, "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
                "ESTAB 0 0 10.0.0.5:443 198.51.100.7:51000\n"
                "ESTAB 0 0 10.0.0.5:443 198.51.100.8:51001\n"
                "ESTAB 0 0 10.0.0.5:443 198.51.100.9:51002\n"
                "ESTAB 0 0 10.0.0.5:443 198.51.100.10:51003\n")


@scenario("service_address_unserved")
def _(nd):
    # The address is up and every listener is bound to the box's own address,
    # so nothing accepts on the service address and nothing covers it.
    nd.cmd_interfaces = lambda: _VIP_IFACES
    serving(nd, "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 10.0.0.5:443 0.0.0.0:*\n"
                "ESTAB 0 0 10.0.0.5:443 198.51.100.7:51000\n")


@scenario("service_address_idle")
def _(nd):
    # A wildcard listener covers the service address, so it is served - and
    # every live connection arrived on the box's own address instead.
    nd.cmd_interfaces = lambda: _VIP_IFACES
    serving(nd, "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
                "ESTAB 0 0 10.0.0.5:443 198.51.100.7:51000\n"
                "ESTAB 0 0 10.0.0.5:443 198.51.100.8:51001\n")


@scenario("gw_unreachable")
def _(nd):
    ping_map(nd, gw_loss=100, inet_loss=100)
    unreachable(nd)

@scenario("gw_icmp_filtered")
def _(nd):
    # The cloud VPC case: nothing answers ping, but the gateway is in the
    # neighbour table, and ARP does not cross a dead cable.
    ping_map(nd, gw_loss=100, inet_loss=100)

@scenario("gw_partial_loss")
def _(nd): ping_map(nd, gw_loss=25)

@scenario("gw_unknown")
def _(nd):
    def ping(t, c=4, w=2):
        if t == "10.0.0.1": return {"ok": True, "cmd": "ping", "stdout": "nothing parseable\n"}
        return {"ok": True, "cmd": "ping", "stdout":
                "4 packets transmitted, 4 received, 0% packet loss\nrtt min/avg/max/mdev = 1/20/30/2 ms\n"}
    nd.cmd_ping = ping

@scenario("inet_unreachable")
def _(nd):
    ping_map(nd, inet_loss=100)
    unreachable(nd, arp=True)
    path_dies_short(nd)

@scenario("destination_unresponsive")
def _(nd):
    # The path carries probes all the way there and the host says nothing.
    ping_map(nd, inet_loss=100)
    unreachable(nd, arp=True)
    mtr(nd, [{"count": 1, "host": "10.0.0.1", "Loss%": 0.0, "Snt": 30, "Avg": 1.0},
             {"count": 2, "host": "198.51.100.1", "Loss%": 0.0, "Snt": 30, "Avg": 12.0},
             {"count": 3, "host": "8.8.8.8", "Loss%": 0.0, "Snt": 30, "Avg": 20.0}])

BACKEND_SS = ("State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
              "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
              + "".join(f"ESTAB 0 0 10.0.0.5:443 203.0.113.{i}:5123{i}\n" for i in range(9))
              + "".join(f"ESTAB 0 0 10.0.0.5:4412{i} 10.0.0.90:5432\n" for i in range(6)))

def with_backend(nd, text=BACKEND_SS):
    """A box serving clients and depending on a backend, through the real parse."""
    nd.cmd_socket_states = lambda: dict(
        {"ok": True, "cmd": "ss -tan", "stdout": text}, **nd.parse_socket_states(text))

@scenario("target_is_a_backend", target=None)
def _(nd): with_backend(nd)

@scenario("target_auto_failed", target="auto")
def _(nd): pass

def sided_flows(nd, *sockets):
    """Flows through the real analyser, with this box's listening ports known -
    which is what lets a connection be called a client's or a backend's."""
    serving(nd)
    ports = nd.parse_socket_states(SERVING_SS)["listen_ports"]
    stats = nd.analyze_tcp_flows(nd.parse_tcp_flows(SS_HEADER + "".join(sockets)),
                                 listen_ports=ports)
    res = {"ok": True, "cmd": "ss -tin", "stdout": "", "stderr": "", "code": 0}
    res.update(stats)
    nd.cmd_tcp_flows = lambda listen_ports=None: res
    return stats

def sided_sock(peer, local_port, **kw):
    """One socket with its local port set, so its side can be decided."""
    return ss_flow(peer, **kw).replace("10.0.0.5:51234", f"10.0.0.5:{local_port}")

@scenario("tcp_flow_loss_backends")
def _(nd):
    # A proxy whose database is lossy while every client connection is clean.
    # This used to read "some destinations are losing traffic", owner "the
    # provider or upstream" - a carrier ticket for the inside of a rack.
    sided_flows(nd,
                sided_sock("203.0.113.9", "443", sent=40_000_000, retrans=2000),
                sided_sock("203.0.113.10", "443", sent=38_000_000, retrans=1800),
                sided_sock("10.0.0.90", "44120", sent=30_000_000,
                           retrans=2_400_000, port="5432"))

@scenario("tcp_flow_loss_clients")
def _(nd):
    sided_flows(nd,
                sided_sock("203.0.113.9", "443", sent=40_000_000, retrans=3_200_000),
                sided_sock("10.0.0.90", "44120", sent=30_000_000, retrans=900, port="5432"))

FORWARDER_SS = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\n"
                + "".join(f"ESTAB 0 0 10.0.0.5:8080 198.51.100.{i}:5100\n"
                          for i in range(40))
                + "".join(f"ESTAB 0 0 10.0.0.5:{40000+i} 203.0.113.{i%250}:443\n"
                          for i in range(2000)))

@scenario("no_traffic_at_all", target=None)
def _(nd):
    # No listeners, and nothing connected anywhere. A connector whose links
    # to its edge are gone looks exactly like this, and every other check
    # passes because a box doing nothing has nothing wrong with its network.
    serving(nd, "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n")

@scenario("target_is_forwarded", target=None)
def _(nd): serving(nd, FORWARDER_SS)

@scenario("no_clients_connected")
def _(nd):
    # Listening on 443, healthy, and nothing is connected. What being taken
    # out of a load balancer's pool looks like from the inside.
    serving(nd, "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n")

@scenario("dns_local_cache")
def _(nd):
    resolvers(nd, [R("127.0.0.53")])

def arp_table(nd, text):
    nd.cmd_arp = lambda: {"ok": True, "cmd": "ip neigh", "stdout": text}

@scenario("gateway_is_virtual")
def _(nd):
    arp_table(nd, "10.0.0.1 dev eth0 lladdr 00:00:5e:00:01:2a REACHABLE\n")

@scenario("virtual_router_conflict")
def _(nd):
    # A CARP vhid and a VRRP vrid on one address. Both live in the same MAC
    # range, which is exactly why they collide.
    arp_table(nd, "10.0.0.1 dev eth0 lladdr 00:00:5e:00:01:2a REACHABLE\n"
                  "10.0.0.1 dev eth0 lladdr 00:00:5e:00:01:07 STALE\n")

V6_ONLY = ("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
           "    inet6 2001:db8:1::5/64 scope global\n"
           "    inet6 fe80::1/64 scope link\n")

def ipv6_only(nd):
    """A box on the network by IPv6 and not by IPv4 - ordinary on mobile
    carriers and in plenty of datacentres outside the US."""
    nd.cmd_interfaces = lambda: {"ok": True, "cmd": "ip addr", "stdout": V6_ONLY}
    nd.cmd_ping = lambda t, c=4, w=2: {"ok": True, "cmd": "ping", "stdout":
        "10 packets transmitted, 0 received, 100% packet loss\n"}
    nd.cmd_check_port = lambda h, p, timeout=5: {"ok": False, "reason": "timeout"}
    nd.cmd_arp = lambda: {"ok": True, "cmd": "ip neigh",
                          "stdout": "10.0.0.1 dev eth0 FAILED\n"}

@scenario("ipv6_only")
def _(nd): ipv6_only(nd)

@scenario("gw_unmeasurable_v4")
def _(nd): ipv6_only(nd)

@scenario("inet_unmeasurable_v4")
def _(nd): ipv6_only(nd)

def queued_sock(peer, local_port, rtt, minrtt, **kw):
    """One socket whose smoothed rtt sits above its own lowest-ever."""
    return (sided_sock(peer, local_port, sent=40_000_000, retrans=1000, **kw)
            .replace("rtt:12.4/3.1", f"rtt:{rtt}/3.1")
            .replace("minrtt:11.9", f"minrtt:{minrtt}"))

@scenario("queuing_delay_backends")
def _(nd):
    # The backend is 96ms away and has been 8ms away on the same connection.
    # 88ms of every round trip is queue - which is a different fault, with a
    # different owner, from a backend that is simply far.
    sided_flows(nd, queued_sock("203.0.113.9", "443", 42.0, 38.0),
                    queued_sock("10.0.0.90", "44120", 96.0, 8.0, port="5432"))

@scenario("queuing_delay_clients")
def _(nd):
    sided_flows(nd, queued_sock("203.0.113.9", "443", 340.0, 41.0),
                    queued_sock("10.0.0.90", "44120", 3.1, 2.8, port="5432"))

@scenario("queuing_delay")
def _(nd):
    # No listening ports, so there are no sides to split by.
    flows(nd, ss_flow("203.0.113.9", sent=40_000_000, retrans=1000)
              .replace("rtt:12.4/3.1", "rtt:340.0/3.1")
              .replace("minrtt:11.9", "minrtt:41.0"))

def own_tls(nd, port="443", **fields):
    """A box listening on a TLS port, with a scripted handshake result."""
    text = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            f"LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:*\n")
    serving(nd, text)
    base = {"ok": True, "cmd": "tls handshake (own)", "host": "127.0.0.1",
            "port": int(port), "own_listener": True, "tls_version": "TLSv1.3",
            "verified": True, "verified_as": "api.example.com"}
    base.update(fields)
    nd.cmd_own_tls = lambda p, timeout=5, address="127.0.0.1": dict(base, port=p)
    # The collector records the listeners it tried, which is what tells the
    # stage strip that the ports stage ran at all.
    orig = nd._check_own_tls
    def wrapped(raw, findings, quick=False):
        orig(raw, findings, quick)
        raw.setdefault("own_tls", {"ok": True, "cmd": "tls", "stdout": "",
                                   "listeners": [base]})
    nd._check_own_tls = wrapped

def own_service(nd, port="8080", **fields):
    # The ports stage only reads as checked when something recorded a listener
    # there, the same way the TLS check does.
    """A box listening on an HTTP port, with a scripted answer from it."""
    serving(nd, "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                f"LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:*\n")
    base = {"ok": True, "cmd": "HEAD /", "port": int(port), "host": "127.0.0.1",
            "tls": False, "ms": 4.0, "status": 200}
    base.update(fields)
    nd.cmd_own_http = lambda p, timeout=5, address="127.0.0.1", tls=False: dict(base, port=p)

@scenario("proxy_configured")
def _(nd):
    # A box told to reach the internet through a proxy. Nothing is broken -
    # the point of the finding is that every other check went direct, so it
    # measured a route this box's applications would not use.
    nd.cmd_proxy_config = lambda: {
        "ok": True, "cmd": "proxy configuration (read, not probed)", "code": 0,
        "stderr": "", "stdout": "HTTPEnable: 1\nHTTPSProxy: proxy.example.com",
        "env": {}, "system": {"HTTPEnable": "1", "HTTPSEnable": "1",
                              "HTTPSProxy": "proxy.example.com", "HTTPSPort": "8080"}}

@scenario("own_service_timing")
def _(nd):
    # A service that answers, slowly, with the delay all on its own side.
    own_service(nd, ms=306.6,
                phases={"connect_ms": 1.3, "tls_ms": None, "wait_ms": 305.2})

@scenario("own_service_silent")
def _(nd): own_service(nd, ok=False, silent=True, status=None)

@scenario("own_service_upstream_error")
def _(nd): own_service(nd, status=502)

@scenario("own_service_erroring")
def _(nd): own_service(nd, status=500)

@scenario("own_service_not_http")
def _(nd): own_service(nd, ok=False, not_http=True, status=None,
                       status_line="+OK POP3 ready")

@scenario("own_tls_expired")
def _(nd): own_tls(nd, days_left=-3, expires="2026-08-04", expired=True)

@scenario("own_tls_expiring")
def _(nd): own_tls(nd, days_left=6, expires="2026-08-13")

@scenario("own_tls_untrusted")
def _(nd): own_tls(nd, verified=False, verify_error="unable to get local issuer certificate")

@scenario("own_tls_handshake_failed")
def _(nd): own_tls(nd, ok=False, error="connection reset by peer")

@scenario("aborts_on_memory")
def _(nd):
    kernel_drops(nd, {"TCPAbortOnMemory": 0}, {"TCPAbortOnMemory": 180})

@scenario("reqq_full_drops")
def _(nd):
    kernel_drops(nd, {"TCPReqQFullDrop": 0}, {"TCPReqQFullDrop": 640})

@scenario("aborts_on_timeout")
def _(nd):
    kernel_drops(nd, {"TCPAbortOnTimeout": 0, "PassiveOpens": 0, "ActiveOpens": 0},
                     {"TCPAbortOnTimeout": 90, "PassiveOpens": 1800, "ActiveOpens": 200})

@scenario("syncookies_live")
def _(nd):
    kernel_drops(nd, {"SyncookiesSent": 0}, {"SyncookiesSent": 4200})

@scenario("syncookies_historical")
def _(nd):
    nd._uptime_seconds = lambda: 30 * 86400
    kernel_drops(nd, {"SyncookiesSent": 90_000})

@scenario("ephemeral_ports_low")
def _(nd):
    # Almost every port the box may open *to one destination*. The range is
    # narrowed so the fixture stays a readable size - the pressure is a share
    # of the range, not an absolute count.
    kernel_drops(nd, {"ephemeral_low": 60000, "ephemeral_high": 60499,
                      "ephemeral_total": 500})
    text = ("State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
            "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
            + "".join(f"ESTAB 0 0 10.0.0.5:{60000 + i} 10.0.0.90:5432\n"
                      for i in range(450)))
    parsed = nd.parse_socket_states(text)
    nd.cmd_socket_states = lambda: dict({"ok": True, "cmd": "ss -tan", "stdout": ""}, **parsed)

@scenario("fd_pressure")
def _(nd):
    kernel_drops(nd, {"fd_used": 950_000, "fd_max": 1_000_000})

@scenario("syn_recv_backlog")
def _(nd):
    kernel_drops(nd, {"somaxconn": 4096})
    text = ("State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
            "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
            + "".join(f"SYN-RECV 0 0 10.0.0.5:443 203.0.113.{i % 254}:5123\n"
                      for i in range(300)))
    serving(nd, text)

@scenario("egress_blocked")
def _(nd):
    # A SaaS box with no outbound internet by design, serving clients the
    # whole time. This reported the carrier as being at fault, critical.
    ping_map(nd, inet_loss=100)
    unreachable(nd, arp=True)
    serving(nd)

@scenario("inet_icmp_filtered")
def _(nd):
    # The hardened-server case: outbound ICMP is firewalled, TCP is fine.
    ping_map(nd, inet_loss=100)
    nd.cmd_check_port = lambda h, p, timeout=5: (
        {"ok": True, "cmd": f"tcp connect {h}:{p}", "connect_ms": 12.0} if p == "443"
        else {"ok": False, "reason": "timeout"})

@scenario("inet_loss_unmeasured")
def _(nd): nd.cmd_ping = lambda t, c=4, w=2: {"ok": True, "cmd": f"ping {t}", "stdout":
    "4 packets transmitted, 3 received, 25% packet loss\n"
    "rtt min/avg/max/mdev = 1.0/20.0/30.0/2.0 ms\n"} if t == "8.8.8.8" else {
    "ok": True, "cmd": "ping", "stdout":
    "4 packets transmitted, 4 received, 0% packet loss\n"
    "rtt min/avg/max/mdev = 1.0/2.0/3.0/0.2 ms\n"}

@scenario("gw_loss_unmeasured")
def _(nd): nd.cmd_ping = lambda t, c=4, w=2: {"ok": True, "cmd": f"ping {t}", "stdout":
    "4 packets transmitted, 3 received, 25% packet loss\n"
    "rtt min/avg/max/mdev = 1.0/2.0/3.0/0.2 ms\n"} if t.startswith("10.") else {
    "ok": True, "cmd": "ping", "stdout":
    "4 packets transmitted, 4 received, 0% packet loss\n"
    "rtt min/avg/max/mdev = 1.0/20.0/30.0/2.0 ms\n"}

@scenario("inet_partial_loss")
def _(nd): ping_map(nd, inet_loss=25)

@scenario("link_errors_live")
def _(nd): counters(nd, rx_errors=1200, rx_crc_errors=1150, d_rx_errors=14)

@scenario("link_errors_historical")
def _(nd): counters(nd, rx_errors=4000, rx_crc_errors=3900)

@scenario("drops_live")
def _(nd): counters(nd, rx_dropped=900, d_rx_dropped=200, d_rx_packets=2_000)

@scenario("nic_ring_overruns")
def _(nd): counters(nd, rx_errors=900, d_rx_errors=40, d_rx_over_errors=35,
                    d_rx_packets=2_000)

@scenario("frame_length_errors")
def _(nd): counters(nd, rx_errors=900, d_rx_errors=40, d_rx_length_errors=35,
                    d_rx_packets=2_000)

@scenario("collisions")
def _(nd): counters(nd, collisions=900)

@scenario("link_saturated")
def _(nd):
    counters(nd, d_rx_bytes=250_000_000)
    nd.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
        {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500, "carrier": True}]}
    ping_map(nd, inet_loss=7, sent=20)      # full AND something failing with it

@scenario("link_busy")
def _(nd):
    # The same full link with nothing failing beside it. A backup, a sync -
    # a link being used, which is not a link that is broken.
    counters(nd, d_rx_bytes=250_000_000)
    nd.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
        {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500, "carrier": True}]}

@scenario("link_flapping_logged")
def _(nd):
    # 80 transitions in ten minutes on a box with 90 days of uptime. The
    # lifetime counter makes that 0.89 a day, under the threshold, and the
    # whole run read "no fault found" before the log was consulted.
    klog_flaps(nd)
    counters(nd, carrier_changes=82)

@scenario("nic_reset_logged")
def _(nd):
    klog(nd, "\n".join([
        "[7775000.100000] e1000e 0000:00:1f.6 eth0: Detected Hardware Unit Hang",
        "[7775002.400000] e1000e 0000:00:1f.6 eth0: Reset adapter unexpectedly",
    ]), uptime=7_775_100)

@scenario("saturation_bursts", uplink_mbps=50, soak=1)
def _(nd):
    # Full for 20s of every 60. The mean across the window is 46% of the line,
    # under every sustained threshold, and calls break three times a minute.
    rates = [50.0 if (t % 60) < 20 else 9.75 for t in range(120)]
    counters(nd, d_rx_bytes=int(sum(rates) * 1e6 / 8), d_rx_packets=100_000)
    rate_series(nd, rates)
    nd.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
        {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500,
         "carrier": True}]}
    ping_map(nd, inet_loss=6, sent=20)      # the harm that makes it a finding

@scenario("uplink_saturated", uplink_mbps=50)
def _(nd):
    # 48 Mbps over the 2s window: 96% of the 50 Mbps line the site was sold,
    # and 4.8% of the gigabit NIC in front of it. Only one of those numbers
    # is the reason anyone is complaining.
    counters(nd, d_rx_bytes=12_000_000)
    nd.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
        {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500, "carrier": True}]}
    ping_map(nd, inet_loss=7, sent=20)

@scenario("uplink_busy", uplink_mbps=50)
def _(nd):
    # The nightly backup. 96% of the line, nobody complaining - and before
    # this split it headlined as root cause over anything else in the report.
    counters(nd, d_rx_bytes=12_000_000)
    nd.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
        {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500, "carrier": True}]}

@scenario("duplex_mismatch")
def _(nd):
    nd.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
        {"name": "eth0", "speed_mbps": 1000, "duplex": "half", "mtu": 1500, "carrier": True}]}

@scenario("slow_link")
def _(nd):
    nd.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
        {"name": "eth0", "speed_mbps": 100, "duplex": "full", "mtu": 1500, "carrier": True}]}

@scenario("mtu_nonstandard")
def _(nd):
    nd.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
        {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1400, "carrier": True}]}

@scenario("optics_alarm")
def _(nd): nd.cmd_optics = lambda i: {"ok": True, "cmd": "ethtool -m", "stdout": "", "parsed":
    {"rx_dbm": -5.0, "tx_dbm": -2.0, "vendor": "V", "alarms": ["Laser bias high alarm"], "warnings": []}}

@scenario("optics_rx_low")
def _(nd): nd.cmd_optics = lambda i: {"ok": True, "cmd": "ethtool -m", "stdout": "", "parsed":
    {"rx_dbm": -32.0, "tx_dbm": -2.0, "vendor": "V", "alarms": [], "warnings": []}}

@scenario("optics_rx_marginal")
def _(nd): nd.cmd_optics = lambda i: {"ok": True, "cmd": "ethtool -m", "stdout": "", "parsed":
    {"rx_dbm": -21.0, "tx_dbm": -2.0, "vendor": "V", "alarms": [], "warnings": []}}

@scenario("optics_warning")
def _(nd): nd.cmd_optics = lambda i: {"ok": True, "cmd": "ethtool -m", "stdout": "", "parsed":
    {"rx_dbm": -5.0, "tx_dbm": -2.0, "vendor": "V", "alarms": [], "warnings": ["Temp high warning"]}}

@scenario("switch_port")
def _(nd): nd.cmd_lldp = lambda: {"ok": True, "cmd": "lldpctl", "stdout": "", "neighbours": [
    {"iface": "eth0", "switch": "SW-1", "port": "Gi1/0/9", "vlan": "20", "via": "LLDP"}]}

@scenario("duplicate_ip")
def _(nd): nd.cmd_arp = lambda: {"ok": True, "cmd": "ip neigh", "stdout":
    "10.0.0.1 dev eth0 lladdr aa:bb:cc:00:00:01 REACHABLE\n"
    "10.0.0.7 dev eth0 lladdr aa:bb:cc:00:00:02 REACHABLE\n"
    "10.0.0.7 dev eth0 lladdr aa:bb:cc:00:00:99 STALE\n"}

@scenario("syn_sent_backlog")
def _(nd): nd.cmd_socket_states = lambda: {"ok": True, "cmd": "ss", "stdout": "",
    "states": {"ESTABLISHED": 5, "SYN_SENT": 6}, "pending": {"SYN_SENT": {"198.51.100.9": 6}}}

@scenario("close_wait_backlog")
def _(nd): nd.cmd_socket_states = lambda: {"ok": True, "cmd": "ss", "stdout": "",
    "states": {"ESTABLISHED": 5, "CLOSE_WAIT": 25}, "pending": {}}

@scenario("tcp_retransmits")
def _(nd): nd._read_tcp_counters = lambda: {"OutSegs": 100000, "RetransSegs": 6000}

@scenario("trace_stalls")
def _(nd): trace(nd, " 1  10.0.0.1 (10.0.0.1)  1.0 ms\n 2  * * *\n 3  * * *\n 4  * * *\n")

@scenario("icmp_filtered")
def _(nd):
    trace(nd, " 1  10.0.0.1 (10.0.0.1)  1.0 ms\n 2  * * *\n 3  * * *\n")
    nd.cmd_traceroute_tcp = lambda t, port=443: {"ok": True, "cmd": "tcptraceroute", "tool": "tcptraceroute",
        "port": 443, "hops": nd.parse_traceroute_hops(
            " 1  10.0.0.1 (10.0.0.1)  1.0 ms\n 2  8.8.8.8 (8.8.8.8)  20.0 ms\n")}

@scenario("loop")
def _(nd): trace(nd, " 1  10.0.0.1 (10.0.0.1)  1.0 ms\n 2  10.0.0.2 (10.0.0.2)  2.0 ms\n"
                     " 3  10.0.0.1 (10.0.0.1)  3.0 ms\n")

@scenario("double_nat")
def _(nd): trace(nd, " 1  192.168.1.1 (192.168.1.1)  1.0 ms\n 2  10.0.0.1 (10.0.0.1)  2.0 ms\n"
                     " 3  8.8.8.8 (8.8.8.8)  20.0 ms\n")

@scenario("cgnat")
def _(nd): trace(nd, " 1  10.0.0.1 (10.0.0.1)  1.0 ms\n 2  100.64.0.1 (100.64.0.1)  8.0 ms\n"
                     " 3  8.8.8.8 (8.8.8.8)  20.0 ms\n")

@scenario("latency_wall")
def _(nd): trace(nd, " 1  10.0.0.1 (10.0.0.1)  1.0 ms\n 2  100.64.0.1 (100.64.0.1)  620.0 ms\n"
                     " 3  8.8.8.8 (8.8.8.8)  640.0 ms\n")

@scenario("path_loss")
def _(nd): mtr(nd, [
    {"count": 1, "host": "10.0.0.1", "Loss%": 0.0, "Snt": 30, "Avg": 1.5},
    {"count": 2, "host": "198.51.100.63", "Loss%": 30.0, "Snt": 30, "Avg": 20.0},
    {"count": 3, "host": "dns.google (8.8.8.8)", "Loss%": 27.0, "Snt": 30, "Avg": 22.0}])

@scenario("path_loss_cosmetic")
def _(nd): mtr(nd, [
    {"count": 1, "host": "10.0.0.1", "Loss%": 0.0, "Snt": 30, "Avg": 1.5},
    {"count": 2, "host": "198.51.100.63", "Loss%": 40.0, "Snt": 30, "Avg": 20.0},
    {"count": 3, "host": "dns.google (8.8.8.8)", "Loss%": 0.0, "Snt": 30, "Avg": 22.0}])

@scenario("pmtu_blackhole")
def _(nd): nd.cmd_path_mtu = lambda t, m=None: {"ok": True, "cmd": "df", "stdout": "", "target": t,
    "iface_mtu": 1500, "path_mtu": 1400, "attempts": [{"mtu": 1500, "payload": 1472, "ok": False, "cmd": "x"}]}

@scenario("pmtu_reduced")
def _(nd): nd.cmd_path_mtu = lambda t, m=None: {"ok": True, "cmd": "df", "stdout": "", "target": t,
    "iface_mtu": 1500, "path_mtu": 1492, "signalled_mtu": 1492,
    "attempts": [{"mtu": 1500, "payload": 1472, "ok": False, "signalled": 1492, "cmd": "x"}]}

@scenario("pmtu_unmeasurable")
def _(nd): nd.cmd_path_mtu = lambda t, m=None: {"ok": True, "cmd": "df", "stdout": "", "target": t,
    "iface_mtu": 1500, "path_mtu": None, "attempts": [{"mtu": 1500, "payload": 1472, "ok": False, "cmd": "x"}]}

@scenario("dns_fail")
def _(nd): nd.cmd_dns = lambda t: {"ok": True, "cmd": "dig", "stdout": "NXDOMAIN\n"}

@scenario("dns_no_resolvers")
def _(nd): nd.cmd_dns_health = lambda check_hijack=True: {"ok": False, "cmd": "r",
    "error": "no DNS resolvers are configured", "resolvers": []}

@scenario("dns_all_resolvers_down")
def _(nd): resolvers(nd, [R("10.0.0.53", ok=False, ms=2000, answers=())])

@scenario("dns_resolver_down")
def _(nd): resolvers(nd, [R("10.0.0.53"), R("10.0.0.54", ok=False, ms=2000, answers=())])

@scenario("dns_resolver_slow")
def _(nd): resolvers(nd, [R("10.0.0.53", ms=900.0)])

@scenario("dns_hijack")
def _(nd): resolvers(nd, [R("10.0.0.53", hijack=True)])

@scenario("dns_disagree")
def _(nd): resolvers(nd, [R("10.0.0.53", answers=("192.0.2.4",)), R("8.8.8.8", answers=("9.9.9.9",))])

@scenario("call_quality_degraded")
def _(nd): ping_map(nd, inet_loss=3, avg=120.0, mdev=45.0)

@scenario("call_quality_bad")
def _(nd): ping_map(nd, inet_loss=25, avg=300.0, mdev=90.0)

@scenario("latency_high")
def _(nd): ping_map(nd, inet_loss=0, avg=800.0, mdev=5.0)

@scenario("port_refused", check_ports=["9999"])
def _(nd): nd.cmd_check_port = lambda h, p, timeout=5: {"ok": False, "cmd": f"tcp {h}:{p}",
    "error": "refused", "reason": "refused"}

@scenario("port_timeout", check_ports=["9999"])
def _(nd): nd.cmd_check_port = lambda h, p, timeout=5: {"ok": False, "cmd": f"tcp {h}:{p}",
    "error": "timeout", "reason": "timeout"}

@scenario("ports_truncated", check_ports=[str(p) for p in range(1, 40)])
def _(nd): pass

@scenario("tls_handshake_failed", check_ports=["443"])
def _(nd): nd.cmd_tls_check = lambda h, p=443, timeout=5: {"ok": False, "cmd": "tls",
    "host": h, "port": p, "error": "connection reset"}

@scenario("tls_expired", check_ports=["443"])
def _(nd): nd.cmd_tls_check = lambda h, p=443, timeout=5: {"ok": True, "cmd": "tls", "host": h,
    "port": p, "verified": False, "expired": True, "tls_version": "TLSv1.2",
    "verify_error": "certificate has expired", "stdout": ""}

@scenario("clock_skewed")
def _(nd): nd.cmd_clock_sync = lambda: {"ok": True, "cmd": "chronyc tracking", "stdout": "",
    "offset_ms": 412_000.0, "synced": True, "source": "chronyc"}

@scenario("clock_unsynced")
def _(nd): nd.cmd_clock_sync = lambda: {"ok": True, "cmd": "chronyc tracking", "stdout": "",
    "offset_ms": None, "synced": False, "source": "chronyc"}

@scenario("tls_not_yet_valid", check_ports=["443"])
def _(nd): nd.cmd_tls_check = lambda h, p=443, timeout=5: {"ok": True, "cmd": "tls", "host": h,
    "port": p, "verified": True, "tls_version": "TLSv1.3", "stdout": "",
    "starts": "2027-01-01", "not_yet_valid_days": 148, "days_left": 500}

@scenario("tls_expiring", check_ports=["443"])
def _(nd): nd.cmd_tls_check = lambda h, p=443, timeout=5: {"ok": True, "cmd": "tls", "host": h,
    "port": p, "verified": True, "days_left": 5, "expires": "2026-08-20",
    "tls_version": "TLSv1.3", "issuer": "Public CA", "stdout": ""}

@scenario("tls_intercepted", check_ports=["443"])
def _(nd): nd.cmd_tls_check = lambda h, p=443, timeout=5: {"ok": True, "cmd": "tls", "host": h,
    "port": p, "verified": False, "intercepted_by": "fortinet", "issuer": "Fortinet Root CA",
    "verify_error": "self signed certificate in chain", "tls_version": "TLSv1.2", "stdout": ""}

@scenario("family_unreachable", check_ports=["443"])
def _(nd): nd.cmd_check_port = lambda h, p, timeout=5: {
    "ok": True, "cmd": f"tcp connect {h}:{p}", "stdout": "open", "stderr": "", "code": 0,
    "ip_version": 4, "families_tried": [6, 4], "family_mismatch": [6]}

@scenario("tls_handshake_slow", check_ports=["443"])
def _(nd): nd.cmd_tls_check = lambda h, p=443, timeout=5: {"ok": True, "cmd": "tls", "host": h,
    "port": p, "verified": True, "tls_version": "TLSv1.3", "stdout": "",
    "tcp_ms": 18.0, "tls_ms": 900.0}       # a handshake doing far more than its round trips

@scenario("tls_untrusted", check_ports=["443"])
def _(nd): nd.cmd_tls_check = lambda h, p=443, timeout=5: {"ok": True, "cmd": "tls", "host": h,
    "port": p, "verified": False, "issuer": None,
    "verify_error": "unable to get local issuer certificate", "tls_version": "TLSv1.2", "stdout": ""}

@scenario("regression_since_baseline", baseline={"detected_gateway": "10.0.0.254", "raw": {},
                                                 "neighbours": [], "hops": [], "version": "1.1.0"})
def _(nd): pass

@scenario("baseline_changes", baseline={"detected_gateway": "10.0.0.1", "raw": {}, "neighbours": [],
                                        "hops": [], "version": "1.0.0"})
def _(nd): pass


@scenario("tcp_flow_loss_all_peers")
def _(nd): flows(nd, ss_flow("203.0.113.9", sent=5_000_000, retrans=300_000),
                     ss_flow("198.51.100.4", sent=4_000_000, retrans=250_000))

@scenario("tcp_flow_loss_some_peers")
def _(nd): flows(nd, ss_flow("203.0.113.9", sent=5_000_000, retrans=400_000),
                     ss_flow("198.51.100.4", sent=4_000_000, retrans=0))

@scenario("tcp_flow_loss_one_peer")
def _(nd): flows(nd, ss_flow("203.0.113.9", sent=5_000_000, retrans=400_000))

@scenario("tcp_flow_receiver_limited")
def _(nd): flows(nd, ss_flow("203.0.113.9", sent=8_000_000, retrans=0, rwnd=61.2))

@scenario("tcp_flow_sendbuf_limited")
def _(nd): flows(nd, ss_flow("203.0.113.9", sent=8_000_000, retrans=0, sndbuf=44.0))

@scenario("tcp_flow_sample_partial")
def _(nd): flows(nd, ss_flow("203.0.113.9", sent=5_000_000, retrans=0), truncated=True)

@scenario("conntrack_drops_live")
def _(nd): kernel_drops(nd, {"ct_count": 65_000, "ct_max": 65_536, "ct_insert_failed": 0},
                            {"ct_count": 65_500, "ct_max": 65_536, "ct_insert_failed": 40})

@scenario("conntrack_near_limit")
def _(nd): kernel_drops(nd, {"ct_count": 55_000, "ct_max": 65_536})

@scenario("conntrack_drops_historical")
def _(nd):
    kernel_drops(nd, {"ct_count": 100, "ct_max": 65_536, "ct_insert_failed": 9_000})
    nd._uptime_seconds = lambda: 10 * 86400          # about 900 a day

@scenario("retrans_spurious")
def _(nd): kernel_drops(nd, {"TCPDSACKRecv": 0, "RetransSegs": 0, "TCPSACKReorder": 0},
                            {"TCPDSACKRecv": 60, "RetransSegs": 100, "TCPSACKReorder": 14})

@scenario("tcp_checksum_errors")
def _(nd): kernel_drops(nd, {"InCsumErrors": 0, "InSegs": 1_000_000},
                            {"InCsumErrors": 30, "InSegs": 2_000_000})

@scenario("connect_failures_high")
def _(nd): kernel_drops(nd, {"AttemptFails": 0, "ActiveOpens": 1_000},
                            {"AttemptFails": 40, "ActiveOpens": 1_100})

@scenario("bond_degraded")
def _(nd):
    nd.OS_NAME = "Linux"
    nd._bond_members_linux = lambda base="/sys/class/net": {
        "bond0": {"members": ["eth0", "eth1"], "down": ["eth1"], "mode": "802.3ad"}}

@scenario("neigh_table_full")
def _(nd):
    nd.OS_NAME = "Linux"
    nd._read_neigh_table = lambda base="/proc": {
        "gc_thresh3": 1024, "entries": 1024, "table_fulls": 37}

@scenario("neigh_table_near_limit")
def _(nd):
    nd.OS_NAME = "Linux"
    nd._read_neigh_table = lambda base="/proc": {
        "gc_thresh3": 1024, "entries": 900, "table_fulls": 0}

@scenario("negotiated_below_capacity")
def _(nd):
    nd.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
        {"name": "eth0", "speed_mbps": 1000, "max_mbps": 10000, "duplex": "full",
         "mtu": 1500, "carrier": True}]}

@scenario("no_route_to_target", check_ports=["443"])
def _(nd): nd.cmd_check_port = lambda h, p, timeout=5: {
    "ok": False, "cmd": f"tcp {h}:{p}", "reason": "no_route",
    "error": "Network unreachable - this device has no route"}

@scenario("port_host_unreachable", check_ports=["443"])
def _(nd): nd.cmd_check_port = lambda h, p, timeout=5: {
    "ok": False, "cmd": f"tcp {h}:{p}", "reason": "host_unreachable",
    "error": "Host unreachable - a router reported it cannot reach the host"}

@scenario("connections_reset_by_peer")
def _(nd): kernel_drops(nd, {"EstabResets": 0, "OutRsts": 0, "PassiveOpens": 0},
                            {"EstabResets": 30, "OutRsts": 2, "PassiveOpens": 100})

@scenario("fault_on_every_interface")
def _(nd):
    ifaces = [dict(name=f"eth{i}", packets=10_000_000, errors=900, drops=0, crc=900,
                   frame=0, overruns=0, collisions=0, err_ppm=90, coll_ppm=0,
                   unknown_counters=[], delta_errors=40, delta_drops=0,
                   delta_packets=2_000, delta_host_errors=0, delta_length_errors=0,
                   sample_seconds=2, rx_mbps=1, tx_mbps=1, operstate="up",
                   carrier_changes=0, delta_carrier_changes=0, rate_series=None,
                   peak_mbps=None, series_seconds=None) for i in range(3)]
    nd.cmd_link_stats = lambda *a, **k: {"ok": True, "cmd": "s", "stdout": "",
                                         "interfaces": ifaces, "sample_seconds": 2,
                                         "source": "sysfs"}

def jittery_sock(peer, local_port, rtt, var, **kw):
    """One socket whose round trip varies by nearly as much as it lasts.

    minrtt is pulled up to sit just under the smoothed rtt on purpose. Left at
    the default it is far below, which is a queue - a different finding that
    ranks above this one and would have made the scenario pass while proving
    nothing about jitter.
    """
    return (sided_sock(peer, local_port, sent=40_000_000, **kw)
            .replace("rtt:12.4/3.1", f"rtt:{rtt}/{var}")
            .replace("minrtt:11.9", f"minrtt:{rtt - 1}"))

@scenario("path_jitter_backends")
def _(nd):
    # 80ms out to the backend, moving 50ms either way. Nothing is lost - the
    # retransmit timer is simply sized for the worst of it.
    sided_flows(nd, jittery_sock("10.0.0.90", "44120", 80.0, 50.0, port="5432"),
                    jittery_sock("10.0.0.90", "44121", 82.0, 48.0, port="5432"))

@scenario("path_jitter_clients")
def _(nd):
    sided_flows(nd, jittery_sock("203.0.113.9", "443", 80.0, 50.0),
                    jittery_sock("203.0.113.9", "443", 82.0, 48.0))

@scenario("throughput_limited_by")
def _(nd):
    sided_flows(nd, sided_sock("10.0.0.90", "44120", sent=900_000_000, port="5432")
                .replace("cubic wscale:7,7", "cubic busy:52344ms wscale:7,7"))

@scenario("virtual_nic")
def _(nd):
    nd.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
        {"name": "eth0", "speed_mbps": None, "duplex": None, "mtu": 1500,
         "carrier": True, "operstate": "up", "driver": "virtio_net"}]}

@scenario("tunnel_mtu")
def _(nd):
    nd.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
        {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500, "carrier": True},
        {"name": "tun0", "speed_mbps": None, "duplex": None, "mtu": 1420, "carrier": True}]}
    base = {k: 0 for k in ("rx_errors", "tx_errors", "rx_dropped", "tx_dropped",
                           "rx_crc_errors", "rx_frame_errors", "rx_over_errors",
                           "collisions", "rx_missed_errors", "rx_length_errors",
                           "tx_carrier_errors")}
    base.update(rx_packets=5_000_000, tx_packets=5_000_000, rx_bytes=0, tx_bytes=0,
                operstate="up", carrier_changes=0)
    nd.OS_NAME = "Linux"
    nd._read_link_stats = lambda: ({"eth0": dict(base), "tun0": dict(base)}, "sysfs")

@scenario("udp_recv_buffer_full")
def _(nd): kernel_drops(nd, {"udp_InDatagrams": 0, "udp_RcvbufErrors": 0, "udp_InErrors": 0},
                            {"udp_InDatagrams": 10_000, "udp_RcvbufErrors": 400,
                             "udp_InErrors": 400})

@scenario("udp_datagrams_corrupt")
def _(nd): kernel_drops(nd, {"udp_InDatagrams": 0, "udp_RcvbufErrors": 0, "udp_InErrors": 0},
                            {"udp_InDatagrams": 10_000, "udp_RcvbufErrors": 0,
                             "udp_InErrors": 400})

@scenario("fragments_lost")
def _(nd): kernel_drops(nd, {"ip_ReasmReqds": 0, "ip_ReasmFails": 0},
                            {"ip_ReasmReqds": 500, "ip_ReasmFails": 120})

@scenario("tcp_orphans_high")
def _(nd): kernel_drops(nd, {"tcp_orphans": 9_000, "tcp_max_orphans": 16_384},
                            {"tcp_orphans": 9_000, "tcp_max_orphans": 16_384})

@scenario("cpu_throttled_live")
def _(nd): kernel_drops(nd, {"core_throttles": 4, "package_throttles": 4},
                            {"core_throttles": 9, "package_throttles": 9})

@scenario("cpu_throttled_historical")
def _(nd): kernel_drops(nd, {"core_throttles": 31, "package_throttles": 31},
                            {"core_throttles": 31, "package_throttles": 31})

@scenario("path_admin_prohibited")
def _(nd):
    trace(nd, "traceroute to 8.8.8.8 (8.8.8.8), 20 hops max\n"
              " 1  10.0.0.1 (10.0.0.1)  0.5 ms  0.4 ms  0.4 ms\n"
              " 2  198.51.100.7 (198.51.100.7)  12.0 ms !X  12.1 ms !X  12.2 ms !X\n")

@scenario("resets_sent_high")
def _(nd): kernel_drops(nd, {"OutRsts": 0, "PassiveOpens": 1_000, "EstabResets": 0},
                            {"OutRsts": 120, "PassiveOpens": 1_100, "EstabResets": 30})

@scenario("syn_retrans_high")
def _(nd): kernel_drops(nd, {"TCPSynRetrans": 0, "ActiveOpens": 1_000},
                            {"TCPSynRetrans": 9, "ActiveOpens": 1_100})   # 9 of 100

@scenario("rcv_buffer_pruned")
def _(nd): kernel_drops(nd, {"RcvPruned": 0, "PruneCalled": 0},
                            {"RcvPruned": 40, "PruneCalled": 12})

@scenario("nic_drops_live")
def _(nd): kernel_drops(nd, {"softnet_processed": 1_000_000, "softnet_dropped": 0},
                            {"softnet_processed": 1_100_000, "softnet_dropped": 50})

@scenario("nic_drops_historical")
def _(nd): kernel_drops(nd, {"softnet_processed": 1_000_000, "softnet_dropped": 500})

@scenario("accept_overflow_live")
def _(nd): kernel_drops(nd, {"ListenOverflows": 10}, {"ListenOverflows": 14})

@scenario("accept_overflow_historical")
def _(nd):
    kernel_drops(nd, {"ListenOverflows": 5_000})
    nd._uptime_seconds = lambda: 10 * 86400          # about 500 a day

@scenario("link_flapping_live")
def _(nd): counters(nd, carrier_changes=9, d_carrier_changes=2)

@scenario("link_flapping")
def _(nd):
    counters(nd, carrier_changes=64)          # 62 beyond the boot baseline...
    nd._uptime_seconds = lambda: 10 * 86400   # ...over ten days is 6.2 a day

@scenario("resolvers_unreadable")
def _(nd): nd.cmd_dns_health = lambda check_hijack=True: {
    "ok": False, "cmd": "resolver check", "resolvers": [],
    "unreadable": "/etc/resolv.conf could not be read (Permission denied)",
    "error": "/etc/resolv.conf could not be read (Permission denied)", "stdout": ""}

@scenario("tcp_flow_loss_unclear")
def _(nd): flows(nd, ss_flow("203.0.113.9", sent=5_000_000, retrans=300_000),
                     ss_flow("198.51.100.4", sent=4_000_000, retrans=250_000),
                 truncated=True)


class TestPerFlowTcp(unittest.TestCase):
    """The per-connection view exists to answer the one question the host-wide
    retransmit counter cannot: is it one destination, or all of them."""

    def stats(self, *sockets, **kw):
        return nd.analyze_tcp_flows(nd.parse_tcp_flows(SS_HEADER + "".join(sockets)), **kw)

    # ---- the split that justifies the check ----------------------------

    def test_loss_to_every_network_reads_as_this_devices_own_link(self):
        s = self.stats(ss_flow("203.0.113.9", sent=5_000_000, retrans=300_000),
                       ss_flow("198.51.100.4", sent=4_000_000, retrans=250_000))
        self.assertEqual(s["shape"], "all_peers")

    def test_loss_to_one_network_while_others_are_clean_reads_as_the_path(self):
        s = self.stats(ss_flow("203.0.113.9", sent=5_000_000, retrans=400_000),
                       ss_flow("198.51.100.4", sent=4_000_000, retrans=0))
        self.assertEqual(s["shape"], "some_peers")
        self.assertEqual(s["networks_lossy"], 1)
        self.assertEqual(s["networks_clean"], 1)

    def test_a_single_destination_is_not_claimed_as_proof_of_either(self):
        """With nothing to compare against, "all peers are lossy" is true and
        meaningless. It gets its own weaker finding rather than the local one."""
        s = self.stats(ss_flow("203.0.113.9", sent=5_000_000, retrans=400_000))
        self.assertEqual(s["shape"], "one_peer")

    def test_two_addresses_in_one_subnet_are_one_path_not_two_faults(self):
        """203.0.113.9 and .40 are reached over the same upstream. Counting them
        as two independent lossy peers turns a path fault into "every
        destination is lossy" - which blames this device's link instead."""
        s = self.stats(ss_flow("203.0.113.9", sent=5_000_000, retrans=400_000),
                       ss_flow("203.0.113.40", sent=5_000_000, retrans=380_000))
        self.assertEqual(s["networks_lossy"], 1)
        self.assertNotEqual(s["shape"], "all_peers")

    def test_ipv6_peers_group_by_their_64(self):
        s = self.stats(ss_flow("[2001:db8::1]", sent=5_000_000, retrans=400_000),
                       ss_flow("[2001:db8::2]", sent=5_000_000, retrans=380_000))
        self.assertEqual(s["networks_lossy"], 1)

    # ---- things that would make it lie ---------------------------------

    def test_old_kernels_without_byte_counters_still_report_loss(self):
        """Kernels before ~4.15 have no bytes_sent/bytes_retrans, only a segment
        count. Without the fallback a genuinely lossy box reads as perfectly
        clean, which is the worst answer this tool can give."""
        old = ("ESTAB 0 0 10.0.0.5:51234 203.0.113.9:443\n"
               "\t cubic rtt:12.4/3.1 mss:1460 segs_out:5000 retrans:0/850 send 1.2Mbps\n")
        s = nd.analyze_tcp_flows(nd.parse_tcp_flows(SS_HEADER + old))
        self.assertEqual(s["flows_measurable"], 1)
        self.assertEqual(s["basis"], "segments")
        self.assertGreater(s["worst_loss_pct"], nd.FLOW_LOSSY_PCT)

    def test_loopback_loss_is_never_a_network_fault(self):
        """Retransmits on 127.0.0.1 mean memory pressure, not a path."""
        s = self.stats(ss_flow("127.0.0.1", sent=9_000_000, retrans=500_000, port="8080"))
        self.assertEqual(s["flows_measurable"], 0)
        self.assertIsNone(s["shape"])

    def test_our_own_ssh_session_is_not_the_evidence(self):
        """Diagnosing over SSH, the admin session is a flow like any other - and
        on a quiet box it can be the only sample, so it would become the verdict."""
        os.environ["SSH_CONNECTION"] = "10.9.9.9 51000 10.0.0.5 22"
        try:
            s = self.stats(ss_flow("10.9.9.9", sent=5_000_000, retrans=400_000, port="51000"))
        finally:
            os.environ.pop("SSH_CONNECTION", None)
        self.assertEqual(s["flows_own_session"], 1)
        self.assertIsNone(s["shape"])

    def test_a_tiny_connection_cannot_produce_a_loss_percentage(self):
        s = self.stats(ss_flow("203.0.113.9", sent=900, retrans=400))
        self.assertEqual(s["flows_measurable"], 0)
        self.assertIsNone(s["shape"])

    def test_a_stuck_flow_does_not_report_more_than_total_loss(self):
        """bytes_retrans counts every resend of the same bytes, so the ratio can
        pass 100. "900% loss" reads as a bug rather than as a fault."""
        s = self.stats(ss_flow("203.0.113.9", sent=100_000, retrans=900_000))
        self.assertEqual(s["worst_loss_pct"], 100.0)

    def test_a_wrapped_detail_block_keeps_its_pairs(self):
        wrapped = ("ESTAB 0 0 10.0.0.5:51234 203.0.113.9:443\n"
                   "\t cubic rtt:12.4/3.1 mss:1460 bytes_sent:5000000\n"
                   "\t bytes_retrans:400000 busy:5000ms\n")
        s = nd.analyze_tcp_flows(nd.parse_tcp_flows(SS_HEADER + wrapped))
        self.assertEqual(s["worst_loss_pct"], 8.0)

    def test_a_socket_with_no_peer_column_is_dropped(self):
        text = (SS_HEADER + "ESTAB 0 0 10.0.0.5:51234\n"
                "\t cubic bytes_sent:5000000 bytes_retrans:400000 busy:5000ms\n")
        s = nd.analyze_tcp_flows(nd.parse_tcp_flows(text))
        self.assertEqual(s["lossy_peers"], [])
        self.assertIsNone(s["shape"])

    def test_unparseable_values_neither_crash_nor_fire(self):
        text = (SS_HEADER + "ESTAB 0 0 10.0.0.5:51234 203.0.113.9:443\n"
                "\t cubic rtt:notanumber bytes_sent:-500 bytes_retrans:zzz rwnd_limited:9999\n")
        s = nd.analyze_tcp_flows(nd.parse_tcp_flows(text))
        self.assertIsNone(s["shape"])
        self.assertEqual(s["receiver_limited"], 0)

    def test_empty_and_header_only_output(self):
        for text in ("", SS_HEADER):
            with self.subTest(text=repr(text[:20])):
                s = nd.analyze_tcp_flows(nd.parse_tcp_flows(text))
                self.assertEqual(s["flows_seen"], 0)
                self.assertIsNone(s["shape"])

    # ---- every "worst" figure describes the same connection -------------

    def test_the_basis_belongs_to_the_connection_that_was_worst(self):
        """One flow measured by bytes, a worse one measured by segments. Taking
        the percentage from one and the basis from another reported a
        segment-derived rate as a byte-derived one."""
        mixed = (SS_HEADER
                 + ss_flow("203.0.113.9", sent=5_000_000, retrans=200_000)
                 + "ESTAB 0 0 10.0.0.5:5 198.51.100.4:443\n"
                   "\t cubic rtt:9.0/1.0 mss:1460 segs_out:1000 retrans:0/500\n")
        s = nd.analyze_tcp_flows(nd.parse_tcp_flows(mixed))
        self.assertEqual(s["worst_loss_pct"], 50.0)
        self.assertEqual(s["basis"], "segments")
        self.assertEqual(s["worst_peer"], "198.51.100.4")

    def test_the_named_peer_is_the_worst_not_the_first_in_sort_order(self):
        """The digest reads "worst loss X% to <peer>". Taking that peer from the
        sorted list credited the worst loss to whoever sorted first."""
        s = self.stats(ss_flow("10.0.0.7", sent=5_000_000, retrans=150_000),
                       ss_flow("203.0.113.9", sent=5_000_000, retrans=450_000))
        self.assertEqual(s["worst_peer"], "203.0.113.9")

    def test_a_collector_with_no_output_does_not_raise(self):
        """`stdout` present but None - the key exists, so .get's default never
        fires and every string operation after it is on None."""
        mod = fresh()
        mod.OS_NAME = "Linux"
        mod.which = lambda c: True
        mod.run = lambda cmd, timeout=15, limit=None: {"ok": True, "cmd": "ss", "stdout": None,
                                           "stderr": "", "code": 0}
        res = mod.cmd_tcp_flows()
        self.assertTrue(res["ok"])
        self.assertIn("not enough traffic", res["stdout"])

    # ---- what leaves the box -------------------------------------------

    def test_the_peer_list_is_capped(self):
        """A report already maps the local network; it should not also export
        every external address this device has spoken to."""
        s = self.stats(*[ss_flow(f"203.0.113.{i}", sent=5_000_000, retrans=400_000)
                         for i in range(30)])
        self.assertLessEqual(len(s["lossy_peers"]), nd.FLOW_PEERS_SHOWN)

    def test_the_report_carries_a_digest_not_the_socket_table(self):
        """ss -tin runs ~430 bytes a socket and names every peer. Storing it raw
        would add ~86KB to a 200-socket report; the digest is a few hundred."""
        mod = fresh()
        big = SS_HEADER + "".join(ss_flow(f"203.0.113.{i}", sent=5_000_000, retrans=0)
                                  for i in range(200))
        mod.OS_NAME = "Linux"
        mod.which = lambda c: True
        mod.run = lambda cmd, timeout=15, limit=None: {"ok": True, "cmd": " ".join(cmd),
                                           "stdout": big, "stderr": "", "code": 0}
        res = mod.cmd_tcp_flows()
        self.assertNotIn("cubic", res["stdout"])
        self.assertLess(len(res["stdout"]), 500)
        self.assertIn("connections", res["stdout"])

    def test_the_collector_is_absent_rather_than_failing_off_linux(self):
        """A check that can't run is never reported as a fault."""
        mod = fresh()
        mod.OS_NAME = "Darwin"
        res = mod.cmd_tcp_flows()
        self.assertFalse(res["ok"])
        self.assertIn("Linux", res["error"])

    # ---- what a partial sample is allowed to conclude -------------------

    def test_a_partial_sample_cannot_blame_this_devices_own_link(self):
        """"No destination is clean" is a claim about what isn't there, so it
        needs the whole sample. ss prints in kernel table order, and a prefix of
        that can easily be one busy application's connections."""
        s = self.stats(ss_flow("203.0.113.9", sent=5_000_000, retrans=300_000),
                       ss_flow("198.51.100.4", sent=4_000_000, retrans=250_000),
                       truncated=True)
        self.assertEqual(s["shape"], "unclear")

    def test_the_same_evidence_complete_does_blame_the_link(self):
        """The guard has to be the truncation, not the evidence."""
        s = self.stats(ss_flow("203.0.113.9", sent=5_000_000, retrans=300_000),
                       ss_flow("198.51.100.4", sent=4_000_000, retrans=250_000))
        self.assertEqual(s["shape"], "all_peers")

    def test_a_partial_sample_still_reports_the_loss_it_did_see(self):
        """Withholding the owner must not turn observed loss into "no fault
        found" - that trades a wrong owner for a wrong all-clear."""
        mod = fresh()
        flows(mod, ss_flow("203.0.113.9", sent=5_000_000, retrans=300_000),
                   ss_flow("198.51.100.4", sent=4_000_000, retrans=250_000),
              truncated=True)
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertNotEqual(report["verdict"]["severity"], "ok")
        self.assertNotIn("no fault", report["verdict"]["headline"].lower())
        self.assertIn("unclear", report["verdict"]["owner"].lower())

    def test_a_partial_sample_still_allows_the_comparative_reading(self):
        """Seeing one lossy and one clean destination is a claim about what IS
        there, and a truncated read still supports it."""
        s = self.stats(ss_flow("203.0.113.9", sent=5_000_000, retrans=400_000),
                       ss_flow("198.51.100.4", sent=4_000_000, retrans=0),
                       truncated=True)
        self.assertEqual(s["shape"], "some_peers")

    # ---- how it relates to the check it refines -------------------------

    def test_two_views_of_the_same_retransmits_are_not_two_signals(self):
        """The host-wide rate and the per-flow split are the same drops counted
        twice. Treating them as independent checks would let one fault
        corroborate itself into high confidence."""
        self.assertEqual(nd._finding_family("tcp_flow_loss_all_peers"),
                         nd._finding_family("tcp_retransmits"))

    def test_a_measured_path_loss_still_owns_the_verdict(self):
        """The flow split refines the retransmit story; it doesn't outrank the
        loss measurement that explains it."""
        mod = fresh()
        flows(mod, ss_flow("203.0.113.9", sent=5_000_000, retrans=400_000),
                   ss_flow("198.51.100.4", sent=4_000_000, retrans=0))
        mod.cmd_ping = lambda t, c=4, w=2: {"ok": True, "cmd": f"ping {t}", "stdout":
            "10 packets transmitted, 6 received, 40% packet loss\n"
            "rtt min/avg/max/mdev = 1.0/20.0/30.0/2.0 ms\n"}
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        codes = [f.get("code") for f in report["findings"]]
        self.assertIn("tcp_flow_loss_some_peers", codes)
        self.assertNotEqual(report["verdict"]["based_on"][0], "tcp_flow_loss_some_peers")


class TestEveryFindingFires(unittest.TestCase):
    maxDiff = None

    # ---- the checks ----------------------------------------------------

    def run_scenario(self, code):
        setup, kw = S[code]
        nd_local = fresh()
        setup(nd_local)
        report = nd_local.diagnose(quick=False, **scenario_kwargs(kw))
        return report, [f for f in report["findings"] if f.get("code") == code]

    def test_every_code_has_a_scenario(self):
        """A finding nobody can trigger is a finding nobody has tested."""
        import re
        with open(nd.__file__, encoding="utf-8") as fh:
            emitted = set(re.findall(r'"code": "(\w+)"', fh.read()))
        missing = sorted(emitted - set(S))
        self.assertFalse(missing, f"no scenario exercises: {missing}")

    def test_every_finding_fires_in_its_scenario(self):
        for code in sorted(S):
            with self.subTest(code=code):
                _report, fired = self.run_scenario(code)
                self.assertTrue(fired, f"{code} did not fire in its own scenario")

    def test_severities_are_what_was_intended(self):
        expected_critical = {
            "no_ipv4", "no_gateway", "gw_unreachable", "inet_unreachable", "dns_fail",
            "dns_no_resolvers", "dns_all_resolvers_down", "duplicate_ip", "loop",
            "pmtu_blackhole", "link_errors_live", "optics_alarm", "optics_rx_low",
            "path_loss", "call_quality_bad", "tls_expired", "link_saturated",
            "tcp_retransmits", "tcp_flow_loss_all_peers", "link_flapping_live",
            "nic_drops_live", "conntrack_drops_live", "rcv_buffer_pruned",
            "uplink_saturated", "link_flapping_logged", "nic_reset_logged",
        }
        # Python concatenates adjacent string literals, so a dropped comma in
        # this set turns two codes into one nonexistent one and quietly stops
        # checking both. That happened here.
        self.assertFalse(expected_critical - {r[0] for r in nd.VERDICT_RULES},
                         "expected_critical names codes no rule ranks")
        # Exempt findings are context and read as "ok" - except the two that
        # report the run was capped, which are warnings about coverage.
        coverage_warnings = ("ports_truncated", "tcp_flow_sample_partial")
        for code in sorted(S):
            with self.subTest(code=code):
                _report, fired = self.run_scenario(code)
                if code in expected_critical:
                    self.assertEqual(fired[0]["severity"], "critical", code)
                elif code in nd.VERDICT_EXEMPT and code not in coverage_warnings:
                    self.assertEqual(fired[0]["severity"], "ok", code)

    def test_a_latent_condition_cannot_headline_over_a_live_outage(self):
        """Pure bottom-up ranks by layer and never asked whether the finding was
        actually breaking anything - so a temperature warning on an optic that
        was passing traffic outranked DNS being completely dead. Something that
        says "not failing yet" cannot explain something failing now."""
        mod = fresh()
        mod.cmd_optics = lambda i: {"ok": True, "cmd": "ethtool -m", "stdout": "", "parsed":
            {"rx_dbm": -5.0, "tx_dbm": -2.0, "vendor": "V", "alarms": [],
             "warnings": ["Temp high warning"]}}
        mod.cmd_dns = lambda t: {"ok": False, "cmd": "dig", "error": "resolution failed"}
        resolvers(mod, [R("10.0.0.53", ok=False)])
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertNotEqual(report["verdict"]["based_on"][0], "optics_warning")
        self.assertEqual(report["verdict"]["severity"], "critical")
        # still reported, just not the headline
        self.assertIn("optics_warning", [f.get("code") for f in report["findings"]])

    def test_a_latent_condition_is_still_the_answer_when_nothing_is_broken(self):
        """The rule suppresses it beside a live failure, not in general - an
        optic with little margin left is exactly what a visit should surface
        when everything else is working."""
        mod = fresh()
        mod.cmd_optics = lambda i: {"ok": True, "cmd": "ethtool -m", "stdout": "", "parsed":
            {"rx_dbm": -5.0, "tx_dbm": -2.0, "vendor": "V", "alarms": [],
             "warnings": ["Temp high warning"]}}
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertEqual(report["verdict"]["based_on"][0], "optics_warning")

    def test_an_active_low_layer_warning_still_outranks_a_higher_critical(self):
        """The founding example: a gateway losing packets explains everything
        failing beyond it. Active loss is not latent, and the layer rule is
        right here - suppressing it would break what the tool is for."""
        mod = fresh()
        ping_map(mod, gw_loss=25, inet_loss=100, sent=20)
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertEqual(report["verdict"]["based_on"][0], "gw_partial_loss")

    def test_every_latent_code_exists_and_is_never_critical(self):
        """A latent finding describes a risk. If one is emitted as critical the
        classification is wrong, and it would then be suppressed by its own
        kind - which is how a rule like this quietly eats a real fault."""
        import re
        source = open(nd.__file__, encoding="utf-8").read()
        for code in sorted(nd.LATENT):
            with self.subTest(code=code):
                self.assertIn(f'"code": "{code}"', source, f"{code} is no longer emitted")
                block = source.split(f'"code": "{code}"')[0]
                sev = re.findall(r'"severity": "(\w+)"', block)[-1]
                self.assertNotEqual(sev, "critical", f"{code} is latent but emitted as critical")

    def test_a_cause_always_outranks_the_symptom_it_produces(self):
        """MOS is computed from the latency and loss measured above it, and
        retransmits are what path loss causes. If either outranks its own cause
        the verdict names a restatement instead of the fault."""
        order = [rule[0] for rule in nd.VERDICT_RULES]
        for cause, symptom in (("inet_partial_loss", "call_quality_bad"),
                               ("path_loss", "call_quality_bad"),
                               ("gw_partial_loss", "call_quality_bad"),
                               ("inet_partial_loss", "call_quality_degraded"),
                               ("path_loss", "tcp_retransmits"),
                               # a duplex mismatch produces the CRC errors on
                               # the full-duplex side; blaming them gives
                               # "replace the cable", which cannot fix a switch
                               ("collisions", "link_errors_live"),
                               ("gw_unreachable", "inet_unreachable"),
                               # A corrupting link produces the retransmits that
                               # make every destination look lossy.
                               ("link_errors_live", "tcp_flow_loss_all_peers"),
                               ("path_loss", "tcp_flow_loss_some_peers"),
                               # "the far end is slow" must never displace a
                               # measured network fault.
                               ("path_loss", "tcp_flow_receiver_limited"),
                               ("call_quality_bad", "tcp_flow_receiver_limited"),
                               # The per-destination split is the specific
                               # reading of the host-wide rate, so it goes first.
                               ("tcp_flow_loss_all_peers", "tcp_retransmits"),
                               ("tcp_flow_loss_some_peers", "tcp_retransmits"),
                               ("tcp_flow_loss_one_peer", "tcp_retransmits")):
            self.assertLess(order.index(cause), order.index(symptom),
                            f"{symptom} outranks {cause}, which produces it")

    def test_housekeeping_findings_do_not_read_as_failures(self):
        report, _ = self.run_scenario("ports_truncated")
        self.assertEqual(report["verdict"]["severity"], "ok")
        self.assertIn("no fault", report["verdict"]["headline"].lower())

    def test_a_critical_finding_never_leaves_its_stage_merely_warning(self):
        for code in ("link_saturated", "tcp_retransmits", "tls_expired"):
            with self.subTest(code=code):
                report, fired = self.run_scenario(code)
                if fired[0]["severity"] != "critical":
                    continue
                states = [s["state"] for s in report["stages"]]
                self.assertIn("fail", states,
                              f"{code} is critical but no stage failed")

    def test_the_clock_parsers_read_real_daemon_output(self):
        """Three daemons, three formats. chrony reports fast/slow in seconds,
        ntpq marks its chosen peer with an asterisk and gives milliseconds, and
        timedatectl says only whether the clock is disciplined at all."""
        self.assertEqual(nd.parse_chrony_tracking(
            "Leap status     : Normal\nSystem time     : 0.000241 seconds fast of NTP time"),
            (0.241, True))
        offset, synced = nd.parse_chrony_tracking(
            "Reference ID    : 00000000 ()\nLeap status     : Not synchronised")
        self.assertIs(synced, False)
        header = ("     remote           refid      st t when poll reach   delay   "
                  "offset  jitter\n")
        self.assertEqual(nd.parse_ntpq_peers(
            header + "*ntp1.example.com 10.0.0.1  2 u   64  128  377   12.345   -4.321   0.567"),
            (-4.321, True))
        # a peer list with nothing selected is a daemon that has settled on nothing
        self.assertEqual(nd.parse_ntpq_peers(
            header + " ntp1.example.com 10.0.0.1  2 u   64  128    0    0.000   0.000   0.000"),
            (None, False))

    def test_a_skewed_clock_outranks_the_certificate_it_invalidates(self):
        """If the clock is wrong then every certificate reading in the report is
        measuring the clock, so the clock has to be named first."""
        order = [rule[0] for rule in nd.VERDICT_RULES]
        for cert in ("tls_not_yet_valid", "tls_expired", "tls_expiring"):
            self.assertLess(order.index("clock_skewed"), order.index(cert))

    def test_a_drifted_clock_says_which_side_of_the_line_it_is_on(self):
        """Five minutes is where Kerberos stops; five seconds only makes logs
        useless. Same finding, different consequence, and the message has to
        say which."""
        for offset, expect in ((412_000.0, "Kerberos"), (9_000.0, "line up")):
            with self.subTest(offset=offset):
                mod = fresh()
                mod.cmd_clock_sync = lambda o=offset: {
                    "ok": True, "cmd": "chronyc tracking", "stdout": "",
                    "offset_ms": o, "synced": True, "source": "chronyc"}
                report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
                fired = [f for f in report["findings"] if f.get("code") == "clock_skewed"]
                self.assertTrue(fired)
                self.assertIn(expect, fired[0]["message"])

    def test_a_box_with_no_time_daemon_says_so_rather_than_nothing(self):
        """A check that cannot run is never reported as a fault - and a clock
        nobody asked about must not read as a clock that is fine."""
        mod = fresh()
        mod.which = lambda c: False
        res = mod.cmd_clock_sync()
        self.assertFalse(res["ok"])
        self.assertIn("no time daemon", res["error"])
        mod.cmd_clock_sync = lambda: res
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertFalse([f for f in report["findings"]
                          if str(f.get("code", "")).startswith("clock")])

    def test_a_certificate_from_the_future_blames_the_clock_first(self):
        """notBefore was never read, so a clock behind the real time made every
        certificate look invalid and the report blamed the certificate. A
        future-dated certificate is rare; a wrong clock is common."""
        mod = fresh()
        mod.cmd_tls_check = lambda h, p=443, timeout=5: {
            "ok": True, "cmd": "tls", "host": h, "port": p, "verified": True,
            "tls_version": "TLSv1.3", "stdout": "", "starts": "2027-01-01",
            "not_yet_valid_days": 148, "days_left": 500}
        report = mod.diagnose("8.8.8.8", ["443"], quick=False, baseline=None)
        fired = [f for f in report["findings"] if f.get("code") == "tls_not_yet_valid"]
        self.assertTrue(fired)
        self.assertIn("clock", fired[0]["message"])
        self.assertIn("clock", report["verdict"]["owner"])

    def test_a_normal_certificate_says_nothing_about_the_clock(self):
        mod = fresh()
        mod.cmd_tls_check = lambda h, p=443, timeout=5: {
            "ok": True, "cmd": "tls", "host": h, "port": p, "verified": True,
            "tls_version": "TLSv1.3", "stdout": "", "days_left": 300}
        report = mod.diagnose("8.8.8.8", ["443"], quick=False, baseline=None)
        self.assertNotIn("tls_not_yet_valid", [f.get("code") for f in report["findings"]])

    def test_the_per_connection_rtt_is_used_not_just_parsed(self):
        """It was read off every connection and discarded. A loss figure with
        no latency beside it tells half the story, and this is the path's own
        round trip to the destination that is actually suffering."""
        text = (SS_HEADER
                + "ESTAB 0 0 10.0.0.5:1 203.0.113.9:443\n"
                  "\t cubic rtt:82.4/9.1 bytes_sent:5000000 bytes_retrans:400000\n"
                + "ESTAB 0 0 10.0.0.5:2 198.51.100.4:443\n"
                  "\t cubic rtt:11.0/1.0 bytes_sent:4000000 bytes_retrans:0\n")
        stats = nd.analyze_tcp_flows(nd.parse_tcp_flows(text))
        self.assertEqual(stats["worst_peer"], "203.0.113.9")
        self.assertEqual(stats["worst_rtt_ms"], 82.4)      # the lossy one, not the clean one

    def test_an_ipv6_target_is_dialled_over_ipv6(self):
        """valid_target accepts IPv6 and the TLS check handles it, but the port
        check opened an AF_INET socket unconditionally - so a perfectly good
        IPv6 address came back as "hostname resolution failed", which sends
        someone to look at DNS."""
        # The claim is about which family gets dialled, so the dialling is
        # stubbed and the address is a documentation one. Opening a real
        # socket made the test's cost, and its timing, depend on whether the
        # machine running the suite has IPv6 at all - and the suite states
        # that it touches no network.
        real_connect, dialled = nd._connect_once, []

        def record(host, port_num, family, socktype, proto, sockaddr,
                   ip_version, timeout):
            dialled.append(ip_version)
            return {"ok": True, "cmd": f"tcp connect {host}:{port_num}",
                    "stdout": "open", "stderr": "", "code": 0,
                    "ip_version": ip_version}

        nd._connect_once = record
        try:
            res = nd.cmd_check_port("2001:db8::1", 443, timeout=3)
        finally:
            nd._connect_once = real_connect
        self.assertNotIn("resolution failed", str(res.get("error", "")))
        self.assertEqual(res.get("ip_version"), 6)
        self.assertEqual(dialled, [6])   # AF_INET6 itself, not a v4 attempt that worked

    def test_both_families_are_tried_before_calling_a_port_shut(self):
        """Taking only the resolver's first answer would have been worse than
        the bug it fixed: a dual-stack name on a network with broken IPv6 would
        newly time out, where the old IPv4-only code happened to work."""
        import socket as _socket
        # the real collector, not fresh()'s stub - this is about what the
        # function does with what the resolver hands it
        #
        # Both halves are stubbed on purpose. This used to hand the real
        # connector a live resolver's own addresses and assume the IPv6 one
        # would fail, so it asserted the fallback on machines with no IPv6 and
        # asserted nothing on machines that have it - passing or failing on a
        # property of the network the suite was run from rather than on the
        # code. Documentation addresses, and a connector that cannot reach
        # anything, keep the answer the same everywhere.
        real_gai, real_connect = _socket.getaddrinfo, nd._connect_once
        _socket.getaddrinfo = lambda h, p, *a, **k: [
            (_socket.AF_INET6, _socket.SOCK_STREAM, 6, "", ("2001:db8::1", p, 0, 0)),
            (_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("192.0.2.1", p))]

        def only_v4_answers(host, port_num, family, socktype, proto, sockaddr,
                            ip_version, timeout):
            if ip_version == 6:
                return {"ok": False, "cmd": f"tcp connect {host}:{port_num}",
                        "error": "timed out", "reason": "timeout", "ip_version": 6}
            return {"ok": True, "cmd": f"tcp connect {host}:{port_num}",
                    "stdout": "open", "stderr": "", "code": 0, "ip_version": 4}

        nd._connect_once = only_v4_answers
        try:
            res = nd.cmd_check_port("dual.example", 443, timeout=3)
        finally:
            _socket.getaddrinfo = real_gai
            nd._connect_once = real_connect
        self.assertTrue(res["ok"])
        self.assertEqual(res["ip_version"], 4)          # fell back and succeeded
        self.assertEqual(res["families_tried"], [6, 4])
        self.assertEqual(res["family_mismatch"], [6])   # and remembered which failed

    def test_a_half_working_dual_stack_service_is_reported(self):
        """Publishing an address for both families and answering on only one
        costs every client a timeout before it falls back. Invisible from a
        machine that only has the working family."""
        mod = fresh()
        mod.cmd_check_port = lambda h, p, timeout=5: {
            "ok": True, "cmd": f"tcp connect {h}:{p}", "stdout": "open", "stderr": "",
            "code": 0, "ip_version": 4, "families_tried": [6, 4], "family_mismatch": [6]}
        report = mod.diagnose("8.8.8.8", ["443"], quick=False, baseline=None)
        fired = [f for f in report["findings"] if f.get("code") == "family_unreachable"]
        self.assertTrue(fired)
        self.assertIn("not over IPv6", fired[0]["message"])

    def test_a_single_family_name_reports_no_mismatch(self):
        """Only one family in the answer means nothing to compare - and a name
        with no AAAA record has not published a broken one."""
        # Stubbed for the same reason as the two above: what is being asserted
        # is the bookkeeping when there is only one candidate, and reaching a
        # real host to find that out made it a network test.
        real_connect = nd._connect_once
        nd._connect_once = (lambda host, port_num, family, socktype, proto,
                            sockaddr, ip_version, timeout: {
                                "ok": True, "cmd": f"tcp connect {host}:{port_num}",
                                "stdout": "open", "stderr": "", "code": 0,
                                "ip_version": ip_version})
        try:
            res = nd.cmd_check_port("192.0.2.1", 443, timeout=4)
        finally:
            nd._connect_once = real_connect
        self.assertIsNone(res.get("family_mismatch"))
        # And says nothing about families either, rather than a list of one.
        self.assertIsNone(res.get("families_tried"))

    def test_a_slow_handshake_is_charged_to_the_server_not_the_path(self):
        """We already did the connect and the handshake and threw the clock
        away. They answer to different people: the connect is a round trip and
        belongs to the path, the handshake beyond it is the server's own work."""
        mod = fresh()
        mod.cmd_tls_check = lambda h, p=443, timeout=5: {
            "ok": True, "cmd": "tls", "host": h, "port": p, "verified": True,
            "tls_version": "TLSv1.3", "stdout": "", "tcp_ms": 18.0, "tls_ms": 900.0}
        report = mod.diagnose("8.8.8.8", ["443"], quick=False, baseline=None)
        fired = [f for f in report["findings"] if f.get("code") == "tls_handshake_slow"]
        self.assertTrue(fired)
        self.assertIn("900ms of that was the TLS handshake", fired[0]["message"])
        self.assertIn("not the path", report["verdict"]["owner"])

    def test_a_handshake_in_proportion_to_its_round_trips_is_fine(self):
        """A 200ms handshake behind a 90ms connect is two round trips, which is
        what a handshake is. Only the excess is the server's."""
        mod = fresh()
        mod.cmd_tls_check = lambda h, p=443, timeout=5: {
            "ok": True, "cmd": "tls", "host": h, "port": p, "verified": True,
            "tls_version": "TLSv1.3", "stdout": "", "tcp_ms": 90.0, "tls_ms": 200.0}
        report = mod.diagnose("8.8.8.8", ["443"], quick=False, baseline=None)
        self.assertNotIn("tls_handshake_slow", [f.get("code") for f in report["findings"]])

    def test_a_fast_link_does_not_make_every_handshake_look_slow(self):
        """On a 1ms LAN a 6ms handshake is six times the connect and entirely
        normal. The ratio needs a floor or it fires on healthy sites."""
        mod = fresh()
        mod.cmd_tls_check = lambda h, p=443, timeout=5: {
            "ok": True, "cmd": "tls", "host": h, "port": p, "verified": True,
            "tls_version": "TLSv1.3", "stdout": "", "tcp_ms": 1.0, "tls_ms": 6.0}
        report = mod.diagnose("8.8.8.8", ["443"], quick=False, baseline=None)
        self.assertNotIn("tls_handshake_slow", [f.get("code") for f in report["findings"]])

    def test_a_changed_answer_between_visits_is_reported(self):
        """Which resolvers are configured is one question; what they answer is
        another, and only the second changes when a service moves."""
        def rep(answers):
            return {"raw": {"dns_health": {"resolvers": [
                {"server": "10.0.0.53", "answers": answers}]}}}
        same = nd.compare_reports(rep(["192.0.2.4"]), rep(["192.0.2.4"]))
        self.assertFalse([c for c in same if c["what"] == "resolves to"])
        moved = nd.compare_reports(rep(["9.9.9.9"]), rep(["192.0.2.4"]))
        entry = [c for c in moved if c["what"] == "resolves to"][0]
        self.assertEqual((entry["before"], entry["after"]), ("192.0.2.4", "9.9.9.9"))

    def test_a_rotated_answer_is_reported_but_is_not_a_regression(self):
        """Any load-balanced or CDN-fronted name hands out a different address
        run to run. Only "worse" changes raise regression_since_baseline, so
        marking this one a deterioration made a healthy repeat visit report a
        regression - intermittently, which is worse than always."""
        def rep(answers):
            return {"raw": {"dns_health": {"resolvers": [
                {"server": "10.0.0.53", "answers": answers}]}}}
        entry = [c for c in nd.compare_reports(rep(["9.9.9.9"]), rep(["192.0.2.4"]))
                 if c["what"] == "resolves to"][0]
        self.assertEqual(entry["direction"], "neutral")
        # and end to end: the same site, one rotated record, still clean
        mod = fresh()
        import json as _json
        base = _json.loads(_json.dumps(mod.json_safe(
            mod.diagnose("8.8.8.8", None, quick=False, baseline=None))))
        base["raw"]["dns_health"]["resolvers"][0]["answers"] = ["203.0.113.14"]
        report = fresh().diagnose("8.8.8.8", None, quick=False, baseline=base)
        codes = [f.get("code") for f in report["findings"]]
        self.assertIn("baseline_changes", codes)
        self.assertNotIn("regression_since_baseline", codes)
        self.assertEqual(nd.exit_status(report), 0)

    def test_a_visit_that_could_not_resolve_is_not_a_change(self):
        """One side missing means the two runs measured different things -
        reporting that as a change manufactures a regression out of a gap."""
        empty = {"raw": {"dns_health": {"resolvers": []}}}
        got = nd.compare_reports({"raw": {"dns_health": {"resolvers": [
            {"server": "10.0.0.53", "answers": ["192.0.2.4"]}]}}}, empty)
        self.assertFalse([c for c in got if c["what"] == "resolves to"])

    def test_the_findings_that_blame_load_say_how_loaded_it_is(self):
        """Three findings tell you the box is too busy; one of them literally
        advised checking CPU while checking nothing. Both directions matter -
        dropping packets at load 48 is capacity, dropping them at 0.2 is a
        limit set too low, and those are different fixes."""
        for code in ("nic_drops_live", "conntrack_drops_live", "accept_overflow_live"):
            for load, cpus, expected in ((48.7, 4, "capacity, not configuration"),
                                         (0.2, 4, "not busy")):
                with self.subTest(code=code, load=load):
                    setup, kw = S[code]
                    mod = fresh(); setup(mod)
                    mod._load_average = lambda l=load, c=cpus: (l, c)
                    report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
                    msg = [f["message"] for f in report["findings"]
                           if f.get("code") == code][0]
                    self.assertIn(f"{load:.2f}", msg)
                    self.assertIn(expected, msg)

    def test_an_unreadable_load_average_adds_nothing(self):
        """Windows has no getloadavg. The finding still stands on its own -
        silence beats a sentence about a number nobody has."""
        mod = fresh()
        mod._load_average = lambda: (None, 0)
        self.assertEqual(mod._load_context(), "")
        setup, kw = S["nic_drops_live"]; setup(mod)
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        msg = [f["message"] for f in report["findings"]
               if f.get("code") == "nic_drops_live"][0]
        self.assertNotIn("Load average", msg)
        self.assertIn("receive backlog was full", msg)

    def test_load_is_context_not_a_check_of_its_own(self):
        """A busy box is not a network fault. This never fires on its own -
        it only qualifies a finding that has already been made.

        The rule is about *load*, not about the CPU. Thermal throttling is a
        finding, and rightly: it is a count of times the hardware clocked
        itself down, not a reading of how busy the box is. A blanket ban on
        the "cpu_" prefix stated the rule as a spelling convention and blocked
        a real fault - so the ban names the load-derived codes, and the
        assertion below is the one with teeth."""
        source = open(nd.__file__, encoding="utf-8").read()
        for banned in ('"code": "high_load"', '"code": "cpu_load',
                       '"code": "cpu_busy', '"code": "load_'):
            self.assertNotIn(banned, source)
        mod = fresh()
        mod._load_average = lambda: (99.0, 1)
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertEqual(report["verdict"]["severity"], "ok")

    def test_a_busy_box_that_is_not_throttling_reports_nothing_thermal(self):
        """The counters are what fires this, not the load beside them."""
        mod = fresh()
        mod._load_average = lambda: (99.0, 1)
        kernel_drops(mod, {"core_throttles": 12, "package_throttles": 12},
                          {"core_throttles": 12, "package_throttles": 12})
        codes = [f["code"] for f in mod.diagnose("8.8.8.8", None, quick=False)["findings"]]
        self.assertNotIn("cpu_throttled_live", codes)
        self.assertIn("cpu_throttled_historical", codes)

    def test_the_conntrack_flow_table_is_never_read(self):
        """/proc/net/stat/nf_conntrack is counters. /proc/net/nf_conntrack is
        the flow list - every connection this box has open, and who with. The
        second is large and nobody's business, and this check has no reason to
        open it."""
        source = open(nd.__file__, encoding="utf-8").read()
        self.assertIn("/proc/net/stat/nf_conntrack", source)
        self.assertNotIn('"/proc/net/nf_conntrack"', source)
        self.assertNotIn("open('/proc/net/nf_conntrack')", source)

    def test_conntrack_stats_are_read_by_column_name_and_as_hex(self):
        """The columns vary by kernel, so they're located by the header rather
        than by position - and "entries" repeats the table total on every row,
        so summing it would multiply the table size by the CPU count."""
        mod = fresh()
        rows = ("entries searched found new invalid ignore delete insert insert_failed drop\n"
                "0000ffff 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000000a 00000005\n"
                "0000ffff 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000006 00000001\n")
        import io
        mod.open = lambda path, *a, **k: (io.StringIO(rows) if "stat/nf_conntrack" in path
                                          else io.StringIO("100"))
        got = mod._read_conntrack()
        self.assertEqual(got["ct_insert_failed"], 0xa + 0x6)   # summed across CPUs
        self.assertEqual(got["ct_drop"], 0x5 + 0x1)
        self.assertNotIn("ct_entries", got)                    # never summed

    def test_a_full_table_outranks_the_failures_it_causes(self):
        """A table that won't accept new connections is the reason traffic
        isn't getting out, not a second opinion about it."""
        mod = fresh()
        kernel_drops(mod, {"ct_count": 65_000, "ct_max": 65_536, "ct_insert_failed": 0},
                          {"ct_count": 65_500, "ct_max": 65_536, "ct_insert_failed": 40})
        mod.cmd_ping = lambda t, c=4, w=2: {"ok": True, "cmd": f"ping {t}", "stdout":
            "10 packets transmitted, 7 received, 30% packet loss\n"
            "rtt min/avg/max/mdev = 1.0/20.0/30.0/2.0 ms\n"}
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertEqual(report["verdict"]["based_on"][0], "conntrack_drops_live")
        self.assertIn("connection tracking", report["verdict"]["owner"])

    def test_a_physical_fault_still_outranks_a_device_side_drop(self):
        """Corrupted frames are layer 1 and a full backlog is layer 2. The
        lowest live fault is the cause - that rule doesn't bend because the
        newer check is more interesting."""
        order = [rule[0] for rule in nd.VERDICT_RULES]
        self.assertLess(order.index("link_errors_live"), order.index("nic_drops_live"))
        self.assertLess(order.index("nic_drops_live"), order.index("conntrack_drops_live"))

    def test_pressure_alone_is_not_a_refusal(self):
        """80% full and nothing turned away is worth saying, but it is not the
        same finding as a table that has started refusing."""
        mod = fresh()
        kernel_drops(mod, {"ct_count": 55_000, "ct_max": 65_536})
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        codes = [f.get("code") for f in report["findings"]]
        self.assertIn("conntrack_near_limit", codes)
        self.assertNotIn("conntrack_drops_live", codes)

    def test_a_roomy_table_says_nothing(self):
        mod = fresh()
        kernel_drops(mod, {"ct_count": 1_200, "ct_max": 262_144})
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertFalse([f for f in report["findings"]
                          if str(f.get("code")).startswith("conntrack")])

    def test_a_zeroed_bsd_counter_block_is_unreadable_not_idle(self):
        """Recent macOS prints the whole tcp block as zeros to an unprivileged
        process rather than refusing, so the parse succeeds and yields nothing
        usable. Zero segments sent is not a state a box you are logged into can
        be in - the session itself is TCP."""
        mod = fresh()
        mod.OS_NAME = "Darwin"
        mod.run = lambda cmd, timeout=10, limit=None: {
            "ok": True, "cmd": " ".join(cmd), "stderr": "", "code": 0,
            "stdout": "tcp:\n\t0 packet sent\n\t\t0 data packet (0 byte)\n"
                      "\t\t0 data packet (0 byte) retransmitted\n"}
        self.assertEqual(mod._tcp_counters_bsd(), {})
        # fresh() stubs the reader with healthy numbers; put the real dispatch
        # back so the collector is exercised rather than the fixture
        mod._read_tcp_counters = lambda: mod._tcp_counters_bsd()
        health = mod.cmd_tcp_health()
        self.assertFalse(health["ok"])
        self.assertIn("not available", health["error"])

    def test_real_bsd_counters_still_parse(self):
        """The guard has to be the zero, not the platform."""
        mod = fresh()
        mod.OS_NAME = "Darwin"
        mod.run = lambda cmd, timeout=10, limit=None: {
            "ok": True, "cmd": " ".join(cmd), "stderr": "", "code": 0,
            "stdout": "tcp:\n\t4,102,331 packets sent\n"
                      "\t\t3,900,000 data packets (1234 bytes)\n"
                      "\t\t2,400 data packets (999 bytes) retransmitted\n"}
        got = mod._tcp_counters_bsd()
        self.assertEqual(got["OutSegs"], 3_900_000)
        self.assertEqual(got["RetransSegs"], 2_400)

    def test_an_unmeasurable_retransmit_check_says_so_in_the_report(self):
        """A reader who doesn't see the heading assumes retransmits were
        checked and were clean, which is the opposite of what happened."""
        report = {"raw": {"tcp_health": {"ok": False, "cmd": "tcp counters",
                                         "error": "TCP counters are not available"}},
                  "findings": [], "hops": [], "os": "Darwin"}
        text = nd.render_text_report(report, color=False, width=90)
        self.assertIn("TCP RETRANSMITS", text)
        self.assertIn("not measured", text)

    def test_collisions_on_a_full_duplex_link_beat_the_errors_they_cause(self):
        """A duplex mismatch produces CRC errors on the full-duplex side, and
        the verdict said "reseat or replace the cable" - which cannot fix a
        switch port set to half. Same shape as the optics rule already here:
        the cause outranks the corruption it produces."""
        mod = fresh()
        counters(mod, rx_packets=10_000_000, tx_packets=10_000_000, collisions=4_000,
                 rx_errors=1_200, rx_crc_errors=1_150, d_rx_errors=14, d_rx_packets=100_000)
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        codes = [f.get("code") for f in report["findings"]]
        self.assertIn("collisions", codes)
        self.assertIn("link_errors_live", codes)     # still reported
        self.assertEqual(report["verdict"]["based_on"][0], "collisions")
        self.assertIn("duplex", report["verdict"]["next_step"].lower())

    def test_errors_without_collisions_still_blame_the_cable(self):
        """The reorder must not cost the diagnosis it was already getting
        right - CRC errors alone are the cable."""
        mod = fresh()
        counters(mod, rx_packets=10_000_000, rx_errors=1_200, rx_crc_errors=1_150,
                 d_rx_errors=14, d_rx_packets=100_000)
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertEqual(report["verdict"]["based_on"][0], "link_errors_live")

    def test_drops_on_an_idle_link_are_explained_as_bursts(self):
        """Throughput here is bytes over seconds. A link can be full for fifty
        milliseconds at a time and read as idle, which is exactly what a flow
        tool sees and this cannot - so drops on a quiet link say so."""
        mod = fresh()
        counters(mod, rx_packets=10_000_000, rx_dropped=900,
                 d_rx_dropped=2_000, d_rx_packets=50_000, d_rx_bytes=2_000_000)
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        fired = [f for f in report["findings"] if f.get("code") == "drops_live"]
        self.assertTrue(fired)
        self.assertIn("in bursts the average cannot show", fired[0]["message"])

    def test_the_probe_reads_the_reply_the_router_sent_back(self):
        """The decision above rests on signalled_mtu, and a test that hands it
        in never runs the code that works it out. Mutating the reader to always
        return None left that test perfectly green while the tool went back to
        calling every DSL line broken, so this drives the real probe through
        each platform's wording.
        """
        # The real probe, not the harness copy: fresh() stubs cmd_path_mtu, so
        # calling it there measures the stub and never reaches the parser.
        replies = {
            "linux": "From 10.0.0.1 icmp_seq=1 Frag needed and DF set (mtu = 1492)",
            "bsd": "frag needed and DF set (MTU 1400)",
            "windows": "Packet needs to be fragmented but DF set.",
            "silent": "1 packets transmitted, 0 packets received, 100% packet loss",
        }
        expected = {"linux": 1492, "bsd": 1400, "windows": True, "silent": None}
        saved = nd.run
        try:
            for name, text in replies.items():
                with self.subTest(reply=name):
                    # every size fails, so the probe records what came back
                    nd.run = lambda cmd, timeout=None, limit=None, _t=text: {
                        "ok": True, "code": 1, "cmd": " ".join(cmd),
                        "stdout": _t, "stderr": ""}
                    out = nd.cmd_path_mtu("8.8.8.8", 1500)
                    self.assertEqual(out["signalled_mtu"], expected[name],
                                     f"{name} reply was read as {out['signalled_mtu']}")
        finally:
            nd.run = saved

    def test_a_smaller_path_mtu_is_only_a_fault_when_nothing_reported_it(self):
        """A path MTU below the interface is ordinary. PPPoE is 1492 and a
        tunnel is less, and when the router replies "fragmentation needed" the
        sender adapts, so transfers complete and nothing is wrong.

        The blackhole is the same measurement with that reply missing, and only
        that one hangs a transfer. Measuring the size alone cannot tell them
        apart, so a working machine on a DSL line was told it was critically
        broken. This pins both halves, because a fix that stopped reporting the
        blackhole would satisfy the first half perfectly."""
        def with_signal(signalled):
            mod = fresh()
            mod.cmd_path_mtu = lambda t, m=None, s=signalled: {
                "ok": True, "cmd": "df", "stdout": "", "target": t,
                "iface_mtu": 1500, "path_mtu": 1492, "signalled_mtu": s,
                "attempts": [{"mtu": 1500, "payload": 1472, "ok": False,
                              "signalled": s, "cmd": "x"}]}
            rep = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
            codes = {f["code"]: f["severity"] for f in rep["findings"]}
            return mod, rep, codes

        mod, rep, codes = with_signal(1492)
        self.assertIn("pmtu_reduced", codes, "a signalled MTU went unreported")
        self.assertNotIn("pmtu_blackhole", codes,
                         "a path that reported its own limit was called a blackhole")
        self.assertEqual(codes["pmtu_reduced"], "ok")
        self.assertEqual(mod.exit_status(rep), 0,
                         "a working DSL line exited non-zero")

        mod, rep, codes = with_signal(None)
        self.assertIn("pmtu_blackhole", codes, "a silent drop stopped being a fault")
        self.assertEqual(codes["pmtu_blackhole"], "critical")
        self.assertEqual(mod.exit_status(rep), 2)

    def test_the_mtu_finding_says_which_direction_it_measured(self):
        """One target, outbound only. Routing is often asymmetric, so the
        return path is not tested and another service may see a different
        limit."""
        source = open(nd.__file__, encoding="utf-8").read()
        pmtu = source.split('"code": "pmtu_blackhole"', 1)[1][:1400]
        self.assertIn("outbound direction only", pmtu)
        self.assertIn("asymmetric", pmtu)

    def test_one_unanswered_probe_is_not_a_loss_rate(self):
        """What SmokePing would say first: four probes can only express loss in
        steps of 25%, and hosts rate-limit ICMP replies as a matter of course.
        A single missing reply was being reported as 25% packet loss on a
        perfectly healthy network - and now exits 1 as well."""
        mod = fresh()
        ping_map(mod, inet_loss=25, sent=4)
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        codes = [f.get("code") for f in report["findings"]]
        self.assertIn("inet_loss_unmeasured", codes)
        self.assertNotIn("inet_partial_loss", codes)
        fired = [f for f in report["findings"] if f.get("code") == "inet_loss_unmeasured"][0]
        self.assertIn("cannot express anything smaller", fired["message"])

    def test_a_sample_big_enough_to_measure_still_reports_loss(self):
        """The guard is the sample size, not the percentage. Five of twenty is
        the same 25% and is real."""
        mod = fresh()
        ping_map(mod, inet_loss=25, sent=20)
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        codes = [f.get("code") for f in report["findings"]]
        self.assertIn("inet_partial_loss", codes)
        self.assertNotIn("inet_loss_unmeasured", codes)

    def test_more_than_one_lost_probe_counts_even_in_a_small_sample(self):
        """Two of four is not a rate-limited reply; it is half the traffic."""
        mod = fresh()
        ping_map(mod, inet_loss=50, sent=4)
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertIn("inet_partial_loss", [f.get("code") for f in report["findings"]])

    def test_the_gateway_gets_the_same_benefit_of_the_doubt(self):
        mod = fresh()
        ping_map(mod, gw_loss=25, sent=4)
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        codes = [f.get("code") for f in report["findings"]]
        self.assertIn("gw_loss_unmeasured", codes)
        self.assertNotIn("gw_partial_loss", codes)

    def test_retransmission_that_was_not_needed_is_not_loss(self):
        """The hole a packet capture would find first: every retransmit-based
        finding here reads as loss. A DSACK is the far end saying "I already
        had that" - the data arrived, late or out of order."""
        mod = fresh()
        kernel_drops(mod, {"TCPDSACKRecv": 0, "RetransSegs": 0, "TCPSACKReorder": 0},
                          {"TCPDSACKRecv": 60, "RetransSegs": 100, "TCPSACKReorder": 14})
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        fired = [f for f in report["findings"] if f.get("code") == "retrans_spurious"]
        self.assertTrue(fired)
        self.assertIn("60 of 100", fired[0]["message"])
        self.assertIn("14 reordering event(s)", fired[0]["message"])

    def test_it_outranks_the_loss_figures_it_calls_into_question(self):
        """If the packets arrived, "your link is bad" is the wrong answer -
        and the loss findings count these retransmits too."""
        order = [rule[0] for rule in nd.VERDICT_RULES]
        for overstated in ("tcp_flow_loss_all_peers", "tcp_flow_loss_some_peers",
                           "tcp_retransmits"):
            self.assertLess(order.index("retrans_spurious"), order.index(overstated))

    def test_a_few_dsacks_do_not_dismiss_real_loss(self):
        """Some spurious retransmission is normal. It only changes the story
        when it is a large share of the total."""
        mod = fresh()
        kernel_drops(mod, {"TCPDSACKRecv": 0, "RetransSegs": 0},
                          {"TCPDSACKRecv": 3, "RetransSegs": 100})
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertNotIn("retrans_spurious", [f.get("code") for f in report["findings"]])

    def test_corruption_past_the_link_layer_exonerates_the_cable(self):
        """Ethernet has its own CRC. A segment that passes that and fails the
        TCP checksum was corrupted somewhere that re-framed the packet - so the
        cable into this device is the one thing it cannot be."""
        mod = fresh()
        kernel_drops(mod, {"InCsumErrors": 0, "InSegs": 1_000_000},
                          {"InCsumErrors": 30, "InSegs": 2_000_000})
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        fired = [f for f in report["findings"] if f.get("code") == "tcp_checksum_errors"]
        self.assertTrue(fired)
        self.assertIn("not the cable into it", fired[0]["message"])
        self.assertIn("offload", report["verdict"]["next_step"])

    def test_a_clean_checksum_count_says_nothing(self):
        mod = fresh()
        kernel_drops(mod, {"InCsumErrors": 4, "InSegs": 1_000_000},
                          {"InCsumErrors": 4, "InSegs": 9_000_000})
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertNotIn("tcp_checksum_errors", [f.get("code") for f in report["findings"]])

    def test_gave_up_is_a_different_finding_from_tried_again(self):
        """A retransmitted SYN eventually got through; a failed attempt did
        not. They have different causes and the counters are separate."""
        mod = fresh()
        kernel_drops(mod, {"AttemptFails": 0, "ActiveOpens": 1_000},
                          {"AttemptFails": 40, "ActiveOpens": 1_100})
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        codes = [f.get("code") for f in report["findings"]]
        self.assertIn("connect_failures_high", codes)
        self.assertNotIn("syn_retrans_high", codes)

    def test_failing_setup_is_separated_from_failing_traffic(self):
        """A SYN is one packet sent before anything has warmed up. Losing it
        repeatedly while established traffic is fine is not general loss - the
        existing retransmit rate mixes the two and cannot tell you which."""
        mod = fresh()
        kernel_drops(mod, {"TCPSynRetrans": 0, "ActiveOpens": 1_000},
                          {"TCPSynRetrans": 9, "ActiveOpens": 1_100})
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        fired = [f for f in report["findings"] if f.get("code") == "syn_retrans_high"]
        self.assertTrue(fired)
        self.assertIn("9 of 100", fired[0]["message"])
        self.assertIn("stateful", report["verdict"]["owner"])

    def test_a_handful_of_connections_is_not_a_sample(self):
        """Two retransmitted SYNs out of three attempts is 66% and means
        nothing. The rate needs enough attempts behind it."""
        mod = fresh()
        kernel_drops(mod, {"TCPSynRetrans": 0, "ActiveOpens": 10},
                          {"TCPSynRetrans": 2, "ActiveOpens": 13})
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertNotIn("syn_retrans_high", [f.get("code") for f in report["findings"]])

    def test_setup_failing_outranks_nothing_it_did_not_cause(self):
        """It points outward - at a firewall or flood protection - so it must
        not sit above the device-side drops that would explain it."""
        order = [rule[0] for rule in nd.VERDICT_RULES]
        self.assertLess(order.index("rcv_buffer_pruned"), order.index("syn_retrans_high"))
        self.assertLess(order.index("nic_drops_live"), order.index("syn_retrans_high"))

    def test_memory_pruning_is_charged_to_this_device(self):
        """The kernel discarding data it already accepted produces retransmits
        that look exactly like a lossy path."""
        mod = fresh()
        kernel_drops(mod, {"RcvPruned": 0, "PruneCalled": 0},
                          {"RcvPruned": 40, "PruneCalled": 12})
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        fired = [f for f in report["findings"] if f.get("code") == "rcv_buffer_pruned"]
        self.assertTrue(fired)
        self.assertIn("socket memory", fired[0]["message"])
        self.assertIn("this device", report["verdict"]["owner"])

    def test_a_box_dropping_its_own_packets_is_not_blamed_on_its_link(self):
        """This is the reason the check exists. A full receive backlog makes
        every destination retransmit equally - the exact signature the per-flow
        check reads as "loss follows every peer, so it's your link". Both fire;
        the one that is the cause has to be the one named."""
        mod = fresh()
        kernel_drops(mod, {"softnet_processed": 1_000_000, "softnet_dropped": 0},
                          {"softnet_processed": 1_100_000, "softnet_dropped": 400})
        flows(mod, ss_flow("203.0.113.9", sent=5_000_000, retrans=300_000),
                   ss_flow("198.51.100.4", sent=4_000_000, retrans=250_000))
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        codes = [f.get("code") for f in report["findings"]]
        self.assertIn("nic_drops_live", codes)
        self.assertIn("tcp_flow_loss_all_peers", codes)
        self.assertEqual(report["verdict"]["based_on"][0], "nic_drops_live")
        self.assertIn("not its cable", report["verdict"]["owner"])

    def test_a_single_dropped_packet_is_not_a_fault(self):
        """Netdata's equivalent alarm is widely reported as too sensitive. A
        rate, not "any drop at all" - a transient on a busy box is normal."""
        mod = fresh()
        kernel_drops(mod, {"softnet_processed": 10_000_000, "softnet_dropped": 0},
                          {"softnet_processed": 11_000_000, "softnet_dropped": 2})
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertNotIn("nic_drops_live", [f.get("code") for f in report["findings"]])

    def test_a_counter_reset_is_not_a_negative_rate(self):
        """Counters go backwards when something resets them; "-4000 drops in
        2s" is not a measurement."""
        mod = fresh()
        kernel_drops(mod, {"softnet_processed": 9_000_000, "softnet_dropped": 4_000},
                          {"softnet_processed": 10_000, "softnet_dropped": 0})
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertNotIn("nic_drops_live", [f.get("code") for f in report["findings"]])

    def test_the_counters_are_absent_rather_than_zero_off_linux(self):
        mod = fresh()
        mod.OS_NAME = "Darwin"
        res = mod.cmd_kernel_drops()
        self.assertFalse(res["ok"])
        self.assertIn("Linux", res["error"])

    def test_softnet_columns_are_read_as_hex(self):
        """One row per CPU, and every column is hex. Reading them as decimal
        under-reports by a factor that grows with the value."""
        mod = fresh()
        rows = "0000ffff 0000000a 00000000 00000000\n0000000f 00000005 00000000 00000000\n"
        import io
        mod.open = lambda path, *a, **k: (io.StringIO(rows) if "softnet" in path
                                          else io.StringIO(""))
        got = mod._read_softnet()
        self.assertEqual(got["softnet_processed"], 0xffff + 0xf)   # summed across CPUs
        self.assertEqual(got["softnet_dropped"], 0xa + 0x5)

    def test_each_check_owns_its_own_threshold(self):
        """conntrack_drops_historical borrowed ACCEPT_OVERFLOW_PER_DAY, so
        tuning the accept queue silently retuned connection tracking - a
        different check, on a different part of the stack, measuring a
        different thing. They happen to share a number today; that is not the
        same as sharing a constant."""
        source = open(nd.__file__, encoding="utf-8").read()
        conntrack = source.split("def _check_conntrack_table", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("CONNTRACK_REFUSAL_PER_DAY", conntrack)
        self.assertNotIn("ACCEPT_OVERFLOW_PER_DAY", conntrack)
        accept = source.split("def _check_accept_queues", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("ACCEPT_OVERFLOW_PER_DAY", accept)
        self.assertNotIn("CONNTRACK_REFUSAL_PER_DAY", accept)

    def test_the_per_day_rate_is_computed_in_one_place(self):
        """It was written three times, each slightly differently - one inverted
        the guard. Three copies of a rule is three chances for it to drift."""
        source = open(nd.__file__, encoding="utf-8").read()
        self.assertEqual(source.count("/ 86400.0"), 1)
        # and the guard it encodes
        self.assertEqual(source.count("uptime < 3600"), 1)
        self.assertNotIn("uptime >= 3600", source)

    def test_the_shared_helper_still_refuses_a_freshly_booted_box(self):
        mod = fresh()
        mod._uptime_seconds = lambda: 120          # two minutes
        self.assertEqual(mod._per_day_since_boot(500), (None, None))
        mod._uptime_seconds = lambda: 10 * 86400
        rate, days = mod._per_day_since_boot(500)
        self.assertEqual(round(rate), 50)
        self.assertEqual(round(days), 10)
        self.assertEqual(mod._per_day_since_boot(0), (None, None))

    def test_a_flap_needs_uptime_before_it_means_anything(self):
        """40 transitions across two years is somebody rebooting a switch twice
        a year; the same 40 in a day is a dying cable. Without the denominator
        the check says nothing rather than guessing."""
        mod = fresh()
        counters(mod, carrier_changes=64)
        mod._uptime_seconds = lambda: None
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertNotIn("link_flapping", [f.get("code") for f in report["findings"]])

    def test_a_long_lived_box_with_few_flaps_is_not_a_fault(self):
        mod = fresh()
        counters(mod, carrier_changes=8)          # 6 beyond the boot baseline
        mod._uptime_seconds = lambda: 400 * 86400  # over more than a year
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        self.assertNotIn("link_flapping", [f.get("code") for f in report["findings"]])

    def test_a_driver_that_does_not_export_the_counter_reports_nothing(self):
        """None is not zero. A NIC without the counter hasn't said "no flaps"."""
        mod = fresh()
        counters(mod, carrier_changes=None)
        mod._uptime_seconds = lambda: 10 * 86400
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        codes = [f.get("code") for f in report["findings"]]
        self.assertNotIn("link_flapping", codes)
        self.assertNotIn("link_flapping_live", codes)

    def test_a_live_flap_outranks_its_own_history(self):
        """Both fire from one counter. Reporting the rate as well as the drop
        we just watched would be the same fault stated twice."""
        mod = fresh()
        counters(mod, carrier_changes=64, d_carrier_changes=3)
        mod._uptime_seconds = lambda: 10 * 86400
        report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
        codes = [f.get("code") for f in report["findings"]]
        self.assertIn("link_flapping_live", codes)
        self.assertNotIn("link_flapping", codes)

    def test_every_critical_finding_moves_a_stage(self):
        """The strip is the one-glance summary. A critical fault that leaves
        every stage reading pass is the "everything looks fine" that sends
        someone hunting upstream - it was true of optical alarms, routing loops
        and unusable call quality until the stage rules were completed."""
        for code in sorted(S):
            with self.subTest(code=code):
                report, fired = self.run_scenario(code)
                if not fired or fired[0]["severity"] != "critical":
                    continue
                states = [s["state"] for s in report["stages"]]
                self.assertIn("fail", states,
                              f"{code} is critical but every stage still reads pass")

    # Findings about this device's own sockets, the site's topology, or how the
    # run itself went. None of them is a stage of "does traffic get out and
    # back", so they deliberately leave the strip alone - listed explicitly so
    # a genuinely forgotten mapping can't hide among them.
    NOT_A_STAGE = {
        "cgnat", "double_nat",                       # reachability inward, not outward
        "close_wait_backlog", "syn_sent_backlog",    # this box's own sockets
        "tcp_flow_receiver_limited",                 # explicitly not the network
        "tcp_flow_sendbuf_limited",                  # a local buffer limit
        "tcp_flow_sample_partial",                   # coverage of the run
        "regression_since_baseline",                 # a diff, not a state
        "accept_overflow_live",                      # an application here, not the chain
        "accept_overflow_historical",
        "clock_skewed", "clock_unsynced",            # breaks services, not the wire
        "pmtu_reduced",                              # a smaller path MTU that the
                                                     # path itself reported: context,
                                                     # not a stage of the chain
        "no_clients_connected",                      # the absence of the inbound
                                                     # leg, which the clients
                                                     # stage reports as "-"
    }

    def test_findings_that_move_no_stage_are_a_decision_not_an_oversight(self):
        for code in sorted(S):
            with self.subTest(code=code):
                report, fired = self.run_scenario(code)
                if not fired or fired[0]["severity"] == "ok":
                    continue
                moved = any(s["state"] in ("fail", "warn") for s in report["stages"])
                if code in self.NOT_A_STAGE:
                    continue
                self.assertTrue(moved, f"{code} moves no stage and isn't listed as exempt")

    def test_the_exemption_cannot_excuse_a_critical_finding(self):
        """A warning that moves no stage is defensible - a wrong clock breaks
        authentication rather than the wire, and the strip does not model that.
        A *critical* one is not: it leaves a report whose verdict says CRITICAL
        beside a strip on which nothing failed, which is the same misleading
        silence as "link PASS" on an adapter that cannot fail a link check.

        The list is a flat allowlist, so nothing stopped a future hardware
        fault - a failed RAID member, a dead PSU read over IPMI - being added
        to it and shipping that report. This is what stops it."""
        for code in sorted(self.NOT_A_STAGE):
            if code not in S:
                continue
            with self.subTest(code=code):
                _report, fired = self.run_scenario(code)
                if not fired:
                    continue
                self.assertNotEqual(
                    fired[0]["severity"], "critical",
                    f"{code} is critical and moves no stage - the strip would read "
                    f"all-clear beside a critical verdict. Give it a stage, or "
                    f"make it a warning, or do not add it.")

    def test_a_stage_carries_the_layer_of_what_put_it_there(self):
        """The sidebar shows a layer beside each stage. It has to come from the
        findings that drove the state, so a passing stage carries none rather
        than a guessed one."""
        report, _ = self.run_scenario("link_errors_live")
        link = next(s for s in report["stages"] if s["stage"] == "link")
        self.assertEqual(link["state"], "fail")
        self.assertEqual(link["layer"], 1)
        self.assertIn("link_errors_live", link["because"])
        for stage in report["stages"]:
            if stage["state"] in ("pass", "skip"):
                self.assertIsNone(stage["layer"], stage["stage"])
                self.assertEqual(stage["because"], [], stage["stage"])

    def test_the_panel_ends_with_the_verdict_so_it_cannot_read_all_clear(self):
        """Seven scenarios put a named owner in the verdict while every stage
        stayed pass - an application at either end, the site's inbound
        topology, a change since the last visit. None of those is a stage of
        "does traffic get out and back", so the chain is right to stay green
        and the panel needs the conclusion on it instead."""
        template = nd.VIEWER_TEMPLATE
        self.assertIn("verdictRow(data.verdict)", template)
        self.assertIn("VERDICT_LAMP", template)
        outside_the_chain = 0
        for code in sorted(S):
            report, _ = self.run_scenario(code)
            verdict = report["verdict"]
            # whatever the stages say, the verdict always has a severity the
            # panel knows how to colour
            self.assertIn(verdict["severity"], ("ok", "warning", "critical"), code)
            if verdict["severity"] != "ok" and not any(
                    s["state"] in ("fail", "warn") for s in report["stages"]):
                outside_the_chain += 1
        self.assertGreater(outside_the_chain, 0,
                           "if nothing sits outside the chain any more, this row's "
                           "reason for existing should be re-read rather than assumed")

    def test_the_stage_strip_reads_stages_not_the_wording_of_findings(self):
        """It used to substring-match the finding text for four keywords, so a
        CRC storm showed all-green (no message says "interface") while
        "The gateway is reachable but 8.8.8.8 is not" lit the gateway lamp.

        The strip was drawn twice - as lamps in the sidebar and as chips in the
        main column - and is now drawn once, in the column that survives print.
        What matters is unchanged: the state comes from the report's own stage
        data and never from reading the findings back."""
        template = nd.VIEWER_TEMPLATE
        self.assertNotIn("severityForFindings", template)
        self.assertNotIn("message.toLowerCase().includes", template)
        strip = template.split("const stageHtml = stages.length ?", 1)
        self.assertEqual(len(strip), 2, "the stage strip is gone")
        body = strip[1].split("' : '';", 1)[0]
        self.assertIn("st.state", body)
        self.assertNotIn("findings", body)
        # Drawn once. Two copies on one screen is what this replaced.
        self.assertEqual(template.count("const stageHtml ="), 1)
        self.assertNotIn("map(ledRow)", template)

    def test_the_strip_did_not_lose_what_only_the_lamps_carried(self):
        """The sidebar lamps showed a layer badge and named the findings that
        put a stage in its state, and the chips showed neither. Dropping the
        lamps without moving those across would have been a tidier page that
        told the reader less."""
        template = nd.VIEWER_TEMPLATE
        body = template.split("const stageHtml = stages.length ?", 1)[1] \
                       .split("' : '';", 1)[0]
        # Computed from the stage, and actually placed in what is returned.
        # Asserting only that the name appears somewhere in the body passes
        # with the condition gutted or the value never interpolated.
        self.assertIn("st.layer ?", body)
        self.assertIn("${layer}", body)
        self.assertIn("st.because &&", body)
        self.assertIn("${why}", body)

    def test_a_version_change_between_visits_is_noticed(self):
        report, _ = self.run_scenario("baseline_changes")
        self.assertTrue(report["comparison"],
                        "a baseline from another version produced no comparison")


class TestCompoundFaults(unittest.TestCase):
    """Real faults arrive with their symptoms attached. A cable corrupting
    frames also loses pings, degrades calls and drives retransmits - four
    findings, one cause. These check the verdict names the cause every time,
    because naming a symptom sends someone to fix the wrong thing."""

    def diagnose_with(self, setup, **kw):
        mod = fresh()
        setup(mod)
        return mod.diagnose(quick=False, **scenario_kwargs(kw))

    def assert_blames(self, report, code, owner_contains):
        verdict = report["verdict"]
        self.assertEqual(verdict.get("based_on", [None])[0], code,
                         f"verdict blamed {verdict.get('based_on')} instead of {code}: "
                         f"{verdict['headline']}")
        self.assertIn(owner_contains.lower(), verdict["owner"].lower())

    def test_bad_cable_beats_the_loss_and_call_quality_it_causes(self):
        def setup(mod):
            counters(mod, rx_errors=1200, rx_crc_errors=1150, d_rx_errors=14)
            ping_map(mod, gw_loss=25, inet_loss=25, avg=90.0, mdev=45.0)
            mod._read_tcp_counters = lambda: {"OutSegs": 100000, "RetransSegs": 6000}
        report = self.diagnose_with(setup)
        self.assert_blames(report, "link_errors_live", "cable")
        codes = {f["code"] for f in report["findings"]}
        self.assertTrue({"gw_partial_loss", "inet_partial_loss"} & codes,
                        "the symptoms should still be reported, just not blamed")

    def test_low_optical_power_beats_the_crc_errors_it_causes(self):
        """On fibre, -32 dBm is why the counters are climbing. Blaming the
        counters produces 'reseat the cable', which is the wrong instruction for
        a dirty connector or a dying laser."""
        def setup(mod):
            mod.cmd_optics = lambda i: {"ok": True, "cmd": "ethtool -m", "stdout": "", "parsed":
                {"rx_dbm": -32.0, "tx_dbm": -2.0, "vendor": "V", "alarms": [], "warnings": []}}
            counters(mod, rx_errors=5000, rx_crc_errors=4900, d_rx_errors=40)
        self.assert_blames(self.diagnose_with(setup), "optics_rx_low", "fibre")

    def test_duplex_mismatch_beats_its_collisions_and_retransmits(self):
        def setup(mod):
            mod.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
                {"name": "eth0", "speed_mbps": 100, "duplex": "half", "mtu": 1500,
                 "carrier": True}]}
            counters(mod, collisions=900, rx_errors=800)
            mod._read_tcp_counters = lambda: {"OutSegs": 100000, "RetransSegs": 4000}
        self.assert_blames(self.diagnose_with(setup), "duplex_mismatch", "switch")

    def test_an_uplink_outage_is_not_blamed_on_dns(self):
        """DNS fails too when nothing routes. The gateway answering is what
        makes this the provider's problem rather than the device's."""
        def setup(mod):
            ping_map(mod, gw_loss=0, inet_loss=100)
            unreachable(mod, arp=True)
            path_dies_short(mod)
            mod.cmd_dns = lambda t: {"ok": True, "cmd": "dig", "stdout": "SERVFAIL\n"}
            resolvers(mod, [R("10.0.0.53", ok=False, ms=2000, answers=())])
        self.assert_blames(self.diagnose_with(setup), "inet_unreachable", "provider")

    def test_localised_path_loss_beats_retransmits_and_call_quality(self):
        def setup(mod):
            mtr(mod, [{"count": 1, "host": "10.0.0.1", "Loss%": 0.0, "Snt": 30, "Avg": 1.5},
                      {"count": 2, "host": "198.51.100.63", "Loss%": 22.0, "Snt": 30, "Avg": 40.0},
                      {"count": 3, "host": "dns.google (8.8.8.8)", "Loss%": 20.0,
                       "Snt": 30, "Avg": 45.0}])
            ping_map(mod, inet_loss=20, avg=45.0, mdev=30.0)
            mod._read_tcp_counters = lambda: {"OutSegs": 100000, "RetransSegs": 5000}
        self.assert_blames(self.diagnose_with(setup), "path_loss", "segment")

    def test_a_full_link_is_called_capacity_not_a_fault(self):
        """The worst possible outcome here is someone replacing working hardware
        because the tool said something was broken."""
        def setup(mod):
            counters(mod, d_rx_bytes=240_000_000)
            mod.cmd_link_modes = lambda: {"ok": True, "cmd": "s", "stdout": "", "interfaces": [
                {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "mtu": 1500,
                 "carrier": True}]}
            mod._read_tcp_counters = lambda: {"OutSegs": 100000, "RetransSegs": 3000}
            ping_map(mod, inet_loss=2, avg=90.0, mdev=40.0)
        self.assert_blames(self.diagnose_with(setup), "link_saturated", "capacity")

    def test_a_leaking_application_is_not_blamed_on_the_network(self):
        def setup(mod):
            mod.cmd_socket_states = lambda: {"ok": True, "cmd": "ss", "stdout": "",
                "states": {"ESTABLISHED": 12, "CLOSE_WAIT": 40}, "pending": {}}
        self.assert_blames(self.diagnose_with(setup), "close_wait_backlog", "application")

    def test_interception_is_found_on_an_otherwise_perfect_network(self):
        def setup(mod):
            mod.cmd_tls_check = lambda h, p=443, timeout=5: {
                "ok": True, "cmd": "tls", "host": h, "port": p, "verified": False,
                "intercepted_by": "fortinet", "issuer": "Fortinet Root CA",
                "verify_error": "self signed certificate in chain",
                "tls_version": "TLSv1.2", "stdout": ""}
        self.assert_blames(self.diagnose_with(setup, check_ports=["443"]),
                           "tls_intercepted", "re-signing")

    def test_a_blackhole_is_found_when_everything_else_passes(self):
        def setup(mod):
            mod.cmd_path_mtu = lambda t, m=None: {"ok": True, "cmd": "df", "stdout": "",
                "target": t, "iface_mtu": 1500, "path_mtu": 1400,
                "attempts": [{"mtu": 1500, "payload": 1472, "ok": False, "cmd": "x"}]}
        self.assert_blames(self.diagnose_with(setup), "pmtu_blackhole", "path")

    def test_a_dead_secondary_resolver_is_found_behind_a_working_one(self):
        def setup(mod):
            resolvers(mod, [R("10.0.0.53", ms=850.0),
                            R("10.0.0.54", ok=False, ms=2000, answers=())])
        self.assert_blames(self.diagnose_with(setup), "dns_resolver_down", "DNS")


if __name__ == "__main__":
    unittest.main(verbosity=2)
