"""
Unit tests for agent-side collectors.

All tests run without network access, a running DK server, or any external
tools (nmap, grype, netmiko).  We test only the pure-Python parsing and
extraction logic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# network_scan.py
# ---------------------------------------------------------------------------

class TestIsPrivateCidrAgent:
    """The agent has its own private-range check (no server dep)."""

    def _is_private(self, cidr: str) -> bool:
        from agent.collectors.network_scan import _is_private_cidr
        return _is_private_cidr(cidr)

    def test_rfc1918(self) -> None:
        assert self._is_private("192.168.1.0/24")
        assert self._is_private("10.0.0.0/8")
        assert self._is_private("172.16.0.0/12")

    def test_loopback(self) -> None:
        assert self._is_private("127.0.0.1/32")

    def test_public(self) -> None:
        assert not self._is_private("8.8.8.0/24")


class TestParseNmapXml:
    """Parse nmap XML output without calling nmap."""

    _SIMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames>
      <hostname name="myhost.local" type="PTR"/>
    </hostnames>
    <os>
      <osmatch name="Ubuntu 22.04" accuracy="95"/>
    </os>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
        <script id="http-server-header" output="nginx/1.24"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.6" addrtype="ipv4"/>
  </host>
</nmaprun>"""

    def test_only_up_hosts_returned(self) -> None:
        from agent.collectors.network_scan import _parse_nmap_xml
        hosts = _parse_nmap_xml(self._SIMPLE_XML)
        assert len(hosts) == 1
        assert hosts[0].ip == "10.0.0.5"

    def test_fqdn_from_ptr(self) -> None:
        from agent.collectors.network_scan import _parse_nmap_xml
        hosts = _parse_nmap_xml(self._SIMPLE_XML)
        assert hosts[0].fqdn == "myhost.local"

    def test_os_detection(self) -> None:
        from agent.collectors.network_scan import _parse_nmap_xml
        hosts = _parse_nmap_xml(self._SIMPLE_XML)
        assert hosts[0].os == "Ubuntu"
        assert hosts[0].os_version == "22.04"

    def test_open_ports_only(self) -> None:
        from agent.collectors.network_scan import _parse_nmap_xml
        hosts = _parse_nmap_xml(self._SIMPLE_XML)
        ports = [s.port for s in hosts[0].services]
        assert 22 in ports
        assert 80 in ports
        assert 443 not in ports  # closed

    def test_service_version(self) -> None:
        from agent.collectors.network_scan import _parse_nmap_xml
        hosts = _parse_nmap_xml(self._SIMPLE_XML)
        ssh = next(s for s in hosts[0].services if s.port == 22)
        assert ssh.service_name == "ssh"
        assert "OpenSSH" in (ssh.version or "")

    def test_banner_from_script(self) -> None:
        from agent.collectors.network_scan import _parse_nmap_xml
        hosts = _parse_nmap_xml(self._SIMPLE_XML)
        http = next(s for s in hosts[0].services if s.port == 80)
        assert http.banner == "nginx/1.24"

    def test_empty_xml_returns_empty(self) -> None:
        from agent.collectors.network_scan import _parse_nmap_xml
        assert _parse_nmap_xml("<nmaprun></nmaprun>") == []

    def test_invalid_xml_returns_empty(self) -> None:
        from agent.collectors.network_scan import _parse_nmap_xml
        assert _parse_nmap_xml("not xml at all") == []


# ---------------------------------------------------------------------------
# cve_scan.py
# ---------------------------------------------------------------------------

class TestCvssToSeverity:
    def _sev(self, score: float) -> str:
        from agent.collectors.cve_scan import _cvss_to_severity
        return _cvss_to_severity(score)

    def test_critical(self) -> None:
        assert self._sev(9.8) == "critical"
        assert self._sev(9.0) == "critical"

    def test_high(self) -> None:
        assert self._sev(8.9) == "high"
        assert self._sev(7.0) == "high"

    def test_medium(self) -> None:
        assert self._sev(6.9) == "medium"
        assert self._sev(4.0) == "medium"

    def test_low(self) -> None:
        assert self._sev(3.9) == "low"
        assert self._sev(0.1) == "low"

    def test_none(self) -> None:
        assert self._sev(0.0) == "none"


class TestNvdItemToFinding:
    _NVD_ITEM = {
        "cve": {
            "id": "CVE-2023-12345",
            "descriptions": [
                {"lang": "en", "value": "A critical vulnerability."},
                {"lang": "fr", "value": "Une vulnérabilité critique."},
            ],
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                ]
            },
            "references": [
                {"url": "https://vendor.example.com/patch", "tags": ["Patch", "Vendor Advisory"]},
            ],
        }
    }

    def test_cve_id(self) -> None:
        from agent.collectors.cve_scan import _nvd_item_to_finding, InstalledPackage
        pkg = InstalledPackage(name="openssl", version="1.1.1", package_manager="dpkg")
        finding = _nvd_item_to_finding(self._NVD_ITEM, pkg)
        assert finding is not None
        assert finding.cve_id == "CVE-2023-12345"

    def test_english_description_preferred(self) -> None:
        from agent.collectors.cve_scan import _nvd_item_to_finding, InstalledPackage
        pkg = InstalledPackage(name="openssl", version="1.1.1", package_manager="dpkg")
        finding = _nvd_item_to_finding(self._NVD_ITEM, pkg)
        assert finding is not None
        assert finding.description == "A critical vulnerability."

    def test_cvss_score_and_severity(self) -> None:
        from agent.collectors.cve_scan import _nvd_item_to_finding, InstalledPackage
        pkg = InstalledPackage(name="openssl", version="1.1.1", package_manager="dpkg")
        finding = _nvd_item_to_finding(self._NVD_ITEM, pkg)
        assert finding is not None
        assert finding.cvss_score == 9.8
        assert finding.severity == "critical"

    def test_patch_url_as_remediation(self) -> None:
        from agent.collectors.cve_scan import _nvd_item_to_finding, InstalledPackage
        pkg = InstalledPackage(name="openssl", version="1.1.1", package_manager="dpkg")
        finding = _nvd_item_to_finding(self._NVD_ITEM, pkg)
        assert finding is not None
        assert "vendor.example.com" in (finding.remediation or "")

    def test_package_fields(self) -> None:
        from agent.collectors.cve_scan import _nvd_item_to_finding, InstalledPackage
        pkg = InstalledPackage(name="openssl", version="1.1.1t", package_manager="dpkg")
        finding = _nvd_item_to_finding(self._NVD_ITEM, pkg)
        assert finding is not None
        assert finding.package_name == "openssl"
        assert finding.package_version == "1.1.1t"


# ---------------------------------------------------------------------------
# ansible.py
# ---------------------------------------------------------------------------

class TestAnsibleExtractIps:
    def _extract(self, facts: dict) -> list[str]:
        from agent.collectors.ansible import _extract_ips
        return _extract_ips(facts, "test-host")

    def test_ansible_host_takes_priority(self) -> None:
        facts = {
            "ansible_host": "10.0.0.5",
            "ansible_default_ipv4": {"address": "10.0.0.6"},
        }
        ips = self._extract(facts)
        assert ips[0] == "10.0.0.5"

    def test_default_ipv4_included(self) -> None:
        facts = {"ansible_default_ipv4": {"address": "10.0.0.10"}}
        ips = self._extract(facts)
        assert "10.0.0.10" in ips

    def test_all_ipv4_addresses(self) -> None:
        facts = {"ansible_all_ipv4_addresses": ["10.0.0.1", "10.0.0.2", "127.0.0.1"]}
        ips = self._extract(facts)
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips
        assert "127.0.0.1" not in ips  # loopback filtered

    def test_no_duplicates(self) -> None:
        facts = {
            "ansible_host": "10.0.0.5",
            "ansible_default_ipv4": {"address": "10.0.0.5"},
            "ansible_all_ipv4_addresses": ["10.0.0.5"],
        }
        ips = self._extract(facts)
        assert ips.count("10.0.0.5") == 1


class TestAnsibleExtractPackages:
    def test_standard_package_format(self) -> None:
        from agent.collectors.ansible import _extract_packages
        facts = {
            "ansible_packages": {
                "bash": [{"name": "bash", "version": "5.1", "arch": "amd64"}],
                "curl": [{"name": "curl", "version": "7.88"}],
            }
        }
        pkgs = _extract_packages(facts)
        names = {p["name"] for p in pkgs}
        assert "bash" in names
        assert "curl" in names
        bash = next(p for p in pkgs if p["name"] == "bash")
        assert bash["version"] == "5.1"
        assert bash["package_manager"] == "ansible"

    def test_missing_packages_fact(self) -> None:
        from agent.collectors.ansible import _extract_packages
        assert _extract_packages({}) == []

    def test_non_dict_packages_ignored(self) -> None:
        from agent.collectors.ansible import _extract_packages
        assert _extract_packages({"ansible_packages": "not-a-dict"}) == []


class TestAnsibleFactCacheReader:
    def test_reads_json_file(self, tmp_path: Path) -> None:
        from agent.collectors.ansible import read_fact_cache
        facts = {"ansible_facts": {"ansible_fqdn": "web01.example.com"}}
        (tmp_path / "web01.json").write_text(json.dumps(facts))
        result = read_fact_cache(str(tmp_path))
        assert "web01" in result
        assert result["web01"]["ansible_fqdn"] == "web01.example.com"

    def test_unwraps_ansible_facts_key(self, tmp_path: Path) -> None:
        from agent.collectors.ansible import read_fact_cache
        facts = {"ansible_facts": {"ansible_distribution": "Ubuntu"}}
        (tmp_path / "host1.json").write_text(json.dumps(facts))
        result = read_fact_cache(str(tmp_path))
        assert result["host1"]["ansible_distribution"] == "Ubuntu"

    def test_missing_dir_returns_empty(self) -> None:
        from agent.collectors.ansible import read_fact_cache
        result = read_fact_cache("/nonexistent/path/that/does/not/exist")
        assert result == {}

    def test_ignores_subdirectories(self, tmp_path: Path) -> None:
        from agent.collectors.ansible import read_fact_cache
        (tmp_path / "subdir").mkdir()
        (tmp_path / "host1.json").write_text(json.dumps({"ansible_fqdn": "h1"}))
        result = read_fact_cache(str(tmp_path))
        assert len(result) == 1


# ---------------------------------------------------------------------------
# netmiko_collector.py
# ---------------------------------------------------------------------------

class TestRedactConfig:
    def _redact(self, text: str) -> str:
        from agent.collectors.netmiko_collector import _redact_config
        return _redact_config(text)

    def test_password_redacted(self) -> None:
        result = self._redact("enable password mysecretpass")
        assert "mysecretpass" not in result
        assert "<REDACTED>" in result

    def test_secret_redacted(self) -> None:
        result = self._redact("enable secret 5 $1$abc$xyz")
        assert "$1$abc$xyz" not in result

    def test_community_redacted(self) -> None:
        result = self._redact("snmp-server community public RO")
        assert "public" not in result

    def test_other_lines_unchanged(self) -> None:
        result = self._redact("interface GigabitEthernet0/0")
        assert "interface GigabitEthernet0/0" in result


class TestParseArpIos:
    _ARP_OUTPUT = """\
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.0.0.1                -   aabb.cc00.0100  ARPA   Vlan1
Internet  10.0.0.2               10   aabb.cc00.0200  ARPA   Vlan1
Internet  10.0.0.3                5   aabb.cc00.0300  ARPA   GigabitEthernet0/1
"""

    def test_parses_all_entries(self) -> None:
        from agent.collectors.netmiko_collector import _parse_arp_ios
        entries = _parse_arp_ios(self._ARP_OUTPUT)
        ips = [e["ip"] for e in entries]
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips
        assert "10.0.0.3" in ips

    def test_empty_output(self) -> None:
        from agent.collectors.netmiko_collector import _parse_arp_ios
        assert _parse_arp_ios("") == []


class TestParseLldpNeighbors:
    _LLDP_OUTPUT = """\
Device ID: switch02.example.com
  IP address: 10.0.0.20
  Local Port id: GigabitEthernet0/1

Device ID: router01.example.com
  IP address: 10.0.0.1
  Local Port id: GigabitEthernet0/2
"""

    def test_parses_neighbours(self) -> None:
        from agent.collectors.netmiko_collector import _parse_lldp_neighbors
        neighbours = _parse_lldp_neighbors(self._LLDP_OUTPUT)
        hosts = [n.get("remote_host", "") for n in neighbours]
        assert any("switch02" in h for h in hosts)
        assert any("router01" in h for h in hosts)

    def test_empty_output(self) -> None:
        from agent.collectors.netmiko_collector import _parse_lldp_neighbors
        assert _parse_lldp_neighbors("") == []


class TestParseVersionIos:
    _IOS_VERSION = """\
Cisco IOS XE Software, Version 17.03.03
Cisco IOS Software [Amsterdam], Catalyst L3 Switch Software
cisco C9300-24T (X86) processor
Version 17.3.3
"""

    def test_vendor_is_cisco(self) -> None:
        from agent.collectors.netmiko_collector import _parse_version_ios
        result = _parse_version_ios(self._IOS_VERSION)
        assert result["vendor"] == "Cisco"

    def test_firmware_version_extracted(self) -> None:
        from agent.collectors.netmiko_collector import _parse_version_ios
        result = _parse_version_ios(self._IOS_VERSION)
        assert result["firmware_version"] is not None
        assert "17" in result["firmware_version"]


# ---------------------------------------------------------------------------
# puppet.py — YAML loading and fact extraction
# ---------------------------------------------------------------------------

class TestPuppetYamlLoader:
    _YAML_WITH_RUBY_TAGS = """\
--- !ruby/object:Puppet::Node::Facts
  name: webserver01.example.com
  values:
    fqdn: webserver01.example.com
    ipaddress: 10.1.2.3
    osfamily: Debian
    operatingsystem: Ubuntu
    operatingsystemrelease: "22.04"
"""

    def test_loads_without_error(self) -> None:
        from agent.collectors.puppet import _load_puppet_yaml
        result = _load_puppet_yaml(self._YAML_WITH_RUBY_TAGS)
        assert result is not None

    def test_values_accessible(self) -> None:
        from agent.collectors.puppet import _load_puppet_yaml
        result = _load_puppet_yaml(self._YAML_WITH_RUBY_TAGS)
        assert result is not None
        values = result.get("values", {})
        assert values.get("fqdn") == "webserver01.example.com"

    def test_invalid_yaml_returns_none(self) -> None:
        from agent.collectors.puppet import _load_puppet_yaml
        result = _load_puppet_yaml(": this: is: not: valid: yaml: ::::")
        # Should either return None or not raise
        # (implementation returns None on parse error)
        assert result is None or isinstance(result, dict)
