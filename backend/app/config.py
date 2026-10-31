"""Resource limits and detection thresholds.

Every threshold used by a detector lives here so that it is documented in one place
and can be tuned without touching detection logic. Resource limits can be overridden
with environment variables (no secrets are involved).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class Limits:
    # Upload and parsing limits protect the service against resource exhaustion.
    max_upload_bytes: int = _env_int("NETSENTINEL_MAX_UPLOAD_MB", 100) * 1024 * 1024
    max_packets: int = _env_int("NETSENTINEL_MAX_PACKETS", 300_000)
    max_analysis_seconds: int = _env_int("NETSENTINEL_MAX_SECONDS", 90)
    # Largest single record we accept; bigger records are treated as corrupt.
    max_record_bytes: int = 262_144
    # Concurrent analyses allowed (each one is CPU and memory heavy).
    max_concurrent_analyses: int = _env_int("NETSENTINEL_MAX_CONCURRENT", 2)
    # Response size bounds.
    max_evidence_per_finding: int = 200
    max_packet_summaries: int = 5_000
    max_conversations: int = 200


@dataclass(frozen=True)
class Thresholds:
    # --- TCP retransmissions -------------------------------------------------
    # A flow is reported when it has at least this many retransmitted segments ...
    retrans_min_per_flow: int = 3
    # ... and at least this share of its data segments were retransmissions.
    retrans_min_ratio: float = 0.02
    # Two identical segments closer than this (with identical IP ID) are treated as
    # a capture duplicate (e.g. SPAN port seeing a packet twice), not a retransmission.
    duplicate_capture_window: float = 0.0005

    # --- TCP resets ----------------------------------------------------------
    refused_min_per_service: int = 3
    aborted_min_per_peer: int = 5

    # --- Port scanning -------------------------------------------------------
    scan_window_seconds: float = 60.0
    scan_vertical_ports: int = 15        # distinct ports on one target inside the window
    scan_horizontal_hosts: int = 15      # distinct hosts on one port inside the window
    scan_slow_total_ports: int = 100     # distinct (host, port) pairs over the whole capture
    scan_min_failure_ratio: float = 0.6  # share of probes that never got a full connection
    scan_stealth_min_ports: int = 5      # FIN / NULL / XMAS probes have no legitimate use

    # --- ARP -----------------------------------------------------------------
    arp_flip_min_transitions: int = 2    # A -> B -> A counts as two transitions
    arp_unsolicited_min: int = 5         # unsolicited replies before calling it a pattern
    arp_reply_window: float = 2.0        # a reply within this time of a request is "solicited"

    # --- DNS -----------------------------------------------------------------
    dns_timeout_seconds: float = 2.0
    dns_min_failures: int = 3
    dns_slow_seconds: float = 0.5
    dns_min_slow: int = 3
    dns_nxdomain_min: int = 5
    dns_random_name_entropy: float = 3.5

    # --- DHCP ----------------------------------------------------------------
    dhcp_unanswered_discover_min: int = 3

    # --- Delays --------------------------------------------------------------
    handshake_slow_seconds: float = 0.5
    handshake_min_slow: int = 2
    response_slow_seconds: float = 2.0
    capture_gap_seconds: float = 10.0

    # --- MTU -----------------------------------------------------------------
    mtu_large_segment_bytes: int = 1200
    mtu_blackhole_min_retrans: int = 3

    # --- Correlation ---------------------------------------------------------
    correlation_gap_seconds: float = 120.0


@dataclass(frozen=True)
class Settings:
    limits: Limits = field(default_factory=Limits)
    thresholds: Thresholds = field(default_factory=Thresholds)


DEFAULT_SETTINGS = Settings()
