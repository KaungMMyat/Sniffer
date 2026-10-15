"""Tests for the port-scan detection logic and the security engine."""

from models.packet_info import PacketInfo
from security import SecurityEngine, SecurityAlert, Severity
from security.detectors.port_scan import PortScanDetector


def make_tcp(number, source, dst_port, flags="S"):
    return PacketInfo(
        number=number,
        time="12:00:00",
        source=source,
        destination="10.0.0.5",
        protocol="TCP",
        length=60,
        src_port="40000",
        dst_port=str(dst_port),
        tcp_flags=flags,
    )


def test_normal_traffic_no_alert():
    detector = PortScanDetector(port_threshold=5, time_window=10.0)
    alerts = [
        detector.inspect(make_tcp(i, "192.168.1.10", port))
        for i, port in enumerate([80, 443, 53], start=1)
    ]
    assert all(alert is None for alert in alerts), "Normal traffic raised an alert"
    print("[OK] Normal traffic (3 ports) -> no alert")


def test_syn_scan_triggers_alert():
    detector = PortScanDetector(port_threshold=5, time_window=10.0)
    alerts = [
        detector.inspect(make_tcp(i, "10.10.10.10", port))
        for i, port in enumerate([21, 22, 23, 25, 80], start=1)
    ]
    fired = [alert for alert in alerts if alert is not None]
    assert len(fired) == 1, f"Expected exactly one alert, got {len(fired)}"
    alert = fired[0]
    assert alert.alert_type == "Port Scan"
    assert alert.severity is Severity.HIGH
    assert alert.source == "10.10.10.10"
    print(f"[OK] SYN scan (5 ports) -> alert: {alert.description}")


def test_ack_packets_ignored():
    detector = PortScanDetector(port_threshold=3, time_window=10.0)
    alerts = [
        detector.inspect(make_tcp(i, "10.10.10.11", port, flags="A"))
        for i, port in enumerate([21, 22, 23, 25, 80], start=1)
    ]
    assert all(alert is None for alert in alerts), "ACK packets counted as scan"
    print("[OK] ACK-only traffic -> no alert")


def test_cooldown_prevents_duplicate_alerts():
    detector = PortScanDetector(port_threshold=3, time_window=10.0, cooldown=60.0)
    first = detector.inspect(make_tcp(1, "10.0.0.9", 80))
    detector.inspect(make_tcp(2, "10.0.0.9", 443))
    second = detector.inspect(make_tcp(3, "10.0.0.9", 22))  # triggers
    third = detector.inspect(make_tcp(4, "10.0.0.9", 8080))  # within cooldown
    assert first is None and second is not None
    assert third is None, "Cooldown did not suppress the duplicate alert"
    print("[OK] Cooldown suppresses duplicate alerts for the same source")


def test_engine_collects_alerts_via_callback():
    received = []
    engine = SecurityEngine(
        alert_callback=received.append,
        detectors=[PortScanDetector(port_threshold=3, time_window=10.0)],
    )
    for i, port in enumerate([21, 22, 23], start=1):
        engine.inspect(make_tcp(i, "172.16.0.7", port))

    assert len(received) == 1, "Callback was not invoked exactly once"
    assert len(engine.alerts) == 1, "Engine did not store the alert"
    engine.reset()
    assert engine.alerts == [], "Engine reset did not clear alerts"
    print("[OK] Engine delivers alerts via callback and resets cleanly")


if __name__ == "__main__":
    print("=" * 60)
    print("Security detection tests")
    print("=" * 60)
    test_normal_traffic_no_alert()
    test_syn_scan_triggers_alert()
    test_ack_packets_ignored()
    test_cooldown_prevents_duplicate_alerts()
    test_engine_collects_alerts_via_callback()
    print("=" * 60)
    print("All security tests passed")
    print("=" * 60)
