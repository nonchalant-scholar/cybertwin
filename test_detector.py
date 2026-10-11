import pandas as pd

from detector import detect_suspicious_activity
from simulator import generate_events


def test_repeated_failed_logins_detected():
    events = generate_events("Repeated Failed Logins")
    df = pd.DataFrame(events)

    alerts = detect_suspicious_activity(df)

    rule_ids = {alert["rule_id"] for alert in alerts}

    assert "CT-001" in rule_ids


def test_multiple_accounts_detected():
    events = generate_events("Multiple Accounts Targeted")
    df = pd.DataFrame(events)

    alerts = detect_suspicious_activity(df)

    rule_ids = {alert["rule_id"] for alert in alerts}

    assert "CT-002" in rule_ids


def test_failed_logins_followed_by_success_detected():
    events = generate_events(
        "Failed Logins Followed by Success"
    )
    df = pd.DataFrame(events)

    alerts = detect_suspicious_activity(df)

    rule_ids = {alert["rule_id"] for alert in alerts}

    assert "CT-003" in rule_ids


def test_empty_events_produce_no_alerts():
    df = pd.DataFrame(
        columns=[
            "timestamp",
            "username",
            "source_ip",
            "status"
        ]
    )

    alerts = detect_suspicious_activity(df)

    assert alerts == []


def test_fewer_than_five_failures_do_not_trigger_ct001():
    df = pd.DataFrame({
        "timestamp": pd.date_range(
            "2026-10-09 10:00:00",
            periods=4,
            freq="5s"
        ),
        "username": ["demo_user"] * 4,
        "source_ip": ["192.0.2.40"] * 4,
        "status": ["failure"] * 4
    })

    alerts = detect_suspicious_activity(df)

    rule_ids = {alert["rule_id"] for alert in alerts}

    assert "CT-001" not in rule_ids

def test_ct001_does_not_combine_failures_from_different_ips():
    events = pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-10-10 10:00:00",
            "2026-10-10 10:00:05",
            "2026-10-10 10:00:10",
            "2026-10-10 10:00:15",
            "2026-10-10 10:00:20",
        ]),
        "username": ["alice"] * 5,
        "source_ip": [
            "192.0.2.10",
            "192.0.2.10",
            "192.0.2.10",
            "192.0.2.20",
            "192.0.2.20",
        ],
        "status": ["failure"] * 5,
    })

    alerts = detect_suspicious_activity(events)

    ct001_alerts = [
        alert for alert in alerts
        if alert["rule_id"] == "CT-001"
    ]

    assert ct001_alerts == []


def test_ct002_does_not_trigger_for_only_two_accounts():
    events = pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-10-10 10:00:00",
            "2026-10-10 10:00:05",
            "2026-10-10 10:00:10",
        ]),
        "username": ["alice", "bob", "alice"],
        "source_ip": ["192.0.2.10"] * 3,
        "status": ["failure"] * 3,
    })

    alerts = detect_suspicious_activity(events)

    ct002_alerts = [
        alert for alert in alerts
        if alert["rule_id"] == "CT-002"
    ]

    assert ct002_alerts == []


def test_ct003_does_not_trigger_when_success_precedes_failures():
    events = pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-10-10 10:00:00",
            "2026-10-10 10:00:05",
            "2026-10-10 10:00:10",
            "2026-10-10 10:00:15",
        ]),
        "username": ["alice"] * 4,
        "source_ip": ["192.0.2.10"] * 4,
        "status": [
            "success",
            "failure",
            "failure",
            "failure",
        ],
    })

    alerts = detect_suspicious_activity(events)

    ct003_alerts = [
        alert for alert in alerts
        if alert["rule_id"] == "CT-003"
    ]

    assert ct003_alerts == []


def test_detector_rejects_zero_second_window():
    events = pd.DataFrame({
        "timestamp": pd.to_datetime(["2026-10-10 10:00:00"]),
        "username": ["alice"],
        "source_ip": ["192.0.2.10"],
        "status": ["failure"],
    })

    import pytest

    with pytest.raises(ValueError, match="window_seconds must be positive"):
        detect_suspicious_activity(events, window_seconds=0)


def test_detector_rejects_missing_required_column():
    events = pd.DataFrame({
        "timestamp": pd.to_datetime(["2026-10-10 10:00:00"]),
        "username": ["alice"],
        "source_ip": ["192.0.2.10"],
        # The required "status" column is intentionally missing.
    })

    import pytest

    with pytest.raises(ValueError, match="Missing required columns"):
        detect_suspicious_activity(events)


def test_detector_does_not_modify_original_dataframe():
    events = pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-10-10 10:00:00",
            "2026-10-10 10:00:05",
        ]),
        "username": ["alice", "alice"],
        "source_ip": ["192.0.2.10", "192.0.2.10"],
        "status": ["failure", "failure"],
    })

    original = events.copy(deep=True)

    detect_suspicious_activity(events)

    pd.testing.assert_frame_equal(events, original)


def test_ct001_includes_events_exactly_at_window_boundary():
    events = pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-10-10 10:00:00",
            "2026-10-10 10:00:15",
            "2026-10-10 10:00:30",
            "2026-10-10 10:00:45",
            "2026-10-10 10:01:00",
        ]),
        "username": ["alice"] * 5,
        "source_ip": ["192.0.2.10"] * 5,
        "status": ["failure"] * 5,
    })

    alerts = detect_suspicious_activity(events, window_seconds=60)

    ct001_alerts = [
        alert for alert in alerts
        if alert["rule_id"] == "CT-001"
    ]

    assert len(ct001_alerts) == 1
    assert ct001_alerts[0]["event_count"] == 5

