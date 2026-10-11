import pandas as pd


def detect_suspicious_activity(
    events_df: pd.DataFrame,
    window_seconds: int = 60
) -> list[dict]:
    """
    Detect suspicious patterns in synthetic login events.

    Analyses login events without modifying the original DataFrame.
    Returns a list of explainable alerts.
    """

    # --------------------------------------------------
    # Input validation
    # --------------------------------------------------

    required_columns = {
        "timestamp",
        "username",
        "source_ip",
        "status",
    }

    missing_columns = required_columns - set(events_df.columns)

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {sorted(missing_columns)}"
        )

    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive.")

    if events_df.empty:
        return []

    # Work on a copy to preserve the original DataFrame.
    df = events_df.copy()

    # Convert timestamps to datetime values.
    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="raise",
    )

    df = df.sort_values("timestamp").reset_index(drop=True)

    alerts: list[dict] = []

    time_window = pd.Timedelta(seconds=window_seconds)

    # --------------------------------------------------
    # CT-001: Repeated failed logins
    #
    # Trigger:
    # At least 5 failures for the same username and
    # source IP within the configured time window.
    # --------------------------------------------------

    failures = df[df["status"] == "failure"]

    for (username, source_ip), group in failures.groupby(
        ["username", "source_ip"]
    ):
        group = group.sort_values("timestamp").reset_index(drop=True)

        # Explicit conversion helps make timestamp arithmetic clear.
        timestamps = [
            pd.Timestamp(value)
            for value in group["timestamp"]
        ]

        left = 0

        for right in range(len(group)):

            # Remove events outside the rolling time window.
            while (
                timestamps[right] - timestamps[left]
                > time_window
            ):
                left += 1

            window = group.iloc[left:right + 1]

            if len(window) >= 5:
                first_time = window.iloc[0]["timestamp"]
                last_time = window.iloc[-1]["timestamp"]

                alerts.append({
                    "rule_id": "CT-001",
                    "alert_type": "Repeated Failed Logins",
                    "severity": "High",
                    "username": username,
                    "source_ip": source_ip,
                    "event_count": len(window),
                    "evidence": (
                        f"{len(window)} failed login attempts "
                        f"occurred within {window_seconds} "
                        "seconds or less."
                    ),
                    "first_seen": first_time,
                    "last_seen": last_time,
                    "recommended_action": (
                        "Review the login history and verify "
                        "whether the activity is legitimate. "
                        "Consider protective controls if warranted."
                    ),
                })

                # One alert per account/source pair is sufficient
                # for this initial prototype.
                break

    # --------------------------------------------------
    # CT-002: Multiple accounts targeted
    #
    # Trigger:
    # Failed login attempts against at least 3 distinct
    # accounts from the same source IP within the window.
    # --------------------------------------------------

    for source_ip, group in failures.groupby("source_ip"):

        group = group.sort_values("timestamp").reset_index(drop=True)

        timestamps = [
            pd.Timestamp(value)
            for value in group["timestamp"]
        ]

        left = 0

        for right in range(len(group)):

            # Remove events outside the rolling time window.
            while (
                timestamps[right] - timestamps[left]
                > time_window
            ):
                left += 1

            window = group.iloc[left:right + 1]

            distinct_accounts = sorted(
                window["username"].unique().tolist()
            )

            if len(distinct_accounts) >= 3:

                alerts.append({
                    "rule_id": "CT-002",
                    "alert_type": "Multiple Accounts Targeted",
                    "severity": "Medium",
                    "username": ", ".join(distinct_accounts),
                    "source_ip": source_ip,
                    "event_count": len(window),
                    "evidence": (
                        "The same source was associated with "
                        "failed login attempts against "
                        f"{len(distinct_accounts)} distinct accounts "
                        f"within {window_seconds} seconds or less."
                    ),
                    "first_seen": window.iloc[0]["timestamp"],
                    "last_seen": window.iloc[-1]["timestamp"],
                    "recommended_action": (
                        "Review the affected accounts and determine "
                        "whether the shared source is expected."
                    ),
                })

                # One alert per source IP is sufficient
                # for this initial prototype.
                break

    # --------------------------------------------------
    # CT-003: Failed logins followed by success
    #
    # Trigger:
    # At least 3 failed login attempts followed by a
    # successful login for the same account and source
    # within the configured time window.
    # --------------------------------------------------

    for (username, source_ip), group in df.groupby(
        ["username", "source_ip"]
    ):

        group = group.sort_values("timestamp").reset_index(drop=True)

        timestamps = [
            pd.Timestamp(value)
            for value in group["timestamp"]
        ]

        for success_index in range(len(group)):

            success_event = group.iloc[success_index]

            if success_event["status"] != "success":
                continue

            success_time = timestamps[success_index]
            earlier_events = group.iloc[:success_index]

            recent_failures = earlier_events[
                (earlier_events["status"] == "failure")
                & (
                    earlier_events["timestamp"]
                    >= success_time - time_window
                )
            ]

            if len(recent_failures) >= 3:

                alerts.append({
                    "rule_id": "CT-003",
                    "alert_type": (
                        "Failed Logins Followed by Success"
                    ),
                    "severity": "High",
                    "username": username,
                    "source_ip": source_ip,
                    "event_count": len(recent_failures) + 1,
                    "evidence": (
                        f"{len(recent_failures)} failed login "
                        "attempts preceded a successful login "
                        f"within {window_seconds} seconds."
                    ),
                    "first_seen": (
                        recent_failures.iloc[0]["timestamp"]
                    ),
                    "last_seen": success_time,
                    "recommended_action": (
                        "Review the successful login and preceding "
                        "failures. Verify whether the account owner "
                        "recognizes the activity."
                    ),
                })

                # One alert per account/source pair is sufficient
                # for this initial prototype.
                break

    return alerts

