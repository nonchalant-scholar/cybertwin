from datetime import datetime, timedelta
import random


def generate_events(scenario: str) -> list[dict]:
    """
    Generate fictional login events for CyberTwin.

    All events are synthetic and remain within the application.
    """

    events = []
    start_time = datetime.now().replace(microsecond=0)

    def add_event(
        timestamp,
        username,
        source_ip,
        status
    ):
        events.append({
            "timestamp": timestamp.isoformat(sep=" "),
            "username": username,
            "source_ip": source_ip,
            "event_type": "login",
            "status": status
        })

    if scenario == "Repeated Failed Logins":

        username = "demo_alex"
        source_ip = "192.0.2.10"

        for i in range(7):
            timestamp = start_time + timedelta(seconds=i * 5)

            add_event(
                timestamp,
                username,
                source_ip,
                "failure"
            )

    elif scenario == "Multiple Accounts Targeted":

        source_ip = "192.0.2.20"
        usernames = [
            "demo_alex",
            "demo_sam",
            "demo_jordan",
            "demo_taylor"
        ]

        for i, username in enumerate(usernames):
            for attempt in range(2):
                timestamp = start_time + timedelta(
                    seconds=i * 8 + attempt * 3
                )

                add_event(
                    timestamp,
                    username,
                    source_ip,
                    "failure"
                )

    elif scenario == "Failed Logins Followed by Success":

        username = "demo_casey"
        source_ip = "192.0.2.30"

        for i in range(4):
            timestamp = start_time + timedelta(seconds=i * 10)

            add_event(
                timestamp,
                username,
                source_ip,
                "failure"
            )

        timestamp = start_time + timedelta(seconds=45)

        add_event(
            timestamp,
            username,
            source_ip,
            "success"
        )

    else:
        raise ValueError(f"Unknown scenario: {scenario}")

    # Randomize event ordering to ensure the investigation
    # module can sort events chronologically later.
    random.shuffle(events)

    return events

