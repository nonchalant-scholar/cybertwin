from datetime import datetime


def simulate_response(
    alert: dict,
    action: str,
    response_state: dict
) -> dict:
    """
    Simulate a defensive response within CyberTwin.

    This function does not interact with real accounts,
    networks, operating systems, or security controls.
    """

    valid_actions = {
        "Simulate Account Lockout",
        "Record for Further Investigation",
        "Dismiss Alert"
    }

    if action not in valid_actions:
        raise ValueError(f"Unsupported response action: {action}")

    username = str(alert.get("username", "")).strip()

    if not username:
        raise ValueError("The alert must identify an account.")

    if action == "Simulate Account Lockout":
        response_state.setdefault("locked_accounts", [])

        if username not in response_state["locked_accounts"]:
            response_state["locked_accounts"].append(username)

        status = "Simulated account lockout recorded"

        details = (
            f"The demo account '{username}' has been marked "
            "as locked in CyberTwin's in-memory simulation."
        )

    elif action == "Record for Further Investigation":
        status = "Escalated for investigation"

        details = (
            f"The alert for '{username}' has been marked "
            "for further investigation in the simulation."
        )

    else:
        status = "Alert dismissed"

        details = (
            f"The alert for '{username}' has been dismissed "
            "in the simulation. This does not establish "
            "that the activity was legitimate."
        )

    record = {
        "timestamp": datetime.now().isoformat(
            sep=" ",
            timespec="seconds"
        ),
        "rule_id": alert.get("rule_id", "Unknown"),
        "username": username,
        "action": action,
        "status": status,
        "details": details
    }

    response_state.setdefault("history", [])
    response_state["history"].append(record)

    return record

