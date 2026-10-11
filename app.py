import streamlit as st
import pandas as pd
import plotly.express as px

from simulator import generate_events
from detector import detect_suspicious_activity
from response import simulate_response


# --------------------------------------------------
# Page configuration
# --------------------------------------------------

st.set_page_config(
    page_title="CyberTwin",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# Initialize session state
# --------------------------------------------------

if "events_df" not in st.session_state:
    st.session_state["events_df"] = None

if "alerts" not in st.session_state:
    st.session_state["alerts"] = []

if "scenario" not in st.session_state:
    st.session_state["scenario"] = None

if "response_state" not in st.session_state:
    st.session_state["response_state"] = {
        "locked_accounts": [],
        "history": []
    }

if "latest_response" not in st.session_state:
    st.session_state["latest_response"] = None


# --------------------------------------------------
# Header
# --------------------------------------------------

st.title("🛡️ CyberTwin")

st.subheader(
    "Interactive Cyberattack Simulation & Defense Lab"
)

st.write(
    "Simulate security events, detect suspicious patterns, "
    "investigate evidence, and simulate defensive responses."
)

st.caption(
    "Educational prototype using synthetic data only. "
    "No real attacks or authentication systems are involved."
)

st.divider()


# --------------------------------------------------
# Scenario selection
# --------------------------------------------------

st.header("1. Select a Simulation Scenario")

scenario = st.selectbox(
    "Choose a scenario:",
    [
        "Repeated Failed Logins",
        "Multiple Accounts Targeted",
        "Failed Logins Followed by Success"
    ]
)


if st.button("▶ Run Simulation", type="primary"):

    events = generate_events(scenario)

    events_df = pd.DataFrame(events)

    events_df["timestamp"] = pd.to_datetime(
        events_df["timestamp"],
        errors="raise"
    )

    events_df = (
        events_df
        .sort_values("timestamp")
        .reset_index(drop=True)
    )

    alerts = detect_suspicious_activity(events_df)

    st.session_state["events_df"] = events_df
    st.session_state["alerts"] = alerts
    st.session_state["scenario"] = scenario

    # Reset simulated defensive state for the new scenario.
    st.session_state["response_state"] = {
        "locked_accounts": [],
        "history": []
    }

    st.session_state["latest_response"] = None


# --------------------------------------------------
# Simulation results
# --------------------------------------------------

if st.session_state["events_df"] is None:

    st.info(
        "Choose a scenario and click 'Run Simulation' "
        "to generate events and analyse them."
    )

else:

    df = st.session_state["events_df"]
    alerts = st.session_state["alerts"]
    current_scenario = st.session_state["scenario"]

    st.divider()

    st.header("2. Simulation Results")

    st.write(f"**Scenario:** {current_scenario}")

    total_events = len(df)

    failed_logins = int(
        (df["status"] == "failure").sum()
    )

    successful_logins = int(
        (df["status"] == "success").sum()
    )

    col1, col2, col3 = st.columns(3)

    col1.metric("Total Events", total_events)
    col2.metric("Failed Logins", failed_logins)
    col3.metric("Successful Logins", successful_logins)

    st.subheader("Generated Security Events")

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True
    )

    st.subheader("Login Event Overview")

    chart_data = (
        df["status"]
        .value_counts()
        .rename_axis("Login Status")
        .reset_index(name="Count")
    )

    chart = px.bar(
        chart_data,
        x="Login Status",
        y="Count",
        color="Login Status",
        title="Distribution of Login Events",
        text="Count"
    )

    st.plotly_chart(
        chart,
        use_container_width=True
    )

    # --------------------------------------------------
    # Detection and alert analysis
    # --------------------------------------------------

    st.divider()

    st.header("3. Detection & Alert Analysis")

    if not alerts:

        st.success(
            "No configured detection rules were triggered."
        )

        st.caption(
            "This does not guarantee that all activity is safe. "
            "Only the configured detection rules were evaluated."
        )

    else:

        st.warning(
            f"The detection engine generated {len(alerts)} alert(s)."
        )

        high_alerts = sum(
            alert["severity"] == "High"
            for alert in alerts
        )

        medium_alerts = sum(
            alert["severity"] == "Medium"
            for alert in alerts
        )

        alert_col1, alert_col2, alert_col3 = st.columns(3)

        alert_col1.metric("Total Alerts", len(alerts))
        alert_col2.metric("High Severity", high_alerts)
        alert_col3.metric("Medium Severity", medium_alerts)

        alerts_df = pd.DataFrame(alerts)

        st.subheader("Alert Summary")

        summary_columns = [
            "rule_id",
            "alert_type",
            "severity",
            "username",
            "source_ip",
            "event_count"
        ]

        st.dataframe(
            alerts_df[summary_columns],
            use_container_width=True,
            hide_index=True
        )

        # --------------------------------------------------
        # Investigation and simulated response
        # --------------------------------------------------

        st.header("4. Investigation & Response")

        st.warning(
            "All response actions below are simulated. "
            "They do not affect real accounts or systems."
        )

        for index, alert in enumerate(alerts):

            with st.expander(
                f"{alert['rule_id']} — {alert['alert_type']} "
                f"({alert['severity']} Severity)",
                expanded=(index == 0)
            ):

                st.markdown(
                    f"**Severity:** {alert['severity']}"
                )

                st.markdown(
                    f"**Rule ID:** {alert['rule_id']}"
                )

                st.markdown(
                    f"**Account(s):** {alert['username']}"
                )

                st.markdown(
                    f"**Simulated source IP:** {alert['source_ip']}"
                )

                st.markdown(
                    f"**Events involved:** {alert['event_count']}"
                )

                st.markdown(
                    f"**First observed:** {alert['first_seen']}"
                )

                st.markdown(
                    f"**Last observed:** {alert['last_seen']}"
                )

                st.markdown("#### Evidence")

                st.write(alert["evidence"])

                st.markdown("#### Recommended Action")

                st.info(alert["recommended_action"])

                # --------------------------------------------------
                # Incident Investigation Timeline
                # --------------------------------------------------

                st.markdown("#### Incident Investigation Timeline")

                # Select events associated with the alert's source IP.
                related = df[
                    df["source_ip"] == alert["source_ip"]
                ].copy()

                # For single-account rules, narrow the investigation
                # to the username associated with the alert.
                if alert["rule_id"] in ["CT-001", "CT-003"]:

                    related = related[
                        related["username"] == alert["username"]
                    ]

                # Display the related events in chronological order.
                related = (
                    related
                    .sort_values("timestamp")
                    .reset_index(drop=True)
                )

                if related.empty:

                    st.info(
                        "No related events were found in the "
                        "current synthetic dataset."
                    )

                else:

                    # Add an investigation sequence number.
                    timeline = related.copy()

                    timeline.insert(
                        0,
                        "sequence",
                        range(1, len(timeline) + 1)
                    )

                    timeline_columns = [
                        "sequence",
                        "timestamp",
                        "username",
                        "source_ip",
                        "status"
                    ]

                    st.dataframe(
                        timeline[timeline_columns],
                        use_container_width=True,
                        hide_index=True
                    )

                    # Summarize the event sequence.
                    failure_count = int(
                        (related["status"] == "failure").sum()
                    )

                    success_count = int(
                        (related["status"] == "success").sum()
                    )

                    st.markdown("#### Investigation Summary")

                    st.write(
                        f"- Related events displayed: {len(related)}"
                    )

                    st.write(
                        f"- Failed login events: {failure_count}"
                    )

                    st.write(
                        f"- Successful login events: {success_count}"
                    )

                    if failure_count > 0 and success_count > 0:

                        st.warning(
                            "The related events include both failed "
                            "and successful login attempts. Review "
                            "their timestamps and context before "
                            "drawing conclusions."
                        )

                    elif failure_count > 0:

                        st.info(
                            "The related events contain failed login "
                            "attempts. This pattern alone does not "
                            "establish that an account was compromised."
                        )

                    else:

                        st.info(
                            "Review the displayed events in context. "
                            "The configured detection rules and "
                            "synthetic dataset define the scope "
                            "of this investigation."
                        )

                # --------------------------------------------------
                # Simulated analyst response
                # --------------------------------------------------

                st.markdown("#### Simulate an Analyst Response")

                action = st.selectbox(
                    "Choose a response action:",
                    [
                        "Simulate Account Lockout",
                        "Record for Further Investigation",
                        "Dismiss Alert"
                    ],
                    key=f"response_action_{index}"
                )

                if st.button(
                    "Execute Simulated Response",
                    key=f"execute_response_{index}"
                ):

                    try:

                        record = simulate_response(
                            alert,
                            action,
                            st.session_state["response_state"]
                        )

                        st.session_state["latest_response"] = record

                        st.success(record["status"])

                        st.write(record["details"])

                    except ValueError as error:

                        st.error(str(error))

    # --------------------------------------------------
    # Simulated account state
    # --------------------------------------------------

    st.divider()

    st.header("5. Simulated Defensive State")

    locked_accounts = st.session_state[
        "response_state"
    ]["locked_accounts"]

    if locked_accounts:

        st.warning(
            "The following demo account identifiers are marked "
            "as locked in this simulation:"
        )

        for account in locked_accounts:
            st.write(f"- {account}")

    else:

        st.info(
            "No demo accounts have been marked as locked "
            "during this simulation."
        )

    # --------------------------------------------------
    # Response audit history
    # --------------------------------------------------

    st.subheader("Response Audit History")

    history = st.session_state["response_state"]["history"]

    if history:

        history_df = pd.DataFrame(history)

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No simulated response actions have been recorded yet."
        )

    # --------------------------------------------------
    # Scope and limitations
    # --------------------------------------------------

    st.divider()

    st.caption(
        "CyberTwin is a rule-based educational prototype. "
        "Alerts identify patterns in synthetic data and do not "
        "prove a real cyberattack occurred. Response actions "
        "only update the application's in-memory simulation."
    )

