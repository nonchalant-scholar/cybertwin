CyberTwin — Interactive Cyberattack Simulation & Defense Lab
Tagline: Simulate the Threat. Detect the Evidence. Investigate the Incident.
CyberTwin is an educational cybersecurity prototype that simulates suspicious login activity, identifies configured patterns using rule-based detection, presents investigation evidence, and records simulated defensive responses.
The project demonstrates a basic security-monitoring workflow using synthetic authentication events and an interactive Streamlit dashboard.

Disclaimer: CyberTwin is a local educational simulation. It does not perform real cyberattacks, interact with real authentication systems, or enforce real security controls.

1. Project Overview
Authentication logs can contain patterns that warrant further investigation, such as repeated failed logins, attempts against multiple accounts, or failed logins followed by a successful login.
CyberTwin generates synthetic login events and evaluates them against predefined detection rules. The dashboard presents the generated events, detection alerts, investigation timelines, and simulated response history.
The prototype is designed to demonstrate the relationship between event generation, rule-based detection, evidence review, and defensive decision-making.
2. Objectives

Generate synthetic authentication events for controlled security scenarios.
Detect configured suspicious login patterns using predefined rules.
Display event statistics and visualizations.
Present alert severity, evidence, and recommended actions.
Reconstruct related events in chronological order for investigation.
Simulate defensive response actions.
Maintain an in-memory history of simulated analyst actions.
Validate detection behaviour through automated tests.

3. Features
Synthetic Event Simulation
CyberTwin supports three scenarios:

Repeated Failed Logins — generates repeated failed authentication attempts against an account.
Multiple Accounts Targeted — generates failed login attempts involving multiple accounts from a source IP.
Failed Logins Followed by Success — generates failed authentication attempts followed by a successful login.

Rule-Based Detection
The detection engine evaluates generated events against predefined rules.



Rule ID
Detection pattern
Severity




CT-001
At least 5 failed logins for the same username and source IP within 60 seconds
High


CT-002
Failed logins from the same source IP against at least 3 distinct accounts within 60 seconds
Medium


CT-003
At least 3 failed logins before a successful login for the same username and source IP within 60 seconds
High



These thresholds are illustrative and intended for educational demonstration. They are not universal security standards.
Interactive Dashboard
The Streamlit dashboard displays:

Total generated events.
Failed and successful login counts.
A login-event distribution chart.
Detection alert summaries.
Alert severity, evidence, and recommended actions.
Related events arranged chronologically.
Investigation summaries.

Simulated Defensive Responses
The analyst can select one of three actions:

Simulate Account Lockout.
Record for Further Investigation.
Dismiss Alert.

CyberTwin records the selected action in an in-memory response history.
These actions do not affect real accounts or operating-system security controls. The simulated state is reset when a new simulation is run and is not designed for persistent storage.
4. Technology Stack

Python — application logic and event processing.
Streamlit — interactive web dashboard.
Pandas — tabular event processing and analysis.
Plotly Express — event-distribution visualization.
pytest — automated testing.

The current detection engine is rule-based. It does not use a trained machine-learning model.
5. Project Structure
CyberTwin/
├── app.py
├── detector.py
├── response.py
├── simulator.py
├── test_detector.py
└── README.md

The Python virtual environment and generated cache folders may also be present locally.
6. Requirements

Python installed on your system.
A terminal or command prompt.
A web browser.
The Python packages listed below.

7. Installation
Open a terminal in the project directory.
Create a virtual environment:
python -m venv .venv

Activate it in Windows PowerShell:
.\.venv\Scripts\Activate.ps1

Install the required packages:
python -m pip install streamlit pandas plotly pytest

If PowerShell blocks virtual-environment activation, you can use the Python executable inside .venv directly to run the application and tests.
8. Run the Application
From the project directory, run:
python -m streamlit run app.py

Streamlit will provide a local address that you can open in your browser.
Choose one of the available scenarios and click Run Simulation to generate events and evaluate them.
9. Run the Tests
Run the automated detection tests with:
python -m pytest -v

The current test suite covers:

Detection of repeated failed logins.
Detection of multiple accounts targeted from a source IP.
Detection of failed logins followed by success.
Handling of empty input.
Handling of a number of failures below the configured threshold.

The five existing detector tests have passed during development.
10. Limitations
CyberTwin is an educational prototype with the following limitations:

It uses synthetic login events rather than live authentication logs.
Detection is limited to the implemented rules and thresholds.
A detection alert indicates a suspicious pattern, not proof of a cyberattack or account compromise.
Source IP addresses and account names belong to the simulation.
Defensive actions update only the application's in-memory simulated state.
Response history is not stored persistently.
The prototype is not a production security monitoring or incident-response system.

11. Future Improvements
Potential future improvements include:

A more polished dashboard interface.
Additional detection rules and configurable thresholds.
Improved incident correlation and investigation views.
Persistent storage for simulated events and response history.
Additional automated tests for detection and response behaviour.
Exportable incident reports.

These are potential extensions rather than claims about currently implemented functionality.
12. Safety Statement
CyberTwin is intended for educational use and controlled demonstrations. All scenarios use synthetic data, and all response actions are simulated within the application.
The project does not attempt to compromise accounts, generate real authentication attacks, or apply defensive controls to external systems.
