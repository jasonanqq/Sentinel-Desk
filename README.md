# Sentinel Desk

**Local Security Monitoring & Email Threat Analysis**

Sentinel Desk brings security logs, detection alerts and email investigations together in one dashboard. It is designed for learning, testing and investigating suspicious activity on your own computer.

## Quick start

**You need:** Windows 10/11 and Python 3.10 or newer. Other operating systems can run the dashboard with Python, but Windows Security log collection is only available on Windows. No extra Python packages are required.

1. Extract the project ZIP to a folder on your computer.
2. Open the `Sentinel_Desk` folder.
3. Double-click **`start_windows.bat`**.
4. Open **http://127.0.0.1:8765** in your browser.
5. Keep the command window open while using Sentinel Desk.
6. Press **Ctrl+C** in that window to stop the server.

If the batch file cannot find Python, install Python from [python.org](https://www.python.org/downloads/) and enable **Add Python to PATH** during installation. You can also open a terminal inside the project folder and run `python app.py` (or `python3 app.py` on macOS/Linux).

> Sentinel Desk runs on your computer, not on a public website. By default, the dashboard is only accessible from that computer. Its database is created locally when you first launch it.

## Explore the dashboard

| Page | What you can do |
| --- | --- |
| **Overview** | See event totals, blocked firewall traffic, current alerts, activity graphs and email investigation counts. Click a chart or source to investigate. |
| **Event Explorer** | Search collected logs and filter by source, severity, event type or date. Export matching events to CSV. |
| **Alert Center** | Review automatically detected activity, open alerts and mark investigated alerts as resolved. Export alerts to CSV. |
| **Data Ingestion** | Import security logs, generate test activity, start live log collectors and check or rebuild search indexes. |
| **Email Threat Analysis** | Submit suspicious emails, inspect detection evidence, search previous cases and manage investigation statuses. |

### First-time walkthrough

1. Go to **Overview** and select **Generate demo activity**.
2. Look at the **Activity over time** chart and click a time bucket.
3. Open **Event Explorer** to see the matching logs.
4. Open **Alert Center** and review the alerts raised by the detection rules.
5. Switch to **Data Ingestion** to see the available live collectors and search indexing status.

The generated events are simulated and are not evidence of an actual attack.

## Search by date or time

Use the **Time Range** controls near the top of the dashboard:

- Enter a number, choose **Days**, **Weeks**, **Months** or **Years**, and click **Search**. For example, `3` + `Weeks` searches the last three weeks from the current time.
- Or choose **24 hours**, **7 days**, **30 days**, **All time**, or **Custom** to select exact start and end times.

The date range applies to event searches, dashboards, alerts and email investigations. On the email page, you can choose **Date analysed** or **Original email date** to decide which date the investigation filter uses. The original email date comes from the supplied message and may not be trustworthy.

## Investigate a suspicious email

1. Select **Email Threat Analysis** in the left navigation.
2. Choose **Upload .eml** to analyse a saved email, or **Paste headers** to analyse copied raw email headers.
3. For a file, click **Choose file** and select a `.eml` file (maximum **1 MB**).
4. Click **Analyse Email**.
5. Review the **risk score**, threat category, authentication results and supporting evidence.
6. Scroll to **Email investigations** and click **Investigate** to reopen a case.
7. Update its status to **New**, **Investigating**, **Resolved**, or **False Positive**, then click **Save status**.

Try the sample files in `samples/`:

| Sample | Expected finding |
| --- | --- |
| `legitimate.eml` | Low-risk example |
| `sextortion_simulated.eml` | Sextortion and suspected spoofing indicators |
| `credential_phishing_simulated.eml` | Credential phishing indicators |
| `impersonation_simulated.eml` | Impersonation / payment fraud indicators |

You can also click a category bar or a day in the email chart to filter cases. Use the sender, IP, category, severity and status fields to narrow down results. Uploading the **exact same email** again reuses its existing investigation rather than creating a second case.

**Understanding results:** A high score means multiple detection indicators warrant attention; it is **not proof** that a device has been hacked. SPF, DKIM, DMARC and Microsoft compauth results are **read from the supplied headers**, which can be forged. Sentinel Desk does not independently verify them through a receiving mail server, perform live DNS/reputation checks, visit suspicious links or execute email attachments. Pasting **headers only** will not detect harmful wording found exclusively in an email body.

## Collect and import security logs

Open **Data Ingestion** to choose a collection method:

- **Import a file:** Select a FortiGate `.log`/`.txt` file or supported `.json`/`.jsonl` event file, then click **Import events**.
- **Syslog UDP:** Click **Start listener** and use **Send test event** to confirm that the listener receives local syslog traffic. The default address is `127.0.0.1:5514`.
- **Log folder watcher:** Click **Start watcher**, then append `.log` or `.jsonl` entries into the `log_inbox` folder. The watcher ingests newly completed lines.
- **Windows Security logs:** On Windows, click **Start Windows logs** to collect supported security events. Windows permissions may require running the command window as administrator.

Collection only continues while the application is running **and** the relevant collector is enabled. To receive syslog from another device, additional network configuration is needed; by default, the listener does **not** accept connections from other computers. Avoid enabling network collection on an untrusted network: UDP syslog is not encrypted or authenticated.

### Search indexing

New events and email investigations are added to local SQLite search indexes. Under **Data Ingestion → Search indexing**, check **Index state** and use **Rebuild index** if the index is out of sync. Rebuilding the index does not remove your records.

## Saving data and privacy

- Events, alerts and email investigations are stored locally in **`events.db`** in the project folder.
- Email investigations retain extracted headers and a body excerpt. Only analyse messages or logs you have permission to handle; avoid uploading confidential employer or customer information.
- To **back up** your records, stop the application and copy `events.db` somewhere safe.
- The **Clear all data** button under Data Ingestion clears **security events and their alerts**, not saved email investigations.
- To start with an **entirely fresh database**, stop the server, back up your data if needed, and delete `events.db` along with any existing `events.db-wal` and `events.db-shm` files. Reopening Sentinel Desk creates a new empty database. This permanently removes saved cases and events from that local installation.

Sentinel Desk is a local investigation and learning tool. It should not replace enterprise monitoring, endpoint protection or professional incident response.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| The page does not open | Confirm `start_windows.bat` is still running. Open `http://127.0.0.1:8765`, not a public URL. |
| `python` is not recognised | Install Python and enable **Add Python to PATH**, then reopen the terminal. |
| Port 8765 is already in use | Close the other Sentinel Desk instance, or run with a different `MONITOR_PORT` setting. |
| No events appear | Generate sample activity or start/import a log source. Check the selected time range and filters. |
| An older email is missing from results | Change the time range to **All time** or select **Original email date** for email investigations. |
| Windows logs show an error | Confirm you are using Windows and try launching the command window with appropriate Security log permissions. |
| The syslog listener shows no traffic | Click **Start listener** first, use **Send test event**, then check the displayed host and UDP port. |
| Re-imported email does not create a new case | Identical email content is deduplicated intentionally. Open its existing investigation. |

## Project files at a glance

- `app.py` — starts the local web server
- `static/` — dashboard interface
- `collectors.py` — live log collection
- `email_threat.py` and `email_rules.json` — email parsing, scoring and detection rules
- `samples/` — anonymised sample emails
- `tests/` — automated checks

To run the automated checks from a terminal in the `Sentinel_Desk` folder:

```bash
python -m unittest discover -s tests -v
```
