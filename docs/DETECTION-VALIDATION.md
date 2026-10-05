# Detection validation

Each TechDetechtives detection rule is paired with a small test that should make it fire. Running the test on a lab endpoint and seeing the alert arrive (and the ticket after it) is how you know the rule, the data collection and the ticketing all work.

The pairing is kept next to the rules in [`platform/detections/validation.yml`](../platform/detections/validation.yml). `scripts/verify.sh repo` fails if a Sigma rule has no entry.

## Where the tests come from

Most tests are from [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (Red Canary, MIT licence), a public library of small, self-contained tests mapped to MITRE ATT&CK techniques. TechDetechtives does not copy it: the file names each test by its permanent id at a pinned commit, and you install the runner on the lab endpoint yourself. Where no stock test fits a rule, the file gives a single harmless command instead.

## Current pairing

| Rule | Technique | Test | Expected |
| --- | --- | --- | --- |
| WMI Provider Host Spawning a Script Interpreter | T1047 | Atomic "WMI Execute Local Process", with the program set to `cscript.exe` | Alert |
| | | Atomic "Create a Process using WMI Query and an Encoded Command" (starts Notepad) | No alert: the rule only watches interpreters |
| PowerShell Encoded Command With Hidden Window | T1059.001 | One command: encoded `Write-Output` in a hidden window | Alert |
| | | Atomic "PowerShell Command Execution" (`powershell.exe -e ...`, visible window) | No alert: a known limit, see the file |
| PowerShell Script Decodes Base64 and Invokes the Result | T1059.001 | Atomic "PowerShell Fileless Script Execution" | Alert (needs Script Block Logging) |
| Download Piped Directly Into a Shell | T1059.004 | Atomic "Detecting pipe-to-shell" and "Command-Line Interface" | Alert (endpoint needs internet access) |
| Suricata 1900001, dynamic DNS query | | `nslookup td-test.duckdns.org` | Alert |
| Suricata 1900002, PowerShell user agent | | `Invoke-WebRequest http://example.com` over plain http | Alert |
| Industrial (OT) rules | | Commands against simulators, under `ot_network_checks` in the file | Alert |
| Flood rules | | `hping3` and `ping` aimed at a lab machine for a few seconds, under `flood_network_checks` | Alert; an ordinary `ping` must stay quiet |
| Layer 2 rules | T1557.002 and others | `arpspoof`, `macof`, `arp-scan` and a changed card address on an isolated lab segment | Alert, after `layer2 on` |
| YARA `TechDetechtives_Script_Base64_Decode_And_Invoke` | | None yet: needs a file carried over unencrypted traffic past the sensor | |

**None of these has been run on a live platform yet.** The expectations come from reading the rules and the test definitions. Each entry has a `confirmed` field for you to fill in.

## What you need

- A **lab endpoint you own** (a Windows VM for the first three rules, a Linux VM for the fourth) that is enrolled in the platform with Elastic Agent, so its process events arrive. Do not use the platform itself or the ticketing machine.
- For the Base64 rule: PowerShell Script Block Logging turned on for that endpoint.
- Optional: [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam/wiki) on the endpoint. Most entries also give a plain command that needs nothing installed.

Endpoint protection may block a test. Leave it on; "blocked" is a result worth recording.

## Running a check

1. On the platform, confirm the rules are on: `sudo platform/apply-overlay.sh rules`.
2. In the console's Hunt screen, confirm the endpoint is sending the data named in the entry's `needs` line.
3. On the lab endpoint, look at what the test does, then run it:

   ```powershell
   Invoke-AtomicTest T1047 -TestGuids b3bdfc91-b33e-4c6d-a5c8-d64bee0276b3 -ShowDetails
   Invoke-AtomicTest T1047 -TestGuids b3bdfc91-b33e-4c6d-a5c8-d64bee0276b3 -InputArgs @{ "process_to_execute" = "cscript.exe" }
   ```

   or the entry's `plain` command, here `wmic process call create cscript.exe`.
4. Wait a few minutes (Sigma rules run on a schedule), then search the console's Alerts screen for the rule title.
5. The alert is medium severity, so a DFIR-IRIS ticket should follow a minute or two later.
6. Clean up: the same `Invoke-AtomicTest` command with `-Cleanup`.
7. Write the date and platform version into the entry's `confirmed` field and commit it.

Run one test at a time, and only the tests in the file. Running a whole technique or the whole library starts many tests at once, including ones that dump credentials or download tools.

## Network, flood and layer 2 tests

These tests disturb a network on purpose: a flood slows it, ARP poisoning intercepts a machine's traffic, and a flood of made-up card addresses can make a switch misbehave. Run them **only on an isolated lab segment that you own** and that the sensor's mirror covers, for a few seconds or a minute at most, and never against a controller that runs a process or a network other people depend on.

1. Flood rules need nothing but the platform. Layer 2 rules need `sudo platform/apply-overlay.sh layer2 on` first, then ten minutes for Zeek to learn which network cards exist.
2. Run one command from the file's `flood_network_checks` or layer 2 entries from a lab machine.
3. Flood alerts arrive within a minute on the Alerts screen, with the rule name starting `TECHDETECHTIVES Flood`. Layer 2 alerts take a few minutes longer, because the Zeek notice is picked up by a Sigma rule that runs on a schedule; the notice itself is in Hunt at once: `event.dataset:zeek.notice AND notice.note:TechDetechtives*`.
4. If a flood figure is crossed by something ordinary on your network (a backup, a scanner), that is a finding too: note it in the entry and tune the rule (see [DETECTION-COVERAGE.md](DETECTION-COVERAGE.md#floods-and-denial-of-service)).

## If the alert does not arrive

Look for the event first (Hunt, same time window). No event means the endpoint is not sending that data. An event without an alert means the rule is off, has not synced yet, or does not match the fields as the platform stores them; fix the rule in `platform/detections/`, run `sudo scripts/install.sh platform`, and repeat the same test.

## Adding a rule

Add its entry to `validation.yml` in the same change. `scripts/fetch-upstream.sh atomic-red-team` downloads the test definitions at the pinned commit so you can find a fitting test and its id.

## Not built yet

A checker that runs after a test and reports pass or fail by asking the platform for the expected alert, and a coverage page showing which techniques have a confirmed rule. Both can read `validation.yml` as it is.
