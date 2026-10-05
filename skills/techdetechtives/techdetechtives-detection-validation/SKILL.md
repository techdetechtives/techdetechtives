---
name: techdetechtives-detection-validation
description: How to prove a TechDetechtives detection rule fires, using the test mapped to it in platform/detections/validation.yml - an Atomic Red Team test or a single harmless command - run on a lab endpoint, then checking for the alert and the ticket. Use when validating a new or changed rule, when asked whether the detections work, when planning an Atomic Red Team or purple-team exercise against this platform, or when recording detection coverage and gaps.
license: MIT
---

# Validating TechDetechtives detections

A rule that has never fired is a guess. Each rule in the repository is paired
with a small test that should trigger it, and validation means running that
test on a lab endpoint and watching the alert arrive. The pairing lives in
`platform/detections/validation.yml`; read it first.

## Where tests may run

Tests imitate attacker behaviour, so where they run is the operator's
decision, not yours.

- Only on a lab endpoint the operator owns, has named for this purpose, and
  that already reports to the platform. Never on the platform, the second
  host, or any machine that was not named.
- Only the tests listed in `validation.yml`, unless the operator asks for
  another by name. Never run a whole technique or the whole library
  (`Invoke-AtomicTest All` and technique-wide runs start many tests,
  including ones that dump credentials or download tools).
- Show the operator what a test will do before it runs
  (`Invoke-AtomicTest <technique> -TestGuids <id> -ShowDetails`, or the
  `plain` command from the file) and let them run it or say yes to each one.
- Do not switch off or add exclusions to endpoint protection to make a test
  pass. If protection blocks the test, record that: a block is a result.

## Procedure

1. **Check the data first.** Each entry has a `needs` line. Confirm in Hunt
   that the endpoint is sending that data (for example a recent
   `event.category: process` event from that host). Without it the test
   proves nothing.
2. **Check the rule is on:** `sudo platform/apply-overlay.sh rules` on the
   platform.
3. **Note the time, then run one test** on the lab endpoint. Entries of kind
   `atomic` give an `Invoke-AtomicTest` command, and most also give a `plain`
   command that does the same thing without installing anything. Entries of
   kind `manual` have only the `plain` command. Install Invoke-AtomicRedTeam
   from the project's own instructions
   (https://github.com/redcanaryco/invoke-atomicredteam/wiki) if you use it.
4. **Wait, then look.** Sigma rules are evaluated on a schedule, so allow a
   few minutes. In the console's Alerts screen, search for the rule title
   from the entry. An entry with `expect: alert` passes when the alert
   appears; one with `expect: none` passes when it does not.
5. **Follow it through.** An alert at medium or above should appear in
   DFIR-IRIS a minute or two after the alert.
6. **Clean up:** run the same `Invoke-AtomicTest` command with `-Cleanup`, or
   remove what the entry's note says the test leaves behind.
7. **Record the result.** In `validation.yml`, set `confirmed` to the date
   and platform version (`"2026-10-12 on 2.4.211"`), or describe what
   happened instead. Commit it. `confirmed: "no"` means nobody has seen it
   work yet.

## When a test does not behave as expected

Work from the data forward: did the event arrive (Hunt, same time window)?
Does the event have the fields the rule uses, with the values the test
produced? Is the rule enabled and has a rule sync run since it was added? A
missing event is a collection problem; a present event with no alert is a
rule or field-mapping problem. Fix the rule in the repository (see
`techdetechtives-detections`), redeliver, and run the same test again.

## Adding a rule

Add an entry to `validation.yml` in the same change as the rule. Prefer an
existing Atomic Red Team test, identified by its permanent `guid` (test
numbers change), from the commit pinned at the top of the file;
`scripts/fetch-upstream.sh atomic-red-team` fetches the definitions to read.
Where no test fits, write the smallest harmless command that produces the
behaviour and mark it `manual`. Add an `expect: none` entry when there is a
near miss worth knowing about, so the limit is written down rather than
discovered during an incident.
