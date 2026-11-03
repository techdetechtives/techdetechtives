# Rule factory

When attackers start using a critical remote-code-execution flaw, the rule factory turns it into tested TechDetechtives detection rules, ready for an analyst to approve. On your own network, it also tells you whether you are exposed.

```
CISA KEV (exploited now) ──► is it code execution? ──► rules already written elsewhere?
                                                        ET Open · SigmaHQ · YARA Forge
                                                                   │
                         ┌─────────────────────────────────────────┘
                         ▼
        draft what is missing, from public information only
          Suricata  the exploit request (Nuclei template)
          Sigma     the product's server process starting a shell (products.yml)
          YARA      the script file the exploit uploads, when it uploads one
                         │
                         ▼
        test: Sigma logic on sample events · YARA on sample files ·
              Suricata replaying the exploit request and look-alikes
                         │
                         ▼
        pull request with the rules, their tests and a report  ──►  analyst approves  ──►  platform
```

On your network, separately:

```
CISA KEV ──► the vulnerability scanner's findings on the platform ──► DFIR-IRIS alert:
             (read-only key, never leaves your network)                CVE, hosts, rules in place
```

## The two halves

**On GitHub: drafting.** `.github/workflows/rulefactory.yml` runs every 6 hours. It needs only public data: CISA's Known Exploited Vulnerabilities list, NVD, public rule sets and exploit templates. For each new remote-code-execution CVE in KEV it:

1. Searches ET Open, SigmaHQ and YARA Forge. Security Onion already loads ET Open and imports SigmaHQ, so a hit there means the rule is coming or only needs switching on; the report says which.
2. Drafts what is missing. Each draft carries its own tests in `platform/detections/cases/<cve>.json`.
3. Runs the repository's rule tests, including a Suricata replay of the exploit request.
4. Opens a pull request with the rules and a report. It stays a draft pull request if a test failed.

A CVE whose ID already appears in a TechDetechtives rule is not drafted again; CVE-2024-4577, for example, is covered by the standing PHP rules.

**On your network: exposure.** `scripts/install.sh rulefactory` on the ticketing machine starts a small container that, every 6 hours, matches recently exploited RCE CVEs against the vulnerability scanner's findings on the platform. Each CVE found becomes one DFIR-IRIS alert naming the hosts, saying whether detection rules are in place, and linking to the pull request. It uses the forwarder's settings and keys; the only outside requests are for the public KEV and NVD feeds.

## Running it by hand

```bash
python3 -m rulefactory build CVE-2022-26134          # one CVE: search, draft, write, test, print the report
python3 -m rulefactory build CVE-2022-26134 --publish # and open the pull request
python3 -m rulefactory watch --list                  # what would be built from KEV now
python3 -m rulefactory exposure --dry-run            # on the ticketing machine: what the scanner finds
```

`build` writes into this checkout: the rule files under `platform/detections/`, the case file and `rulefactory/reports/<CVE>.md`. Review them with `git diff`. Drafting needs PyYAML; the Suricata replay needs Suricata, or Docker with `TD_SURICATA_IMAGE=jasonish/suricata:7.0.11`; the YARA check needs `yara`.

## What it will and will not do

- It drafts only from public information, so a rule is only as good as the public exploit. A Suricata rule from a Nuclei template matches that exploit's request; attackers who change the request may slip past it. The Sigma rule catches what follows the exploit (the server starting a shell), whatever the request looks like.
- The sensor reads plain HTTP only, or HTTPS that is decrypted before it reaches the sensor.
- YARA is drafted only when the exploit uploads a script file. Most RCE exploits do not, and the standing web shell rules cover what attackers drop next.
- Nothing goes live without a person merging the pull request.
- Rule IDs for drafted Suricata rules come from 1900501 to 1900899, the same ID for the same CVE every time.

## Teaching it more products

`products.yml` lists server software whose process can be watched for starting a shell: Confluence, Jira, Exchange, SharePoint, MOVEit, WebLogic, ActiveMQ, GeoServer, OFBiz, Jenkins and Zimbra so far. Add an entry with the words that pick it from KEV's vendor and product names, its server process, and a sample parent process for the test. PHP, Apache, nginx, IIS and Tomcat are covered by the standing `web_server_spawns_shell` rules.

## Settings

| Setting | Use |
| --- | --- |
| `TD_RF_GITHUB_TOKEN` or `GITHUB_TOKEN` | Push branches and open pull requests (`--publish`) |
| `TD_RF_REPO` | Repository for pull requests (default `techdetechtives/techdetechtives`) |
| `TD_RF_WATCH` | Comma-separated vendor or product words; only these are watched |
| `TD_RF_MAX_PER_RUN` | Most CVEs built in one run (default 3) |
| `TD_RF_NVD_API_KEY` | Optional NVD key, for a higher rate limit |
| `TD_RF_CACHE` | Download cache (default `~/.cache/td-rulefactory`) |
| `TD_SURICATA_IMAGE` | Suricata container for the replay test |
| `TD_ES_*`, `TD_IRIS_*` | Exposure check: the forwarder's settings in `config/techdetechtives.env` |

## Sources and licences

- CISA Known Exploited Vulnerabilities: US government work, public.
- NVD: public.
- ET Open (Proofpoint): searched, never copied.
- SigmaHQ (Detection Rule License 1.1) and YARA Forge (per-rule licences): searched and reported, never copied.
- Nuclei templates (ProjectDiscovery, MIT licence): the exploit request a draft is made from; credited in each drafted rule.
