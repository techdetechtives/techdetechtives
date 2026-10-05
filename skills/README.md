# Analyst skills

Guidance files that let an AI assistant (Claude Code, or any assistant that reads the [Agent Skills](https://agentskills.io) format) help with work on a TechDetechtives deployment: writing and validating detections, hunting, triage, and vulnerability prioritisation. A skill is a folder with a `SKILL.md`; the assistant loads one when a request matches its description.

Nothing here runs on the platform. The skills are documents for the assistant on the analyst's or administrator's own machine.

## What is here

| Folder | What | Licence |
| --- | --- | --- |
| `techdetechtives/` | 4 skills written for this platform: how it is laid out and its limits, writing and delivering rules, the hunting workbench, and validating rules with Atomic Red Team tests | MIT |
| `community/` | 26 skills selected from the community [cybersecurity skills library](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) by mukul975 and contributors, copied unchanged | Apache-2.0 (a `LICENSE` file is in each skill folder) |

The community library is an independent project. Despite its repository name it is not affiliated with Anthropic, and TechDetechtives is not affiliated with either.

## Install

On the machine where the assistant runs:

```bash
skills/install-skills.sh                 # into ~/.claude/skills (Claude Code, all projects)
skills/install-skills.sh --target .claude/skills      # this project only
skills/install-skills.sh --only-techdetechtives       # without the community skills
skills/install-skills.sh --list
skills/install-skills.sh --remove
```

`scripts/install.sh skills` does the same. Start a new assistant session afterwards. For another assistant, pass its skills folder to `--target`.

## How the community skills were chosen

The library holds more than 800 skills, including offensive ones (credential theft, command-and-control, phishing). TechDetechtives is a monitoring product, so only skills about detecting, hunting, triaging and prioritising were considered, and only for tools this platform uses: Sigma, YARA, Zeek data, Elastic, Sysmon, Greenbone. The list is in `selection.txt`.

Each selected skill's documents were read before being added, looking for text that tries to steer an assistant, instructions that send data to outside services, embedded secrets, and risky commands. None contained steering text or secrets. Skills were left out when they:

- install or reconfigure Suricata or Zeek by hand, or add outside rule sources (the platform manages its own sensors);
- push indicators or incident details to outside services, or page and ticket through other products, as part of their normal steps;
- set up scanning in ways that conflict with how this repository installs Greenbone;
- run Atomic Red Team tests unattended or across whole techniques (use `techdetechtives-detection-validation` instead);
- were mostly placeholder text.

Two things to know about what was kept:

- **Helper scripts are not included.** Upstream skills carry a `scripts/` folder of Python helpers. Those were not reviewed and are not copied, so a few references to `scripts/agent.py` or `scripts/process.py` in the documents point at files that are not here. Get them from the upstream repository if you want them, and read them first.
- **The community skills are generic and uneven.** They were written for hand-built stacks, and some contain commands or queries that are out of date or wrong. Some mention outside lookup services (VirusTotal, AbuseIPDB, ThreatFox and similar) and containment steps. The `techdetechtives-platform` skill tells the assistant how this platform differs and to ask before anything leaves the network or changes a system; install it alongside them. Treat what an assistant proposes from these skills as a draft to check.

## Keeping them current

`upstream.lock` pins the library commit. `MANIFEST.sha256` lists every copied file with its checksum, and `scripts/verify.sh repo` fails if a file differs from it, so a change to a community skill cannot slip in unnoticed. To update or add skills: change the commit or `selection.txt`, read what changed, run `skills/sync-skills.sh`, and commit.

To change how a community skill behaves on this platform, do not edit it; add the guidance to a skill under `techdetechtives/`.
