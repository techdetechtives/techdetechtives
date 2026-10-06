# Anomaly detection: sixteen projects reviewed, and what was built

Reviewed 2026-10-06 by reading each repository's code at the commit named.
Nothing from them was run. The question for each: does it work in an isolated
network, and would it improve the OT IDS? Earlier reviews
(`AI-NIDS-REVIEW.md`, `PROJECT-REVIEWS.md`) had already set aside classifiers
trained on office-network datasets, so "trains a model on a public dataset"
was not enough to be interesting.

**Outcome.** No code was taken from any of them. Seven ideas were, and they are
built into one new program, `ot-ids/baseline/td_baseline.py`, described at the
end. Three more ideas are written down as the next candidates.

## The sixteen

| Project | Commit | Licence | What it is | Verdict |
| --- | --- | --- | --- | --- |
| [jertel/elastalert2](https://github.com/jertel/elastalert2) | `78ac39c` | Apache-2.0 | Alerting daemon for Elasticsearch and OpenSearch | **Ideas taken:** first seen, went quiet |
| [Stream-AD/MIDAS](https://github.com/Stream-AD/MIDAS) | `8193235` | Apache-2.0 | Anomaly scores on a stream of (source, destination, time) | **Idea taken:** a count against its own history |
| [online-ml/river](https://github.com/online-ml/river) | `086e802` | BSD-3 | Online machine learning library | **Idea taken:** do not learn from what was just flagged |
| [dmtkfs/ics-modbus-anomaly-detection](https://github.com/dmtkfs/ics-modbus-anomaly-detection) | `00e5ab7` | MIT | Course project scoring a Modbus dataset | **Ideas taken:** a function a master never used; a device that starts asking |
| [activecm/rita](https://github.com/activecm/rita) | `1317d70` | GPL-3.0 | Beaconing and long connections from Zeek logs | Not run. Beacon score is the next candidate |
| [Cyber04-08/modbus-ids-testbed](https://github.com/Cyber04-08/modbus-ids-testbed) | `1617157` | none | Student comparison of rules and a forest on a simulator | Not usable (no licence). One idea noted |
| [7mouz/OT-modbus-detection-lab](https://github.com/7mouz/OT-modbus-detection-lab) | `e2c8bc4` | none | A 42-line Zeek script for one simulated plant | Not usable (no licence). One idea noted |
| [AAH20/otforge](https://github.com/AAH20/otforge) | `776358a` | Apache-2.0 | Rule generator tested against its own synthetic traffic | Nothing |
| [mhebert-security/modbus-dnp3-traffic-analysis](https://github.com/mhebert-security/modbus-dnp3-traffic-analysis) | `b7e9701` | none | A plan and an essay; no code | Nothing |
| [HediBsf/Passive-Industrial-Network-Monitoring…](https://github.com/HediBsf/Passive-Industrial-Network-Monitoring-Modbus-TCP-Security-Analysis-Platform) | `fb1ce67` | none | Modbus simulator and pcap reader; no detection | Nothing |
| [austin-taylor/flare](https://github.com/austin-taylor/flare) | `0f7af61` | MIT | Beacon finder for Elasticsearch flows | Dead since 2021 |
| [stratosphereips/zeek_anomaly_detector](https://github.com/stratosphereips/zeek_anomaly_detector) | `23b93c4` | GPL-2.0 | Ranks the oddest rows of a Zeek log file | Nothing |
| [stratosphereips/StratosphereLinuxIPS](https://github.com/stratosphereips/StratosphereLinuxIPS) | `b5061a9` | GPL-2.0 | A whole behavioural IPS | Not run: a second Zeek, Redis, TensorFlow, daily feeds |
| [ymirsky/Kitsune-py](https://github.com/ymirsky/Kitsune-py) | `7c8ea51` | MIT | Autoencoder ensemble on packet statistics | Nothing |
| [yzhao062/pyod](https://github.com/yzhao062/pyod) | `3a71f47` | BSD-2 | Library of about 60 outlier detectors | Nothing to ship |
| [linkedin/luminol](https://github.com/linkedin/luminol) | `b0dc7df` | Apache-2.0 | Anomalies in one time series | Nothing |

## Why most of them do not fit

**The industrial ones are small and tied to one simulator.** Six projects
claim anomaly detection for industrial networks. Two contain no detection at
all. One (otforge) generates rules from an invented device profile and
"validates" them against traffic generated from the same profile, so its zero
false positives are true by construction; the rule files its emitter writes
match every TCP packet. Three have no licence, so nothing can be copied from
them however good. None has been near a plant.

**The general libraries answer a different question.** PyOD, River, Kitsune
and luminol score rows or series of numbers. An address, a port and a function
code are not numbers; turned into numbers they lose the one thing an operator
needs to hear: "this address never talked to that controller before". They
also bring NumPy, SciPy, a compiled Rust extension (River) or LLVM (PyOD),
which cannot be added to an appliance that is installed with no Internet
without rebuilding its images. The platform's own Random Cut Forest detectors
already do the series-of-numbers job.

**The behaviour tools are whole products.** RITA needs its own ClickHouse
database and a second copy of the connection data, checks GitHub and downloads
a threat feed by default, shows results in its own terminal screen, and, by
default, drops every connection between two internal addresses, which in an
isolated plant is all of them. Slips brings a second Zeek, Redis, TensorFlow
and about fifty feeds refreshed daily. Both are GPL.

## What was worth taking

| Idea | From | Where in that project |
| --- | --- | --- |
| Report a value the first time it is seen, against a list built over a learning window | ElastAlert 2, `new_term` rule | `elastalert/ruletypes.py`, class `NewTermsRule` |
| Report a key whose events stop | ElastAlert 2, `flatline` rule | `elastalert/ruletypes.py`, class `FlatlineRule` |
| Score a count against the same key's own long-run rate | MIDAS | `src/NormalCore.hpp` |
| Do not fold a flagged period into what is normal | MIDAS-F; River | `src/FilteringCore.hpp`; `river/anomaly/filter.py` |
| A function code this master never used | dmtkfs | `src/heuristics.py`, lines 195-196 |
| A device that both asks and answers | dmtkfs | `src/heuristics.py`, lines 208-221 |

Each was changed where the original would not survive a plant:

- **ElastAlert 2 keeps its lists in memory.** A restart rebuilds "first seen"
  from the last 30 days and forgets "went quiet" entirely, so a device already
  silent at restart is never noticed. Here the list is a file.
- **Its "went quiet" has no idea of the sensor.** When the mirror port fails,
  every key goes quiet at once. Here hours with no industrial traffic at all
  are not counted against any device, and are reported once as the sensor's
  problem.
- **MIDAS scores every record and uses approximate counters** (count-min
  sketches in 32-bit floats). On a steady poll the score swings between about
  1/n and n within each tick, an hourly job is flagged for ever, and a counter
  stops counting at 16.7 million, which a ten-per-second poll reaches in 19
  days. A plant has thousands of conversations, not billions: exact counts in a
  dictionary are smaller, right, and can be read by a person. Here there is one
  comparison per closed hour, against the most that was seen in any hour while
  learning.
- **dmtkfs measures its heuristics on the rows it took its baseline from**, so
  its published precision mostly measures whether an address is an attacker
  address. The two ideas stand without the measurement.

## What was built: `baseline/td_baseline.py`

One Python file, standard library only, about 1,000 lines. It runs every 15
minutes inside the product's own `dashboards-helper` container, reads the
industrial protocol records already in OpenSearch with one search, keeps an
exact list of who talks to whom with which operations on that container's
volume, and after learning reports:

| Finding | Meaning |
| --- | --- |
| new-master | An address acting as a master of a protocol for the first time: never seen before, or one that only answered until now |
| new-device | An address never seen before that answers an industrial protocol |
| new-service | A known device answering a protocol it never answered |
| new-pair | A known master talking to a device it never talked to |
| sweep | A master reaching more than five devices it never talked to |
| new-operation | An operation never used between a master and a device (a control operation is ranked higher) |
| burst | An operation used far more in an hour than in any hour while learning |
| quiet | A device or master heard in nine hours out of ten that has stopped for four hours |
| sensor-silent | No industrial traffic at all for four hours |

Findings are sentences ("10.0.0.99 was never seen before and is acting as a
master by modbus. It talked to: 10.0.1.10 (modbus). Operations:
WRITE_SINGLE_COIL."), are written to a file on the server, and, once an
operator switches alerts on, go to the product's alert webhook and appear
beside every other alert with their ATT&CK for ICS technique. How to use it is
in `ot-ids/README.md`.

It closes two gaps the ATT&CK coverage page lists as needing "the list of real
masters" (T0848 Rogue Master) and "no alert is defined" (T0864 Transient Cyber
Asset). It is not counted on that page while its alerts are off by default.

**An independent review of the first version found fifteen defects**, each
demonstrated against a copy. The ones that mattered: a search that timed out
was taken as "no traffic"; the product marks every record of a device with an
industrial vendor's network card as industrial, so time synchronisation and
web pages entered the list; IEC 104 records were turned round wrongly and
would have reported controllers as rogue masters; a record that arrived late
was never seen; a replaced HMI made every controller "stop answering"; one
record from an old test capture ended learning at once. All fifteen are fixed
and each has a test (`tests/test_baseline.py`, class `WhatTheReviewFound`).
The same review confirmed the search against OpenSearch 3.8's source and
documentation, and the webhook, container user, volume and crontab against the
product's source.

## Next candidates, not built

- **Beaconing.** RITA's score is four numbers per pair of addresses: how even
  the gaps between connections are, how even their sizes are, how much of the
  day they cover, and how flat their hourly counts are. It is about 150 lines
  of arithmetic and could be written afresh from that description (RITA's code
  is GPL and is not copied). It is not built because a master polling a
  controller is a perfect beacon: in a plant the score only means something for
  pairs that are not in the baseline, and those are reported already.
- **Writes to an address never written before.** From Cyber04-08 and 7mouz:
  learn which registers each master writes on each device, counting every
  address a block write covers, and report a write outside them. It needs the
  decoder's detailed Modbus log and a long learning period, because some
  setpoints are touched once a season.
- **Limits on a named setpoint.** From 7mouz: a value outside a range the site
  gives for one register. Only the site can supply the ranges, and the author's
  own notes show the price: an operator dragging a slider raised about twenty
  alerts.

Looked at and already covered: a read of more registers than the protocol
allows, and a Write Single Coil with an invalid value (otforge, Cyber04-08).
Suricata's own Modbus decoder raises "invalid value" for both, in its bundled
protocol-event rules (signature numbers 2250001 to 2250009).

## Limits of this review

Every clone was shallow, so how long each project has been maintained was
judged from its last commit and changelog only. Three reviewers read the code;
their reports were spot-checked against the clones (licences, RITA's
internal-address filter, ElastAlert 2's 30-day window, MIDAS's formula, the
dmtkfs lines cited) and not otherwise repeated.
