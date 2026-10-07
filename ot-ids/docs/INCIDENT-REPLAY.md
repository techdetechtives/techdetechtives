# Replaying an incident from captured packets

Written 2026-10-07 for version 0.14.0. What the product can do was established
by reading the source of Malcolm 26.09.0, Suricata 8.0 and Arkime 6.7.0; the
files are named with each statement. **None of it was run in the product
here**: there is no built ISO, Docker, Suricata, Zeek or OpenSearch where this
was written. What this kit adds was tested against stand-ins (see "Test status"
in the README). An independent reviewer checked every statement below against
the same sources and corrected several; "Limits and traps" holds what the
first version of this page did not know.

## The short answer

Yes: the appliance can replay an incident, and in the way that matters for an
intrusion detection system. It keeps the packets, it can show them again, and
it can put any capture file through every engine again, with the rules
installed today, and store the result at the times in the capture. What it
lacked was a way to read the outcome as one account of the incident, a way to
make an exported capture fit to replay, and one safeguard. Version 0.14.0 adds
the three:

- **`td-replay`** reads what the engines made of an uploaded capture, or of a
  period of live traffic, and prints the incident in order: the ATT&CK tactics
  as they first appeared, every detection, what the traffic holds that the
  plant's normal traffic never did, and the other traffic around it.
- **`td-pcap-order`** puts the packets of a capture file in time order. A
  capture exported from Arkime is not in time order, and replayed as it is can
  give a different result from the one the live sensor would have given.
- **The baseline no longer learns from uploaded captures.** Until now a capture
  uploaded for study, if its times were recent, was taken for the plant's own
  traffic: an attack capture could have taught the baseline that the attacker
  was normal, or raised "new master" alerts for a replay. That was a fault in
  this kit's baseline program (0.12.0 and 0.13.0).

Three things about the product decide whether a replay tells the truth. Each
is a step of the procedure below: the file must be in time order, it needs a
name the product has not seen, and Suricata must be restarted before a replay
that is to be compared with an earlier one.

It cannot play packets back onto a network wire, and should not; see "What was
not built".

## What the product does by itself

| Capability | How | Read in |
| --- | --- | --- |
| Keeps every packet | The sensor (or a server capturing by itself) writes full captures to disk where they are captured. **Nothing deletes old ones unless you say so.** Two settings in `./scripts/configure` do it, both off as shipped: "Arkime PCAP Management" (`MANAGE_PCAP_FILES`: Arkime deletes the oldest captures when free space falls below `ARKIME_FREESPACEG`, 10% by default, and knows which it deleted) and, on a system installed from the ISO, "Prune Oldest PCAP" (a service that deletes the oldest files when the disk is 90% full). Switch one on, or the disk fills. How far back you can replay is then the size of that disk divided by your traffic. | `config/arkime.env.example`, `docs/malcolm-config.md` (Managing disk usage), `scripts/installer/configs/configuration_items/storage.py`, `malcolm-iso/config/includes.chroot/etc/skel/.config/systemd/user/prune-pcap.service` |
| Shows the packets of a period again | Arkime, Sessions: pick the time range, filter (`ip == 10.0.1.10`), open a session to read its payload as text, hex or decoded. Hunt searches inside the packets of the sessions you filtered. | `docs/arkime.md` |
| Hands the packets out as a file | Arkime, Sessions, the arrow at the right of the search bar, PCAP Export: the sessions on screen become one capture file. Only sessions made from packets have packets; the rows that come from Zeek's logs do not. **The file is written session by session, in the order the sessions ended, not in time order.** | `docs/arkime.md` (PCAP Export); Arkime 6.7.0 `viewer/apiSessions.js` (`sessionsPcapList`: sorted by `lastPacket`) |
| Analyses a capture file again | Upload it at `https://<server>/upload/` (50 GB a file by default). Within about a minute it goes through Arkime, Zeek and Suricata, and the files Zeek carves go to the file scanner. pcapng files work in Zeek and only partly in Arkime. An SFTP server for the same purpose listens on port 8022 of the server itself only, unless "Expose SFTP" is chosen in `./scripts/configure`. | `docs/upload.md`, `shared/bin/pcap_processor.py`, `docker-compose.yml` |
| Ignores a file it has seen | **A file with the name and size of one it has processed before is skipped without a word.** | `shared/bin/pcap_watcher.py` (the check against Arkime's files index) |
| Stores the result where the incident was | The records carry the times in the capture, not the time of the upload. They are tagged with the words of the file's name and of the upload page's Tags box, and the node name of Zeek's, Suricata's and Arkime's records ends in `-upload`. File-scan hits get the tags but not that node name. | `shared/bin/pcap_utils.py` (`tags_from_filename`), `logstash/pipelines/enrichment/97_arkimize.conf`, `shared/bin/pcap_processor.py`, `logstash/pipelines/filescan/11_parse.conf` |

There is no `tcpreplay` or other tool to send packets in the product (searched
for in its whole source).

## Three ways to replay, and what each is for

1. **Look again.** Arkime on the stored packets. Nothing is analysed again; you
   read what was on the wire. For "what exactly did it send to the controller".
2. **Judge again by today's rules.** Export the incident's packets from Arkime,
   put them in time order, and upload the file. Suricata runs every rule now
   installed over it, so a rule added or corrected after the incident shows
   what it would have said. The three Modbus rules corrected in 0.13.0 are an
   example: an identification sweep recorded last month raised nothing then and
   raises them on replay.
3. **Analyse a capture from elsewhere.** Another site, a vendor's sample, a
   recording from a portable tap, a published attack capture for a drill.
   Upload it; it is analysed as if this sensor had seen it.

## Procedure

1. **Find the period.** From the alert that started the question, or
   `td-replay report --from 2026-10-01T02:00 --to 2026-10-01T09:00` (UTC, up to
   seven days, read in whole hours) for what the live record holds already.
2. **Export the packets.** Arkime, Sessions, the same period, a filter that
   takes in the addresses involved, the eye icon set to "Arkime Sessions",
   then PCAP Export. With separate sensors the packets are stored on the
   sensor; Arkime on the server fetches them from it, so the sensor must be
   reachable.
3. **Put the packets in time order.** On the server:

   ```bash
   td-pcap-order sessions.pcap incident7.pcap
   ```

   It says how many packets were out of order and writes a new file; it never
   changes the packets or writes over a file. The program is one Python file
   with no dependencies (`/usr/local/lib/techdetechtives/td_pcap_order.py`, in
   this repository under `hardening/rootfs`), so it can be copied to the
   machine the export was saved on; Wireshark's `reordercap` does the same. A
   capture that came straight from tcpdump or a tap is in order already
   (`td-pcap-order --check FILE` says).
4. **Give the file a name the product has not seen, with one word of your
   own**, such as `incident7.pcap`; for a second replay of the same packets,
   `incident7b.pcap`. The product silently skips a file whose name and size it
   has processed before. The word becomes the tag you find the replay by. The
   product splits the name at commas, dashes, dots, slashes and underscores,
   and drops parts that are only digits and the words pcap, cap, dmp, log,
   zeek, bro, suricata, tcpdump and netsniff: `INC-2026-031.pcap` is tagged
   only `INC`. Capitals count. Use the ending `.pcap`. The upload page's Tags
   box adds tags too, and they also change the stored name.
5. **If this replay is to be compared with an earlier one**, or the same
   addresses were replayed in the last day, restart the Suricata that analyses
   uploads first, so that it has forgotten the earlier one:

   ```bash
   cd ~/Malcolm && ./scripts/restart -s suricata
   ```

   (`suricata` is the one for capture files; the live one is `suricata-live`
   and is not touched.) Why is under "Limits and traps".
6. **Upload** at `https://<server>/upload/`. Wait a few minutes.
7. **Read the replay** on the server:

   ```bash
   td-replay list                          # uploaded captures, by tag, with when their traffic took place
   td-replay report --tag incident7
   td-replay report --tag incident7 --format markdown > incident7.md
   td-profile --tag incident7              # the whole traffic profile of the capture
   ```

8. **Go back to the packets** where the report points: Arkime, expression
   `tags == incident7`; in the dashboards, filter `tags:incident7` and set the
   time picker to the capture's period, not to today.

What `td-replay report` prints, on a made-up intrusion:

```
Incident replay, 2026-08-31 14:00 UTC to 2026-08-31 16:00 UTC
Records: live traffic and uploaded captures, tagged incident7. Times are UTC.
49 records: modbus 33, weird 7, alert 5, conn 2, intel 1, notice 1.

The course of events
  14:30:00  Discovery (T0888), from 10.66.6.6
  14:45:00  Impair Process Control, from 10.66.6.6
  14:50:00  Inhibit Response Function (T0814), from 10.66.6.6

Detections in order (6 kinds of event between pairs of addresses)
  14:24:10  indicator match: 203.0.113.50 (on the list: abuse-ch-ipblocklist)  (10.66.6.6 -> 203.0.113.50; once)
  14:30:00  rule alert: TECHDETECHTIVES OT Modbus - Read Device Identification ...  (10.66.6.6 -> 10.0.1.10; severity 51, 2 times, last 14:30:01)  [T0888 Remote System Information Discovery]
  14:45:00  rule alert: TECHDETECHTIVES OT Correlation - Address identified controllers, then wrote to one by Modbus  (10.66.6.6 -> 10.0.1.10; severity 71, once)  [T0888, T1692]
  14:50:00  rule alert: TECHDETECHTIVES OT Modbus - Force Listen Only Mode (device stops answering)  (10.66.6.6 -> 10.0.1.10; severity 91, once)  [T0814 Denial of Service]

Against the baseline: what this traffic holds that the plant's normal traffic never did
  14:30:00  10.66.6.6 is not in the baseline's list at all. It acted as a master by modbus. Operations never used there before: DIAGNOSTICS on 10.0.1.10 (modbus), once; READ_DEVICE_IDENTIFICATION on 10.0.1.10 (modbus), 2 times; WRITE_SINGLE_COIL on 10.0.1.10 (modbus), 5 times.

Other traffic in the period
  Other protocols reaching controllers:
      10.66.6.6 -> 10.0.1.10 (device)  3389/tcp rdp  9.0 MB, 1 connections
  Addresses outside the private ranges:
      10.66.6.6 -> 203.0.113.50  443/tcp tls  57.3 MB, 1 connections
```

The comparison with the baseline is the part no rule gives you: it works for an
attack no rule was written for, because it only asks what this plant had never
done before. It reads the baseline's list and changes nothing in it.

The techniques shown are the ones the product keeps: for a rule alert that is
the parent technique (T1692, not T1692.001; the sub-technique is in the rule's
own metadata), and tactics from Zeek's notices and from file-scan hits, which
use the enterprise ATT&CK names, appear beside the ICS ones.

## What each part of this kit does with a replayed capture

| Part | On a replayed capture |
| --- | --- |
| Suricata rules: this kit's, the imported sets, the bundled set, Suricata's own protocol event rules | All run. The Suricata that analyses uploads uses the same rule folder, the same stream-depth setting and the same image as the live one (`docker-compose.yml`, services `suricata` and `suricata-live`). Rates and time windows are counted in the capture's own time. **A rule that limits its own alerts to so many per address in a time (60 of the 97 rules this kit writes do) remembers that from one file to the next**, see "Limits and traps". |
| Correlation chains (address identifies controllers, then changes one) | Work **inside one file, if it is in time order**. Suricata clears its flows and the flags it keeps per address between capture files (`PostRunDeinit` in Suricata's `src/suricata.c`: `FlowShutdown`, `HostCleanup`), so a chain whose two halves are in two files is not seen. Export the incident as one file and order it. |
| ATT&CK technique in each alert | Carried, as for live alerts. `td-replay` puts the tactics in order of first appearance. |
| Zeek: industrial decoders, ACID notices, threat indicators, the layer 2 watch | All run: the Zeek that analyses uploads loads the same local policy, indicator folder and custom scripts (`zeek/config/local.zeek`, `docker-compose.yml`). The layer 2 watch needs the capture to hold the ARP traffic, which an Arkime export of chosen sessions may not. |
| YARA rules on files in the traffic | **Only if file extraction is switched on.** The product's default is `none` (`ZEEK_EXTRACTOR_MODE` in `config/zeek.env.example`; "File Extraction Mode" in `scripts/installer/configs/configuration_items/file_carve.py`), and with it no file is carved and no YARA rule ever runs, live or replayed: not this kit's, not Elastic's. Choose a File Extraction Mode in `./scripts/configure`; `interesting` takes the file types that are worth scanning. A capture replayed after the mode is switched on has its files scanned, whatever the mode was when the traffic was first seen. A hit carries the capture's tags, so `td-replay report --tag` lists it; the product does not mark it as uploaded, so `--uploads only` cannot. |
| Baseline (`td-baseline`) | Leaves uploaded captures out, since 0.14.0: it neither learns from them nor reports on them. `td-replay` compares a capture with its list without changing it. `TD_BASELINE_INCLUDE_UPLOADS=true` restores the old behaviour. **That setting is needed on a system whose Zeek analyses rotated capture files instead of the capture interface** (not the default): the product marks all of such a system's records the way it marks an upload, and the baseline would read nothing. `td-baseline check` says so when it sees it. |
| Traffic profile (`td-profile`) | Leaves uploaded captures out unless asked: `--tag WORD`, `--uploads include` or `--uploads only`. `--from` and `--to` give a period in the past. |
| Alert monitors and anomaly detectors | Look back from now: 15 minutes for most, 24 hours for the tactic-chain monitor. A capture whose times lie further back does not set them off; one recorded within the last day can, because the monitors do not tell uploaded records from live ones. |

## Limits and traps

- **Suricata remembers its alert limits between replays.** In Suricata 8 the
  counters behind a rule's `threshold` option are kept for as long as the engine
  runs, per rule number, revision and address (`src/detect-engine-threshold.c`;
  nothing in `PostRunDeinit` clears them), and the product keeps one Suricata
  running for all uploads (`suricata/scripts/suricata_socket.py`). A rule that
  allows one alert per address in an hour or a day therefore stays silent on a
  second replay of the same traffic, or of an earlier capture with the same
  addresses, until a packet later than its window arrives. Without the restart
  in step 5, "the new rule did not fire" can be untrue. A rule whose revision
  number changed starts afresh.
- **The same file uploaded twice is analysed once.** Rename it (step 4).
- **An Arkime export is not in time order** (step 3). Replayed as it is, an
  event on a long connection can reach the engine after a later event on a
  short one: a correlation rule may not fire and a rate may be miscounted.
  What Zeek makes of a file whose time runs backwards was not established.
- **Uploading what the sensor already saw doubles it.** The live records and
  the replayed ones are both there, at the same times. Counts in the
  dashboards double for that period unless you filter by tag, or by
  `node:*-upload` or its opposite. `td-replay` with `--from` and `--to` and
  `td-profile` leave uploads out by default for this reason.
- **File-scan hits are not marked as uploaded.** In a report on a period of
  live traffic, a hit from a capture uploaded with times in that period is
  listed among the live ones, with the capture's tags shown beside it.
- **A replay cannot be taken back with a button.** Arkime's own "Remove Data"
  is switched off for the product's user (`arkime/etc/user_settings.json`),
  and the product has no other function to remove the records of one upload;
  they stay until the index they are in is pruned. Use a tag you will
  recognise.
- **`td-replay list` shows tags, not files.** Tags the product is known to add
  by itself and tags found only on rule alerts (rules can carry tags of their
  own) are left out; `list --all` shows them. A word you chose that happens to
  be one of those is still found by `report --tag`.
- **`td-replay` reads at most seven days in one report**, in whole hours, and
  lists the first 40 detections unless `--top` says more; `--format json` has
  all of them.
- **The comparison with the baseline is as good as the baseline.** While it is
  still learning, more looks new than is, and the report says so. A capture
  from another plant will be new in every line.
- **What the engines do not decode, the replay does not show.** The same
  limits as live: the rules cover the protocols and operations listed in the
  README, and a quiet replay is not proof that nothing happened.
- **Zeek's "weird" records are counted, not listed.** A capture cut out of a
  longer one has many half-seen connections.
- **Not run in the product.** That uploaded records carry the tags and the
  `-upload` node name, the names of the fields the report reads
  (`event.kind`, `rule.name`, `event.severity`, `threat.*`), what Suricata
  keeps and clears between files, the order of Arkime's export and the
  skipping of a repeated file were read in source code. The first replay on an
  installed system will show whether each holds: `td-replay list` printing the
  capture you uploaded is the first check; replaying one file under two names,
  with and without the restart, is the second.

## What was not built, and why

- **Playing packets onto a wire (tcpreplay).** Replaying a capture onto a plant
  network sends its commands to the real controllers again: the stop command in
  the capture stops the controller a second time. A sensor on a mirror port has
  no need of it, since uploading the file gives the engines the same packets.
  The one honest use is a lab: a second machine playing a capture into a spare
  sensor's capture port, to exercise the live path (the baseline, the monitors)
  for training. That needs no change to the appliance, and it must never be
  connected to the plant.
- **Removing a replay's records.** Possible in OpenSearch (delete by query on
  the tag), not offered: it is the one step here that destroys data, and it
  could not be tried.
- **Restarting Suricata from `td-replay`.** The report only reads; a command
  that restarts a part of the product belongs in the operator's hands.
- **Comparing two replays of one capture**, before and after a rule update, to
  list what the update changed. The next candidate: both replays are in the
  index under different tags, so it is a matter of reading two reports side by
  side, with the restart of step 5 between them.
- **A chain across two capture files.** Suricata's reset between files is its
  own behaviour; merge the files before uploading (`mergecap`, on another
  machine), then order the result.
