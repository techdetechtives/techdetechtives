# Rule test cases

One JSON file per rule set or CVE. `platform/tests/` reads every file here, so a rule and its proof travel together.

```json
{
  "about": "what these cases test",
  "covers": [1900401, 1900402],
  "suricata": [
    {"name": "...", "request": {"method": "POST", "uri": "/x?y", "headers": {}, "body": "..."}, "alerts": [1900401]},
    {"name": "Look-alike: ...", "request": {"method": "GET", "uri": "/"}, "alerts": []}
  ],
  "sigma": {"techdetechtives_x.yml": {"match": [{"Image": "..."}], "nomatch": [{"Image": "..."}]}},
  "yara": {"TechDetechtives_X": {"match": ["file text", {"base64": "..."}], "nomatch": ["..."]}},
  "validation": [{"rule": "sigma/techdetechtives_x.yml", "title": "...", "tests": [{"kind": "manual", "expect": "alert", "...": "..."}]}]
}
```

- **suricata:** each request is written into a packet capture and replayed through Suricata (`test_suricata_engine.py`). It must raise exactly the SIDs in `alerts` out of the file's `covers` list. Every rule in `techdetechtives-web.rules` and every `techdetechtives-cve-*.rules` file needs a request that raises it.
- **sigma:** events evaluated by the Sigma logic in `test_detection_rules.py`.
- **yara:** sample files, as text or Base64; scanned when `yara` is installed.
- **validation:** the live test pairing for a Sigma rule, the same as an entry in `validation.yml` (`scripts/verify.sh repo` reads both).

`web.json` is written by hand. `cve-*.json` files come from the rule factory (`rulefactory/`) and can be edited like any other.
