# Review: AI-Based-Network-IDS

Reviewed 2026-10-06: https://github.com/akankshavm22/AI-Based-Network-IDS at
commit `69247e7` (three commits, January 2026, MIT licence). The questions were
whether it works in an isolated network and whether it would improve the
TechDetechtives OT IDS.

**Short answer: it runs offline apart from one feature, but it would not
improve this product, and it is not adopted. Two of its ideas are worth
having, and the OT IDS has both in a form that works offline.**

## What it is

A student project: one 212-line Streamlit page (`app.py`), a saved model, and a
README.

1. You upload a CSV from the public CIC-IDS dataset.
2. It trains a random forest (scikit-learn, 200 trees) on eight flow statistics
   from that CSV, such as flow duration, packet counts and packet timing.
3. "Capture Live Packet" picks a random row **from the uploaded CSV's test
   split** and shows the model's label for it. Nothing is captured from a
   network.
4. "Explain Attack" sends the row and the label to Groq's hosted LLaMA model
   over the Internet and prints the reply.

## Does it work offline?

| Part | Offline? |
| --- | --- |
| Training and prediction | Yes, once Python with `streamlit`, `pandas`, `numpy`, `scikit-learn` and `matplotlib` is installed from an offline package mirror. (`matplotlib` is imported but missing from its `requirements.txt`.) |
| "Explain Attack" | **No.** It calls Groq's cloud service and needs an Internet connection and an API key. Network details would leave the site. |
| Live traffic | Not applicable. It has no capture, no PCAP reader and no connection to Zeek or Suricata. |

## Why it would not improve the OT IDS

- **It does not look at traffic.** It classifies rows of a spreadsheet. Using it
  on a plant network would mean writing the capture, the flow-statistics
  extraction and the alert output, which is everything except the 20 lines that
  train the model.
- **Its inputs are not what the sensors produce.** The eight features are
  CICFlowMeter statistics. Zeek's connection records have some of them
  (duration, packet counts) but not the packet-timing ones.
- **It is trained on office-network attacks from 2017.** CIC-IDS contains port
  scans, web attacks, brute force and denial of service against ordinary IT
  hosts. It contains no Modbus, S7, DNP3 or any other industrial traffic. A
  model trained on it has never seen what normal looks like on a control
  network, and models trained on one network's labelled data are known to
  transfer poorly to another.
- **It needs labelled attacks to learn from.** A plant has none.
- **The shipped model file should not be loaded.** `nids_model.pkl` is a Python
  pickle: loading one runs whatever code its author put in it. Inspected without
  loading, it holds a scikit-learn 1.6.1 random forest and nothing unexpected,
  but the app itself never loads it (it only overwrites it), so there is no
  reason to.

## What is worth having, and where the OT IDS has it

| Idea | In the OT IDS |
| --- | --- |
| Learn what is normal and flag departures from it | The platform's anomaly detection (Random Cut Forest) learns from **this plant's own traffic**, with no attack samples. Three detectors for industrial traffic are added: activity per protocol, operations per protocol, and how many devices each machine talks to. See "Anomaly detectors and correlation monitors" in the README. |
| Explain an alert in plain words | Every TechDetechtives rule says in its message what happened and why it matters ("Address identified controllers, then sent S7 PLC STOP"). No model and no Internet are involved, so the wording is the same every time and nothing leaves the site. |

## If machine learning is wanted later

A version that would help looks different from this project:

- trained on site, on the sensor's own Zeek records, without labels;
- scoring industrial fields (function codes, register ranges, who writes to
  whom), not only flow sizes;
- writing its findings back as events, so they appear beside rule alerts and
  can be correlated with them;
- if a language model is wanted for summaries, one that runs on the server
  itself. That needs a GPU or a lot of memory, and its output must be treated
  as a draft, not as a finding.

That is a project of its own. The anomaly detectors above are the part of it
that is available today.
