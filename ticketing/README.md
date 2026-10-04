# Ticketing

Every platform alert at or above a chosen severity becomes one alert in DFIR-IRIS, an open-source incident response and case management tool. Analysts work the queue in DFIR-IRIS and merge related alerts into cases.

Both parts run on your own analytics host. Nothing is hosted outside your network.

## What gets installed

| Part | What it is | Where it comes from |
| --- | --- | --- |
| DFIR-IRIS 2.4.29 | Web application, database, queue, worker and web server (5 containers) | Fetched from its own repository at install into `ticketing/iris-web/` (git-ignored). LGPL-3.0. |
| Forwarder | One small container that reads alerts from the platform and posts them to DFIR-IRIS | `ticketing/forwarder/` in this repository. MIT. |

## Install

On the analytics host, after the platform connection is set up (README steps 2 and 3):

```bash
scripts/install.sh ticketing --name tickets.example.internal --ip 10.20.30.50
scripts/verify.sh ticketing
```

`--name` is the name analysts type in the browser and `--ip` is this host's internal address; both go into the TLS certificate. The first start downloads the DFIR-IRIS images, so the host needs internet access once.

Sign in at `https://<name>:8443` as `administrator`. The password is the `IRIS_ADM_PASSWORD` value in `ticketing/iris-web/.env`. Change it after the first sign-in.

## How alerts become tickets

- The forwarder asks the platform every 30 seconds for events tagged as alerts (the same set the console's Alerts page shows) with `event.severity` at or above `TD_TICKET_MIN_SEVERITY`.
- **One alert, one ticket.** Repeats of the same rule each get their own ticket.
- Each ticket carries the rule name, engine (Suricata, Sigma or YARA), severity, the main fields (hosts, addresses, user, command line, file), the full event, and a link back to the event in the platform console.
- Only alerts raised after the forwarder first starts are ticketed, unless `TD_TICKET_BACKFILL_MINUTES` is set.
- The forwarder remembers what it has sent, so restarts and outages do not create duplicates or lose alerts. If DFIR-IRIS is down, alerts wait and are sent when it returns.

| Platform severity | `event.severity` | DFIR-IRIS severity | Ticketed by default |
| --- | --- | --- | --- |
| Low | 1 | Low | No |
| Medium | 2 | Medium | Yes |
| High | 3 | High | Yes |
| Critical | 4 | Critical | Yes |

Settings live in `config/techdetechtives.env` under "Ticketing". After changing them, re-run `scripts/install.sh ticketing`.

## Volume

One ticket per alert can mean a lot of tickets. A single noisy network rule can raise thousands of alerts a day. If the queue becomes unworkable:

- Tune or disable the noisy rule on the platform (Detections), which is the real fix.
- Raise `TD_TICKET_MIN_SEVERITY` to 3 so only high and critical alerts are ticketed.
- `TD_TICKET_MAX_PER_CYCLE` limits how fast tickets are created; it delays alerts, it does not drop them.

## Keeping it internal and secure

- DFIR-IRIS listens on port 8443 on this host. Keep the host on your internal network and do not publish or port-forward that port. Restrict it with the host firewall to the analyst network, for example `sudo ufw allow from 10.20.30.0/24 to any port 8443 proto tcp`.
- The setup script replaces the development TLS certificate that ships with DFIR-IRIS (its private key is public) with one generated on your host. Browsers warn until you trust `ticketing/certs/iris-cert.pem` or install a certificate from your own CA in `ticketing/iris-web/certificates/web_certificates/`.
- All passwords and keys are generated on your host and stored in `ticketing/iris-web/.env` and `config/techdetechtives.env`, both readable only by the installing user and both git-ignored. Back them up with the Docker volumes.
- **Least privilege:** the forwarder starts with the administrator's API key. Once DFIR-IRIS is running, create a dedicated user in DFIR-IRIS with only the "alerts write" permission, put that user's API key in `TD_IRIS_API_KEY`, and re-run the install command.
- The forwarder uses the platform's read-only key. It cannot change or acknowledge alerts on the platform.

## Operating it

```bash
docker logs -f td-forwarder                         # what the forwarder is doing
(cd ticketing/iris-web && docker compose logs app)  # DFIR-IRIS application log
scripts/install.sh ticketing-down                   # stop both (tickets are kept)
python3 -m unittest discover -s ticketing/tests -v  # forwarder tests, no Docker needed
```

To upgrade DFIR-IRIS, change its line in `upstream.lock` to the new version and commit, read the DFIR-IRIS upgrade notes, back up the volumes, and re-run the install command.

## Using a DFIR-IRIS you already run

Skip `setup-iris.sh`. Set `TD_IRIS_URL`, `TD_IRIS_API_KEY` and `TD_IRIS_CA_CERT` (a path under `ticketing/certs/`, written as `/iris-certs/<file>`) in `config/techdetechtives.env`, then run `docker compose -f ticketing/docker-compose.yml --env-file config/techdetechtives.env up -d --build`.
