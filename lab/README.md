# The demo lab: مؤسسة واحة الرمال للتجارة

This is the small, fictional company estate that Iris scans live during the demo: مؤسسة واحة الرمال للتجارة
("Wahat Alramal Trading Est."), at `wahat-alramal.test` and `www.wahat-alramal.test`. RFC 2606 reserves
`.test` and it never resolves on the internet, so nothing here can be mistaken for a real company or reach one.

The lab runs only on the project's own server, on a private Docker bridge (`demolab_lab`, 172.29.53.0/24) with
no published ports, so nothing outside that server can reach it. Only the private lab worker on the same host
scans it, and Iris reaches the worker over the team's tailnet.

| Container | Address | What it is |
|---|---|---|
| `lab-dns` (CoreDNS 1.11.3) | 172.29.53.53 | Authoritative for `wahat-alramal.test` only. Zone transfer refused, no forwarding (queries outside the zone are refused). Reloads the zone within 2 s of a new SOA serial. |
| `lab-web` (nginx + `labd.py`) | 172.29.53.10 | The site on 80/443 (`server_tokens off`; a lab CA and leaf, RSA-3072/SHA-256, generated inside the container at start), plus decoy listeners. |

## Estates and defects

`estates.py` (stdlib only) defines the estates and renders everything the lab applies: the zone file, the
nginx site, the home page and the decoy-port table. `estate("demo")` plants
`spf_missing, dmarc_none, mysql_3306, ipp_631, ssh_22, no_redirect`; `estate("seed-<n>")` plants a seeded
random 3 to 6 of the ten plantable defects.

| Defect | Planted as | Detectors the scanner raises (measured) | Fix |
|---|---|---|---|
| `spf_missing` | no SPF TXT at the apex | `spf_missing` | `publish_spf` |
| `dmarc_none` / `dmarc_missing` | `_dmarc` with `p=none` / absent | `dmarc_missing_or_none` | `set_dmarc_reject` |
| `mysql_3306` | MySQL 8.4 handshake, every login refused | `exposed_internal_port`, `exposed_database_port` | `close_db_port` |
| `redis_6379` | answers `-NOAUTH` to anything | `exposed_internal_port`, `exposed_database_port` | `close_cache_port` |
| `ipp_631` / `lpd_515` | minimal IPP (HTTP 200) / accept and close | `exposed_printer_service` | `close_printer_ports` |
| `ssh_22` | `SSH-2.0-OpenSSH` (no version) | `exposed_management_port` | none: reported to the owner |
| `ftp_21` | `220 FTP service ready` | `high_risk_port_open` | `close_ftp_port` |
| `no_redirect` | plain HTTP serves the site | `no_https_redirect` | `enable_https_redirect` |

Every estate also shows `BASELINE_DETECTORS`: `dkim_missing, dnssec_missing, mta_sts_missing,
no_ddos_protection, waf_absent` and the six missing hardening headers (`missing_hsts, missing_csp,
missing_x_frame_options, missing_x_content_type_options, missing_referrer_policy,
missing_permissions_policy`). Reads that stay open on every estate (no cookie set, a version-less
`Server` banner, and the weak-cipher probe) are reported as unread.

Optional payload slots (page `<title>`, an `X-Note` header, an extra apex TXT record, the IPP/LPD reply text)
are empty by default. They test that target-controlled text never reaches the model. No payload ever goes into
the `Server` header.

## Running it on the server

```sh
cd ~/demolab
./up.sh      # seeds ./state with the demo estate on a cold start, then builds and starts the lab
./down.sh    # stops and removes this compose project only (./state is kept)
```

The worker changes the lab by rewriting `./state` (zone, nginx site, page, ports, then `version.json` last);
`labd` applies it within a second and acknowledges in `applied-web.json`.
