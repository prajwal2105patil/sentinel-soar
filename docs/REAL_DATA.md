# Running Sentinel-SOAR on real public data

The repo ships with **synthetic** data (`data/sample_auth.log`, `data/cloudtrail.jsonl`)
so it runs offline and the labeled scoreboard is reproducible. But the pipeline is not
tied to that data — the sshd parser reads real logs unchanged. Use this to answer the
fair question *"does it work on messy real-world data?"*

## The dataset

**loghub — OpenSSH_2k.log** · https://github.com/logpai/loghub
A widely-cited research corpus of real system logs. `OpenSSH_2k.log` is 2,000 lines of
genuine `sshd` auth activity from a lab host, including real internet brute-force
traffic (invalid-user sprays, repeated root failures, occasional accepted logins).
No login credentials or PII — just standard syslog auth lines.

## Run it

```bash
python scripts/fetch_public_sample.py                              # downloads to data/public/ (needs network)
python -m core.ingest --log data/public/OpenSSH_2k.log --no-cloud  # ingest REAL logs
python -m cli.hunt top-talkers                                     # real attacker IPs surface here
python -m cli.hunt spray --min-users 5                             # real password-spray sources
python -m core.detect                                              # run the YAML rules over real data
```

## What to expect

- `top-talkers` / `spray` surface the real brute-force sources in the capture.
- `core.detect` fires the `brute_force` rule on the real high-volume sources.
- The **scoreboard gate** (`eval/detection_quality.py`) still reports on the *synthetic*
  labeled set — there are no ground-truth labels for the public capture, so precision/
  recall are not claimed on it. That separation is deliberate and honest: real data
  proves the plumbing handles messy input; the synthetic set is where metrics are earned.

## Why the parser "just works"

loghub OpenSSH lines are ordinary `sshd` syslog:

```
Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2
Dec 10 07:02:47 LabSZ sshd[24203]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2
```

`core/ingest.py` already parses exactly this shape (`tests/test_ingest.py` locks it in).
Non-auth lines (`Connection closed`, `reverse mapping`, …) ingest as `other` rather than
crashing.
