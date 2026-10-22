<div align="center">

![php2shell — behavioural detection and exploit chain](assets/banner.svg)

# PHP2SHELL

**One vulnerability, two tools: a behavioural scanner that proves exposure, and an exploit-chain harness that documents exactly how far the chain gets.**

[![CI](https://github.com/Mr-Destroyer/PHP2SHELL/actions/workflows/ci.yml/badge.svg)](https://github.com/Mr-Destroyer/PHP2SHELL/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![Dependencies](https://img.shields.io/badge/runtime%20deps-none-brightgreen.svg)](#quickstart)
[![Tests](https://img.shields.io/badge/tests-78%20passing-brightgreen.svg)](scanner/tests)
[![Licence](https://img.shields.io/badge/licence-MIT-yellow.svg)](LICENSE)

</div>

---

## What this is

`php2shell` is an unauthenticated RCE class in PHP core reachable during multipart
request parsing, tracked as **CVE-2026-109618** (Apache `mod_php`) and
**CVE-2026-109619** (php-fpm). This repository holds the two halves of my work on it:

| Tool | What it answers | Entry point |
|---|---|---|
| **[`scanner/`](scanner/)** | *Is this host exposed?* — answers by triggering the OOM path, not by trusting a version string | `./scanner/scan -u https://host` |
| **[`exploit-kit/`](exploit-kit/)** | *How far does the chain actually get?* — stage-by-stage harness with lab evidence | `./exploit-kit/exploit -u https://host` |

Both are pure standard-library Python. Nothing to `pip install`, nothing to compile.

> **The exploit kit does not achieve RCE, and this repo does not claim it does.**
> Stages 0–2 are verified against a live lab; stage 3 delivers the forged
> structures but the carrier never reaches `PS(http_session_vars)`. The evidence,
> including the offsets and the sweeps that failed, is in
> [`exploit-kit/FINDINGS.md`](exploit-kit/FINDINGS.md).

---

## Quickstart

```bash
git clone https://github.com/Mr-Destroyer/PHP2SHELL.git
cd PHP2SHELL

# 1. Is a target exposed?
./scanner/scan -u https://target.example

# 2. Batch it, with JSON output for the report
./scanner/scan -l targets.txt -t 10 -o results.json

# 3. Against a host you own: how far does the chain go?
./exploit-kit/exploit -u http://127.0.0.1:8080 --diagnose
```

`./scanner/scan --ui` starts a local web console on a free port — the same engine,
with per-probe detail and a live result table.

### Scanner verdicts

```
$ ./scanner/scan -u https://example.com

  VULNERABLE  https://example.com
  confidence : HIGH
  version    : PHP 8.4.26 (unpatched, fixed in 8.4.27)
  signal     : in-band PHP fatal (memory exhausted in Unknown)
  sent       : 1,048,617 bytes
```

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | A probe reproduced the parser-path OOM. Confidence is `HIGH` when the signal is in-band. |
| `LIKELY VULNERABLE` | No behavioural signal, but the version string is in the affected range. Labelled as a fallback, never merged with the above. |
| `NOT VULNERABLE` | Baseline held and no probe produced a crash signal. |
| `INCONCLUSIVE` | The control request failed, so no differential claim can be made. |

---

## Why behavioural detection

Most scanners shipped after disclosure read `X-Powered-By`. That is wrong in both
directions:

- **False positives.** Debian, Ubuntu and RHEL backport security fixes without
  bumping the upstream version, so `PHP/8.2.29` may already be patched.
- **False negatives.** `expose_php = Off` is common hardening. No header, no
  detection — even on a fully vulnerable host.

So the scanner sends what the vulnerability actually is: a multipart body
engineered to exhaust `memory_limit` while the request is being parsed, and then
reads how the target fails. Version data is only ever used as a separately
labelled fallback. Details in
[`docs/detection-methodology.md`](docs/detection-methodology.md).

<details>
<summary><b>Why a crash is the signal (and why that is not the same as "exploitable")</b></summary>

The bug lives in the early-session window that opens during multipart parsing.
Exhausting memory there is the precondition for corruption — it is the same code
path the exploit chain walks. A reproduced OOM therefore proves the path is
reachable on that build.

It does **not** prove a working exploit exists for that build. Heap layout and
symbol offsets differ per image, which is exactly what stage 3 of the chain runs
into. Treat `VULNERABLE` as "the precondition holds", not as "you are owned".
</details>

<details>
<summary><b>What the scanner deliberately does not do</b></summary>

- No fuzzing of payload classes — it walks one path, the one the CVE describes.
- No version-only claims presented as findings.
- No automatic exploitation. The scanner never sends a forging body.
- No telemetry, no callbacks, no cloud lookups. It runs offline apart from the
  target itself.
</details>

---

## Verified results

Everything below was measured on `php:8.4.26-apache`, Apache 2.4.69 prefork,
`mod_php`, `memory_limit=8M`, single worker. Full log in
[`exploit-kit/FINDINGS.md`](exploit-kit/FINDINGS.md).

| Check | Result |
|---|---|
| Scanner verdict on the lab | **VULNERABLE / HIGH** |
| OOM reachable during request init | **YES** — `Allowed memory size ... in Unknown on line 0` |
| Worker survives the OOM | **YES** — 3 consecutive OOMs, then normal service |
| Stage 0 — worker rotation | **WORKS** — fresh child per attempt |
| Stage 1 — heap base leak | **WORKS** — 4096-byte read, 98 pointers, stable chunk base |
| Stage 2 — libphp base leak | **WORKS** — `pDestructor` → `zval_ptr_dtor` |
| Stage 3 — forge and execute | **FAILS** — carrier never reaches `PS(http_session_vars)` |
| Full RCE | **NOT REPRODUCED** |

Offsets were derived from the image with `nm`, not copied from the public PoC
(whose defaults belong to a different build):

```
zif_system    = 0x465370
zval_ptr_dtor = 0x65EB60
```

---

## Repository layout

```
PHP2SHELL/
├── scanner/                  # behavioural detector (php2shell-scanner)
│   ├── php2shell/            # cli, scanner, probe, transport, version, ui, web/
│   ├── tests/                # 78 unit tests, stdlib unittest only
│   └── scan                  # zero-install launcher
├── exploit-kit/              # stage-by-stage chain (php2shell-exploit)
│   ├── php2shell_exploit/    # exploit, leak, structures, diagnose, http, cli
│   ├── FINDINGS.md           # lab evidence, including the failures
│   └── exploit               # zero-install launcher
├── docs/                     # methodology, CLI reference, chain notes, lab setup
├── assets/banner.svg
└── .github/workflows/ci.yml  # test suite on 3.9 → 3.13
```

---

## Documentation

