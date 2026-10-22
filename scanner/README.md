# php2shell-scanner

Behavioural scanner for **php2shell** — CVE-2026-109618 and CVE-2026-109619.

Zero dependencies. Python 3.9+. Detects the vulnerability by *triggering* it, not
by trusting a version string.

```
$ ./scan -u https://example.com

  VULNERABLE  https://example.com
  confidence : HIGH
  version    : PHP 8.4.26 (unpatched, fixed in 8.4.27)
  signal     : in-band PHP fatal (memory exhausted in Unknown)
  sent       : 1,048,617 bytes
```

---

## Why behavioural detection

Most scanners released after disclosure check `X-Powered-By`. That is unreliable
in **both** directions:

- **False positives.** Debian, Ubuntu, RHEL and LTS vendors routinely backport
  security fixes *without* bumping the upstream version. A host reporting
  `PHP/8.2.29` may already be patched.
- **False negatives.** `expose_php = Off` is common hardening. No header, no
  detection — even on a fully vulnerable host.

So this scanner does what the vulnerability does: it sends a multipart body
engineered to exhaust `memory_limit` during request parsing, and observes how
the target fails. Version data is used only as a labelled fallback.

---

## How it works

### 1. Control request

A 42-byte multipart POST. Its only job is to establish a baseline: does this
target produce output for a normal multipart request?

If the control fails or returns 5xx, the scan stops as `INCONCLUSIVE`. Every
differential signal below depends on this baseline, so probing a target we
cannot baseline would produce noise.

### 2. Progressive probes

Bodies of **1 MiB → 8 MiB → 20 MiB**, escalating only when the previous probe
produced no signal. Each body contains:

- deeply nested array keys (`a[][a][a]...`, 62 levels)
- file parts with `filename=""` — these bypass `max_file_uploads` but still
  create all six `$_FILES` entries, and the nesting multiplies that work
- header-line filler, which costs far more memory in PHP's parser than on the wire

Escalation means a low-`memory_limit` target is caught with 1 MiB, and a host
that already answered is never sent 20 MiB.

### 3. Signal analysis

| Signal | Meaning | Confidence |
|---|---|---|
| **In-band PHP fatal** in `Unknown on line 0` | PHP died during request initialization, before any script ran | HIGH |
| **Differential empty 500** | Control produced output, probe produced nothing | HIGH |
| **Frontend 502/503/504** | Upstream PHP-FPM worker died mid-request | HIGH |
| **Empty 200** after control output | FPM swallowed the error | MEDIUM |
| **Version says unpatched** | No crash observed | MEDIUM |
| **Nothing** | No signal, no version | NONE |

`Unknown on line 0` is the discriminator. An OOM that names a real file and line
is an ordinary application error and is explicitly **not** reported.

### 4. Verdicts

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | Behavioural proof — a crash signal fired |
| `LIKELY VULNERABLE` | Version says unpatched, no crash observed |
| `FIXED` | Version says patched, no crash observed |
| `NO SIGNAL` | Nothing observed. **Not** proof of safety |
| `INCONCLUSIVE` | Target blocked or broke the scan |
| `ERROR` | Scan could not complete |

---

## The false positive this scanner avoids

A **patched** PHP can still exhaust memory on a large multipart body and return
an empty 500. The patch does not prevent OOM — it prevents OOM from leaving
exploitable state behind.

A naive scanner sees "empty 500 after big request" and reports vulnerable. That
is wrong on every patched host with a low `memory_limit`.

This scanner handles it by:

1. Treating the **in-band `Unknown on line 0` fatal** as the primary signal —
   that location only appears when PHP fails during request initialization.
2. Requiring the **control request to have produced output** before any
   differential signal counts.
3. Escalating probe size, so a patched host that OOMs at 1 MiB is not
   re-tested at 20 MiB.
4. Falling back to version data with **explicitly reduced confidence**, never
   silently upgrading it to `VULNERABLE`.

The test suite covers this case directly (`test_patched_oom_is_not_vulnerable`).

---

## Install

No dependencies. Either run in place:

```bash
./scan -u https://example.com
```

Or install the entry point:

```bash
pip install -e .
php2shell-scan -u https://example.com
```

---

## The browser UI

```bash
./scan --ui -u https://example.com
```

A local page opens on `127.0.0.1`. The scanner streams its real progress into a
target card, and when the verdict lands, a one-punch hero settles the argument:

| Verdict | What happens |
|---|---|
| `VULNERABLE` / `LIKELY` | The card shatters into fragments. |
| `FIXED` / `NO SIGNAL` | The fist stops short. *"Not punchable."* |
| `INCONCLUSIVE` / `ERROR` | He never reaches the target. |

The animation is driven by scanner events, not a timer, so the punch only
happens once a real result exists. Every pose change corresponds to something
the scanner actually observed: the card sweeps while probes are in flight, and
the impact fires on the verdict event.

Zero dependencies, no external assets. The page is plain HTML/CSS/JS with an
inline SVG rig; the audio is synthesized with WebAudio.

**It is local-only by design.** The server binds `127.0.0.1`, and each run
generates a fresh token that is required on every API route. A random web page
that guesses the port still cannot make the UI scan on your behalf. The server
stays up for repeat scans until you press `Ctrl-C`.

```bash
# fixed port, don't open a browser
./scan --ui --port 8765 --no-open

# UI with no target: type URLs in the page
./scan --ui
```

---

## Usage

```bash
# single target
./scan -u https://example.com

# list of targets, 20 threads, JSON out
./scan -l hosts.txt -t 20 -o results.json

# only vulnerable hosts, machine-readable
./scan -l hosts.txt -q

# custom headers (auth, cookies)
./scan -u https://example.com -H "Authorization: Bearer TOKEN"

# restrict verdict rules to one SAPI
./scan -u https://example.com --sapi fpm

# cap probe size (less intrusive)
./scan -u https://example.com --max-probe-mib 8

# verbose: show every probe
./scan -u https://example.com -v
```

### Options

| Flag | Description | Default |
|---|---|---|
| `-u, --url` | Target URL (repeatable) | — |
| `-l, --list` | File of targets, one per line | — |
| `-t, --threads` | Concurrent scans | 5 |
| `--timeout` | Per-request timeout (s) | 60 |
| `--connect-timeout` | Connect timeout (s) | 10 |
| `--max-probe-mib` | Largest probe | 20 |
| `--sapi` | `auto` / `mod_php` / `fpm` | auto |
| `-H, --header` | Extra header (repeatable) | — |
| `-k, --insecure` | Skip TLS verification | off |
| `-o, --output` | JSON output file | — |
| `--all-results` | Include non-vulnerable in JSON | off |
| `-v, --verbose` | Per-probe detail | off |
| `-q, --quiet` | Only vulnerable targets | off |
| `--yes` | Skip confirmation prompt | off |
| `--ui` | Launch the browser UI (interactive, stays up until Ctrl-C) | off |
| `--port` | UI port | free port |
| `--no-open` | Do not open a browser automatically | off |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No vulnerable targets found |
| 1 | At least one vulnerable target |
| 2 | Usage or I/O error |
