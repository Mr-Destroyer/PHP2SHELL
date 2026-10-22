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
