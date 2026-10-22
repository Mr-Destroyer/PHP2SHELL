# Detection methodology

The scanner's entire design follows from one rule: **the verdict must come from
behaviour the target cannot fake by accident, and version data must never be
promoted into behavioural evidence.**

## Why not read `X-Powered-By`

| Failure mode | Example |
|---|---|
| False positive | Debian ships `PHP/8.2.29` with the fix backported; the header still looks affected. |
| False negative | `expose_php = Off` — no header at all, on a fully vulnerable host. |
| Trivial to spoof | A WAF or a load balancer can rewrite or invent the header. |

A scanner built on the header is measuring configuration, not exposure.

## The signal

`php2shell` is reachable during **multipart request parsing**. The bug sits in the
early-session window opened when a file part is seen: `MULTIPART_EVENT_FILE_START`
runs `php_rinit_session(0)` before modules are activated. Exhausting memory inside
that window corrupts state in a way that survives the request.

The scanner therefore sends a body engineered to exhaust `memory_limit` while the
parser is still building `$_FILES`, and reads how the target fails. That is the
same code path the exploit walks, which is why a reproduced OOM is meaningful.

## Request sequence

### 1. Control request

A 42-byte multipart POST. Its only job is to establish a baseline: does this
target answer a normal multipart request at all?

If the control fails, or returns 5xx, the scan stops as `INCONCLUSIVE`. Every
differential signal depends on this baseline; probing a target we cannot baseline
would produce noise and, worse, a confident-looking negative.

### 2. Progressive probes

| Probe | Body size | Escalation rule |
|---|---|---|
| P1 | 1 MiB | sent always |
| P2 | 8 MiB | only if P1 produced no signal |
| P3 | 20 MiB | only if P2 produced no signal |

Each body contains three things:

- **Deeply nested array keys** — `a[][a][a]…` to 62 levels. The parser allocates
  per level, so a small wire size costs a large amount of heap.
- **File parts with `filename=""`** — these bypass `max_file_uploads` but still
  create all six `$_FILES` entries, and the nesting multiplies that work.
- **Header-line filler** — costs far more memory inside PHP's parser than it does
  on the wire, which keeps the body small enough to pass most proxies.

Escalation is not just politeness. A low `memory_limit` target is caught with
1 MiB, and a host that already answered is never sent 20 MiB.

## Verdict rules

| Verdict | Condition | Confidence |
|---|---|---|
| `VULNERABLE` | In-band PHP fatal naming memory exhaustion during parsing | `HIGH` |
| `VULNERABLE` | Worker dies / connection drops, reproducible across probes, control held | `MEDIUM` |
| `LIKELY VULNERABLE` | No behavioural signal, version in an affected range | `LOW` — labelled as fallback |
| `NOT VULNERABLE` | Control held, all probes clean | `HIGH` for the probes sent |
| `INCONCLUSIVE` | Control failed, or every probe blocked (`403`/`413`/timeout) | `NONE` |

`--sapi mod_php` and `--sapi fpm` narrow the rules to one server model, which
matters on hosts answering both on port 80 and on a FastCGI socket.

## What each probe isolates

| Probe feature | What it rules out |
|---|---|
| Control request | Target unreachable, or not parsing multipart at all |
| Nesting depth | Targets that cap body size but not parse complexity |
| Empty `filename=""` | `max_file_uploads` as the limiting factor |
| Filler headers | A conclusion that depends only on body byte count |
| Escalation | A `NO SIGNAL` caused by sending too little |

## Known blind spots

- A WAF or proxy that rejects the body with `413` before PHP parses it will
  produce `INCONCLUSIVE`, not `NOT VULNERABLE` — by design.
- `memory_limit = -1` hosts may never OOM, producing no signal even when
  vulnerable.
- Distro backports can carry the fix under an affected-looking version.
- Long-running workers may still serve old code after a package update; compare
  worker start time with package install time.
- php-fpm pools with `pm=static` and recycled children may mask the crash signal.
