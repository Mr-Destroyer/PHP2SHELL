# Architecture

Two independent Python packages in one repository. They share no code — on
purpose. The scanner must stay small enough to read in one sitting, and the
exploit kit must be free to be wrong in public.

```
scanner/php2shell/                exploit-kit/php2shell_exploit/
├── cli.py        argument parsing ├── cli.py        argument parsing
├── scanner.py    orchestration    ├── exploit.py    stage 0–3 driver
├── probe.py      body construction├── leak.py       stage 1–2 reads
├── transport.py  HTTP             ├── structures.py forged zend structures
├── version.py    classification   ├── diagnose.py   mechanism analysis
├── ui.py         web console      └── http.py       HTTP
└── web/          index/app/css
```

## Scanner data flow

```
cli.py
  └─ scanner.py ── per target, in a thread pool
       ├─ transport.py   control request ─────────────► baseline
       ├─ probe.py       build 1 / 8 / 20 MiB body
       ├─ transport.py   send probe, capture failure mode
       ├─ version.py     classify Server / X-Powered-By (fallback only)
       └─ verdict        behavioural first, version never promoted
            ├─ ui.py    render result table (CLI or web)
            └─ cli.py   JSON output, exit code
```

### Why the layers are separate

- **`transport.py` opens a fresh connection per probe.** A pooled connection
  would pin the scan to one worker and hide rotation, which is exactly the
  variable the exploit chain depends on.
- **`probe.py` is pure.** Given a size and a mode it returns bytes. That is what
  makes the probe bodies unit-testable without a network — 78 tests, no sockets.
- **`version.py` cannot influence a behavioural verdict.** It returns a
  classification object; the verdict builder reads it only when no signal was
  observed, and then labels the result `LIKELY VULNERABLE`.
- **`ui.py` renders, never decides.** It receives finished results.

## Exploit kit data flow

```
cli.py
  └─ exploit.py
       ├─ stage 0  rotate      http.py    abort the current worker
       ├─ stage 1  leak heap   leak.py    forge field + read through dangling PS(id)
       ├─ stage 2  leak code   leak.py    walk hash, pDestructor -> zval_ptr_dtor
       └─ stage 3  forge       structures.py, exploit.py
  └─ diagnose.py   same requests, mechanism reporting instead of execution
```

`structures.py` holds the forged `zend_string` / `zval` / hash layouts as explicit
offsets rather than `struct.pack` calls, so a reader can diff them against
`zend_types.h` line by line. That is the point: the file is documentation that
happens to be executable.

## Design constraints

| Constraint | Reason |
|---|---|
| Standard library only | The scanner runs on jump hosts with no package manager. |
| Python 3.9+ | Matches the oldest interpreter still common on assessment hosts. |
| No shared module between the two tools | A scanner must not import exploit code, or a false positive becomes a liability. |
| Web assets vendored, no CDN | The UI must work on an air-gapped assessment network. |
| Loopback-only UI | One operator, one host. Not a service. |

## Testing strategy

The suite targets the decisions, not the plumbing:

| Test file | Covers |
|---|---|
| `test_version.py` | Version ranges, backport-looking strings, missing headers |
| `test_probe.py` | Body construction, nesting depth, part counts, size bounds |
| `test_scanner.py` | Verdict rules, confidence, `INCONCLUSIVE` paths |
| `test_ui.py` | Result rendering, escaping, empty and mixed result sets |

Nothing in the suite makes a network call. A test that needs a target belongs in
the lab, not in CI — CI cannot distinguish "the tool is broken" from "the lab is
down".
