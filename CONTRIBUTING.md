# Contributing

This is a security-research repository. The bar for a change is that it makes a
claim **more verifiable**, not that it adds a feature.

## Ground rules

1. **No unverified claims.** If a change makes a tool say something about a
   target, the change must come with the evidence that the statement is true —
   a test, a lab log, or a packet capture summary. "Works on my box" is not
   evidence.
2. **Never merge behavioural and version evidence.** They are different
   confidence classes and stay labelled separately, in code and in output.
3. **Standard library only.** Both tools ship with zero runtime dependencies and
   that is a feature: the scanner runs on a jump host with nothing installed.
4. **No payload collection.** This repo is not a payload zoo. One path, the one
   the CVE describes.

## Layout

| Path | Owns |
|---|---|
| `scanner/php2shell/` | detection engine, transport, verdict rules, web UI |
| `scanner/tests/` | unit tests — the suite is the contract |
| `exploit-kit/php2shell_exploit/` | chain stages, leak logic, structures |
| `exploit-kit/FINDINGS.md` | lab evidence; update it when a stage changes state |
| `docs/` | methodology and reference prose |

## Before you open a PR

```bash
make test          # 78 tests, must be green
make lint          # tabs and trailing whitespace
make compile       # syntax check both packages
```

If you touched the chain, also run `./exploit-kit/exploit -u <lab> --diagnose`
against the docker lab described in [`docs/lab-setup.md`](docs/lab-setup.md) and
paste the stage table into the PR. If a stage changed status — either direction —
say so plainly in `FINDINGS.md`. A negative result is a result; the current stage 3
failure is documented precisely because it is useful to the next person.

## Commit style

Imperative subject under ~72 characters, body explaining *why* when the diff does
not. Prefix with the area when it is not obvious: `scanner:`, `exploit-kit:`,
`docs:`.

## Reporting a bug in the tools

Open an issue with: target SAPI and PHP version, the command line, the full
verdict block, and whether the target was behind a WAF or proxy. Redact hostnames.

For a bug in **PHP itself**, report it to the PHP security team, not here.

## Licence

Contributions are accepted under the MIT licence in [LICENSE](LICENSE).
