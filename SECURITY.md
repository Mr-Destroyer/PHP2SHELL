# Security policy

## Scope of this policy

This policy covers vulnerabilities **in the tools in this repository** — the
scanner and the exploit kit. It does not cover `php2shell` itself; that is PHP's
security process (`security@php.net`), and the advisories are linked in the
README.

## What counts as a vulnerability here

- The scanner reports `VULNERABLE` on a host that is not exposed (false positive).
- The scanner reports `NOT VULNERABLE` on a host that is exposed (false negative),
  unless caused by a documented limitation such as a WAF or `memory_limit=-1`.
- The scanner crashes, hangs, or corrupts output on a well-formed target.
- The exploit kit sends traffic outside the target it was pointed at.
- The local `--ui` console is reachable from another host, or serves a
  directory-traversal path.
- A secret, credential or private target list is committed to this repository.

## Reporting

Email **security@zim.dev** with:

1. Affected tool and version (`./scan --version`).
2. A minimal reproduction: command line, target class, observed vs expected.
3. Impact — what an operator would wrongly conclude because of the bug.

Expect an acknowledgement within 72 hours. Please do not open a public issue
before a fix ships; use GitHub's private vulnerability reporting if you prefer.

## Threat model of the local UI

`--ui` binds to `127.0.0.1` only, and every API route requires the per-run
`?token=` that the terminal prints (compared with `secrets.compare_digest`). Static
assets are served from a fixed manifest, not from a path join, so there is no
traversal surface.

It is a convenience console for one operator on one host, not a service. Do not
expose the port. A report that "the UI has no login" is not a vulnerability — it
has a token, and no user accounts by design. "The UI binds to `0.0.0.0`" would be
a vulnerability.

## Supported versions

Only the current `main` is supported. These are research tools; fixes land on
`main` and are not backported to tags.
