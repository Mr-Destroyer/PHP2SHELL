# Changelog

All notable changes to this repository. Both tools live here; entries are tagged
`scanner` or `exploit-kit` so a reader can follow one at a time.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions are per-tool — the scanner and the exploit kit do not version in lockstep.

## [Unreleased]

### scanner

- UI: keep the result table sortable when a scan is still running.
- Probe: cap header-line filler on targets that return `413` early.

### exploit-kit

- Stage 3: the carrier still never reaches `PS(http_session_vars)`. Next attempt
  is to make the forge field land after the request heap is freed rather than
  before, per the open question in `FINDINGS.md`.

## scanner 1.1.0 — 2026-10-22

### Added

- `--sapi` to pin verdict rules to `mod_php` or `fpm`, for hosts that answer on
  both a module and a FastCGI socket.
- Progressive probe escalation (1 → 8 → 20 MiB): a low `memory_limit` target is
  caught with 1 MiB, and a host that already answered is never sent 20 MiB.
- `--ui` local web console: per-probe detail, live table, no external assets.
- JSON output with `--all-results` so a report can show negatives too.

### Changed

- Verdicts no longer merge behavioural and version evidence. `LIKELY VULNERABLE`
  is a separate verdict from `VULNERABLE`, and confidence is `HIGH` only when the
  crash signal is in-band.
- `INCONCLUSIVE` is returned when the control request fails, instead of guessing.

### Fixed

- Version parsing ignored `PHP/8.4.x` reported through `Server:` when
  `X-Powered-By` was suppressed.
- Transport reused a pooled connection across probes, which hid per-request
  worker rotation. Each probe now opens its own connection.

## scanner 1.0.0 — 2026-10-19
