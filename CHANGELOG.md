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
