---
name: Bug report
about: A wrong verdict, a crash, or output that does not match the docs
title: "[bug] "
labels: ["bug"]
---

## Tool and version

```
$ ./scanner/scan --version
```

## What happened

A clear description of the observed behaviour.

## What you expected

If this is a verdict problem, say what verdict you expected and why — a changelog
entry, a lab reproduction, or a packet capture beats "it should be vulnerable".

## Reproduction

```bash
# exact command line, redacted hostnames
```

## Target context

| Field | Value |
|---|---|
| PHP version | |
| SAPI (`mod_php` / `fpm`) | |
| `memory_limit` | |
| Behind a WAF or proxy? | |
| `post_max_size` | |

## Verdict block

```
# paste the full output block, including confidence and signal lines
```

## Anything else

Logs, `-v` output, or a note about what you already ruled out.
