---
name: Feature request
about: A new detection rule, a new stage primitive, or a reporting improvement
title: "[feat] "
labels: ["enhancement"]
---

## Which tool

- [ ] `scanner/`
- [ ] `exploit-kit/`
- [ ] docs / CI

## What it should do

Describe the behaviour, not the implementation.

## Why it is worth the complexity

Both packages are stdlib-only on purpose and the scanner is small on purpose.
Say what this buys that the current behaviour does not — a new SAPI, a new failure
mode, a reporting gap.

## Evidence it would work

For a detection rule: which probe feature isolates which variable? A rule that
cannot be explained in one sentence is usually two rules.

For a chain primitive: what did you measure, and on which image?

## What it must not break

- [ ] Behavioural and version evidence stay separately labelled
- [ ] No new runtime dependencies
- [ ] `make test` stays green
- [ ] No payload collection added
