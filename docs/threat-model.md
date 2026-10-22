# Threat model

What these tools assume about a target, what they assume about their operator, and
where those assumptions break.

## Assets

| Asset | Where it lives | Consequence if lost |
|---|---|---|
| Target list | `-l` file, operator's disk | Disclosure of what you are assessing |
| Scan results | `-o` JSON, console output | Disclosure of exposure, and of the assessment itself |
| Lab offsets | `exploit-kit/php2shell_exploit/structures.py` | Public knowledge already; not sensitive |
| Nothing else | — | The tools hold no credentials, no telemetry, no cloud state |

Both tools are stateless. There is no database, no phone-home, no analytics.

## Assumptions about the target

1. **It parses multipart bodies.** If it does not, the scan is `INCONCLUSIVE`.
2. **The path to PHP is not buffering the whole body.** A proxy that answers
   `413` short-circuits detection.
3. **`memory_limit` is finite.** `-1` defeats the OOM signal.
4. **The worker is not immediately recycled after a crash.** Aggressive `pm=ondemand`
   recycling can mask the signal; a `VULNERABLE` verdict is still valid, a
   `NOT VULNERABLE` one may be a false negative.
5. **The response reaches us.** A WAF that rewrites error pages hides the signal.

Assumption 4 and 5 are the ones that produce wrong negatives. They are documented
in [`detection-methodology.md`](detection-methodology.md#known-blind-spots) and
repeated in the README's limitations, because a scanner that quietly lies is worse
than one that abstains.

## Assumptions about the operator

- You own the target, or you hold **written** authorisation.
- You understand that `VULNERABLE` is a precondition, not an exploit.
- You will not expose the `--ui` port.

None of these are enforced in code. They cannot be: the tools run on your host,
against your target. This section exists so that the assumption is explicit rather
than implied.

## Threat: the tools as a weapon against the operator

| Threat | Mitigation |
|---|---|
| Malicious `-l` file with huge line count | Lines are stripped and capped; a target is a URL, not a program |
| Target returns a giant body to exhaust scanner memory | Response bodies are read with a cap, not `read()` |
| Target returns a crafted version string | Version data never promotes a verdict to `VULNERABLE` |
| `--ui` serving local files | Static assets are served from a fixed manifest, not a path join |
| SSRF against internal services via `-u` | Out of scope by design: you choose the target, and that is the tool's purpose |

## Threat: the tools as a weapon against a third party

The realistic misuse is "scan someone else's estate". Nothing in the code prevents
it, and nothing can — the same is true of `nmap`. What the code does do is make
misuse loud and attributable:

- The scanner prints an authorised-use banner and asks for confirmation on a TTY
  unless `--yes` is passed (piped/non-interactive runs skip the prompt).
- Both tools print an authorised-use banner in `--help` and on start.
- Every probe is a large multipart POST; it is not stealthy, and it will appear in
  the target's logs with the operator's source address.

That is a deliberate choice. This is a verification tool, not a reconnaissance
tool.

## Supply chain

| Surface | Position |
|---|---|
| Runtime dependencies | None. Nothing to compromise via `pip`. |
| Build step | None. The launchers run from a checkout. |
| Web assets | Vendored, no CDN, no external font or script |
| CI | Runs the test suite only; no publish, no secrets |
| Actions | Pinned to major versions; Dependabot watches them |

A zero-dependency tool has a small supply chain, which is the main reason both
packages stay on the standard library even where a library would be nicer.

## Out of scope

- Denial of service against the target beyond the deliberate worker crash the
  probe causes. Both tools send bounded bodies and stop.
- Persistence, lateral movement, or post-exploitation. The exploit kit stops at
  the primitive; it does not include a stager.
- Anything involving a target you do not control.
