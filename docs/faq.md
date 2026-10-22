# FAQ

### The scanner says `LIKELY VULNERABLE` but I cannot reproduce a crash. Which is it?

`LIKELY VULNERABLE` is a version-data verdict with no behavioural signal behind it.
Treat it as a lead, not a finding. Check the vendor changelog for a backported fix,
then try `--max-probe-mib 32 -v` to see whether your probes are reaching PHP at all.

### Everything returns `INCONCLUSIVE`. Is the tool broken?

Almost never. `INCONCLUSIVE` means the control request failed or every probe was
blocked, so no differential claim is possible. Common causes, in order:

1. A WAF or proxy answering `403` / `413` before PHP parses the body.
2. `post_max_size` below the probe size — PHP rejects the body early.
3. TLS interception without `-k`.
4. The target is not PHP at all.

Run with `-v` and look at what the control request actually got back.

### Does a crash mean I can exploit it?

No. A reproduced OOM proves the vulnerable parsing path is reachable, which is the
precondition for corruption. It does not prove a working chain exists for that
build — heap layout and symbol offsets vary per image. That gap is the entire
subject of [`exploit-chain.md`](exploit-chain.md).

### Why does the exploit kit fail at stage 3? Is my lab wrong?

Stage 3 fails on the reference lab too. The carrier never reaches
`PS(http_session_vars)`; it is freed before the session table is walked. If you
reproduce the documented stages 0–2 and then a stage 3 failure, your lab is
correct.

### Why do the public PoC offsets not work?

They belong to a different build. With `0x43A870` / `0x613C50`, stage 2 cannot
match: the low 12 bits of the leaked `pDestructor` (`0xb60`) only line up with
`0x65EB60`. Derive your own with `nm -D libphp.so`.

### Can I use this against a host I do not own?

No. Both tools deliberately crash PHP workers. Use them on your own images or
under written authorisation.

### Is `memory_limit = -1` a bypass or a blind spot?

A blind spot. With no limit the OOM may never occur, so the scanner reports no
signal even on a vulnerable build. Fall back to version data and label it as such.

### Will a WAF stop the scanner?

Often, and it will usually show up as `INCONCLUSIVE` rather than a false negative,
which is the behaviour we want. Some WAFs answer `200` with a block page; the
scanner sees the control request fail to baseline and stops.

### Why no `requests` dependency?

Because the scanner has to run on a jump host where you cannot install anything,
and because the probe bodies are the interesting part — a 20 MiB multipart body
with 62 levels of nesting is easier to reason about when the only layer beneath it
is `http.client`.

### The UI has no login. Is that a bug?

No, it is the design. `--ui` binds to `127.0.0.1` and every API route requires the
per-run `?token=` printed in the terminal, which is also what blocks CSRF from a
random page in the same browser. There are no user accounts because there is one
operator. If you expose the port, that is the bug — see
[`../SECURITY.md`](../SECURITY.md).

### How do I add a detection rule for a new SAPI?

Add the rule to the verdict builder in `scanner/php2shell/scanner.py`, extend
`--sapi` choices in `cli.py`, and add a case to `tests/test_scanner.py`. A rule
without a test will be reverted: the suite is the contract.

### Why is `-c` limited to 14 bytes?

The primitive, not the CLI. The command is delivered through a fixed-size buffer in
the forged structure. Use `--fetch` to retrieve a file you wrote, or chain through
a small stub.

### Where are the tests for the exploit kit?

There are none in CI, and that is deliberate: every meaningful assertion needs a
live lab with a specific image, a specific worker count and a specific heap state.
CI cannot distinguish a broken tool from a broken lab, so the exploit kit is
verified by `FINDINGS.md` and by `--diagnose` runs pasted into pull requests.
