# Security Policy

Aletheia is defensive tooling — a reverse-engineering / triage suite
for malware analysts and security researchers who have authorization
to examine the binaries they run through it. Please read this file
before opening an issue or submitting a PR touching the sandbox,
debug, or hypervisor layers.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security bug.

Use GitHub's [private vulnerability reporting form](https://github.com/zaehuncho/Aletheia/security/advisories/new) with:

- A clear description of the class of the problem.
- A minimal repro against an artifact we can look at — a sample
  binary hash we can pull from VirusTotal / Malware Bazaar, a
  synthetic PE you can attach, or a stack trace.
- Your suggested severity and why.

We aim to acknowledge within 3 business days and to ship a fix or
publish a mitigation within 30 days of an acknowledged report. If
we can't meet either, we'll say so and give you a revised date.

**Do not include a working exploit** in the initial mail. Describe
the class of problem and a repro shape; if we need more detail, we'll
ask through the private advisory thread.

## Threat model

Aletheia executes potentially hostile code inside a Win32 debugger
loop. The intended user is an analyst who has:

- Explicit authorization to run the target sample.
- A sacrificial machine or a snapshotted VM.
- Modern Windows 11 with Defender enabled.

Aletheia's dynamic layer is **not** an anti-cheat evader, **not** a
malware runtime obfuscator, and **not** designed to run inside a
production endpoint. Reports that assume any of those threat models
will be closed as out-of-scope.

### In scope

- False negatives on real packed samples with citable references (a
  VT hash for the sample; a paper for the family).
- False positives on known-clean binaries.
- Crashes / hangs in the analyzer that a hostile sample can trigger
  from user-mode ring-3 execution.
- Path-traversal / file-write bugs in the packer harness or dump
  paths.
- Any driver-mode issue in the `hv/` scaffold — even though it isn't
  loaded by default, the source itself is a live target.

### Out of scope

- **Detection-evasion tooling.** We don't accept issues asking us to
  suppress a detection, hide a debugger from a sample, or bypass
  HVCI / Secure Boot. Aletheia is defensive tooling; those requests
  are refused.
- **Signed-driver bypass.** If your report is "I can load an
  unsigned `.sys` on Windows 11", that isn't a bug in Aletheia — it
  is a Windows kernel policy that isn't ours to relax.
- **Sandbox escape from inside the analyzed sample.** Aletheia's
  Win32 Debug API loop is a *debugger*, not a sandbox: a sample that
  escapes it is doing what any debugged program can do. If you find
  a case where a sample can *escalate through* Aletheia — turn a
  ring-3 execution into a ring-0 or Aletheia-privileged action — that
  IS in scope, please report.
- **Recovered malicious code.** If a sample Aletheia dumped is
  malicious — that's the point of the tool. Don't file an issue.

## Boundaries the maintainers hold

Two clean-room boundaries are structural and non-negotiable:

1. **No anti-cheat evasion.** The maintainers develop unrelated
   anti-cheat-evasion tooling elsewhere; none of that source has
   been consulted for Aletheia. PRs adding evasion primitives — even
   when defensively framed — will be closed.
2. **No proprietary hypervisor code.** The `hv/` tree is clean-room
   against the public Intel SDM and AMD APM, cross-checked against
   named open-source projects (hvpp, SimpleVisor, Bareflank,
   DRAKVUF, LibVMI, KVM-svm). PRs referencing or transcribing from
   proprietary or leaked HV sources will be closed.

## Coordinated disclosure

We'll credit reporters in the changelog unless they ask not to be.
Names, no company affiliation unless you provide one. If you'd like
your report kept private after fix, tell us — we'll fix silently and
issue a "silent 2026-08-xx security fix" line in the changelog.
