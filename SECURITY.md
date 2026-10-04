# Security Policy

`crypt-data` is a cryptography library: factories, readers and writers for keys,
certificates and key stores. A defect here can silently weaken something a
consumer believes is protected, so the reporting path below is deliberately not
the public issue tracker.

## Supported Versions

Only the current minor line receives security fixes. This is a
single-maintainer project, and supporting several lines at once is a promise it
could not keep.

| Version | Supported          | Required JDK | Needs crypt-api |
|---------|--------------------|--------------|-----------------|
| 12.x    | :white_check_mark: | 25 and above | 10.0.0 or newer |
| 11.x    | :x:                | 21 and above | 9.5             |
| 10.x    | :x:                | 21 and above | 9.3 - 9.5       |
| < 10    | :x:                | 17 and above | 9 - 9.3         |

The current release is **12.2**. If you are on an older line, the fix for a
reported vulnerability will be an upgrade to the current one rather than a
backport.

## Reporting a Vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting,
which is enabled on this repository:

[Report a vulnerability](https://github.com/astrapi69/crypt-data/security/advisories/new)

That keeps the report between you and the maintainer until a fix exists, and it
creates the draft advisory a CVE can later be issued from.

Please include, as far as you can:

- the version you found it in, and whether the current release is affected
- which class or method is involved
- what an attacker gains - reading key material, forging a signature, getting a
  weaker key than was asked for, and so on
- a way to reproduce it: a failing test is ideal, since this project fixes bugs
  test-first and yours would become the regression guard

### What happens next

This is a spare-time project, so no response time is promised that could not be
met. What is promised instead:

- a reply acknowledging the report, and whether it is reproducible
- if it is: a fix on the current line, a release, and an advisory crediting you
  unless you prefer otherwise
- if it is not, or it turns out to be intended behaviour: an explanation of why,
  rather than silence

### What belongs elsewhere

This library never implements cryptographic primitives itself - ciphers, hashes,
signatures, key derivation and random generation all come from the JDK or from
Bouncy Castle, and the code here only orchestrates them. A flaw in a primitive
itself belongs to whoever implements it:

- the JDK: <https://openjdk.org/groups/vulnerability/report>
- Bouncy Castle: <https://github.com/bcgit/bc-java/security/policy>

A flaw in *how this library uses* one of them - a key written in a format the
caller did not ask for, a password left in memory, a comparison that is not
constant time - is squarely in scope here.

## What this project already does

So that a report can start from what is known rather than from zero:

- **CodeQL** runs on every push and pull request to `master` and `develop`, plus
  weekly. Its first run on this repository found seven real
  `java/insufficient-key-size` alerts, all since fixed.
- **Dependabot security updates** are enabled.
- Test key material is generated at test runtime and never committed, so nothing
  in this repository is a real key.
- The test suite covers 100% of lines and branches, and PIT mutation testing
  kills every mutant it generates - measured on `RELEASE-12.2` and recorded, with
  the commit it was measured on, in the family's canonical table at
  [mystic-crypt/docs/TESTING.md](https://github.com/astrapi69/mystic-crypt/blob/develop/docs/TESTING.md).
  A gap in the tests is therefore a documented decision rather than an accident.
