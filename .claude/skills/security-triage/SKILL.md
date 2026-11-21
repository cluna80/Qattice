---
name: security-triage
description: >
  Triage and fix security vulnerabilities in Qattice — Dependabot alerts, CVEs, npm/Cargo
  advisories, and any reported security issue. Use this skill whenever vulnerabilities are
  mentioned, flagged, or discovered. Triggers on: "Dependabot alert", "vulnerability",
  "CVE", "security advisory", "npm audit", "cargo audit", "security issue", "fix the vulns",
  "what are these vulnerabilities", or any push output or CI check that mentions security
  findings. Never dismiss or defer a critical or high severity finding without understanding
  it first.
---

# Security Triage

Security vulnerabilities need to be understood before they're fixed — a blind `npm update`
or `cargo update` can break things. Work through this systematically.

## Step 1: Get the full alert list

Use the GitHub API to fetch all open Dependabot alerts:

```bash
gh api repos/<owner>/<repo>/dependabot/alerts --paginate \
  -q '.[] | select(.state=="open") | {number:.number, severity:.security_vulnerability.severity, package:.security_vulnerability.package.name, summary:.security_advisory.summary}'
```

Sort mentally by severity: **critical → high → medium → low**.

## Step 2: Prioritize by actual risk

Not all vulnerabilities are equal. For each finding, ask:

**Is the vulnerable code reachable in this project?**
- A DoS vuln in a build tool that never runs in production = low actual risk
- An auth bypass in `better-auth` used by the wallet = critical actual risk

**Is the attack vector realistic?**
- Requires local network access vs. remote unauthenticated = very different
- Requires attacker-controlled input that never reaches this code = may be unexploitable

**Ecosystem:** Rust crates via `Cargo.lock` vs. JS packages via `package.json` are different:
- Rust: check `chain-forge-*` crates — anything touching crypto is highest priority
- JS/wallet: `Qattice wallet/package.json` — auth, serialization, and input validation are highest priority

## Step 3: Check for patched versions

**For npm (Qattice wallet):**
```bash
cd "Qattice wallet"
npm outdated                    # shows current vs latest
npm audit                       # shows which updates fix which vulns
```

**For Cargo:**
```bash
cargo audit                     # requires cargo-audit: cargo install cargo-audit
```

Check the advisory for the minimum patched version — don't just grab latest blindly.

## Step 4: Fix by severity tier

### Critical / High — fix immediately

These get their own commit. Do not bundle with unrelated work.

For npm:
```bash
cd "Qattice wallet"
npm install <package>@<patched-version>
npm audit   # verify the finding is gone
```

For Cargo:
```bash
cargo update -p <crate> --precise <patched-version>
cargo test --no-run   # verify it still compiles
```

If bumping a version introduces breaking changes, scope that work separately — don't silently
fix a breaking API change inside a "security update" commit.

### Medium — fix in next planned update

Group medium findings into a single dependency update commit. Document what was updated and why.

### Low — track but don't rush

Low findings often have no practical exploit path. Note them, but they don't need an emergency fix.
Revisit when doing a planned dependency sweep.

## Step 5: Verify the fix

After updating:
1. Run `npm audit` or `cargo audit` again — confirm the alert count dropped
2. Run the relevant test suite to confirm nothing broke
3. For `better-auth` or any auth-related change: manually verify that login/logout still works
   if you have a way to test it

## Step 6: Commit correctly

One commit per severity tier (or per package if the changes are unrelated):

```
fix(deps): patch critical better-auth OAuth state vulnerability

Updates better-auth from 1.6.30 to X.X.X to address:
- CVE-XXXX-XXXX: OAuth state used as Magic Link (critical)
- CVE-XXXX-XXXX: OAuth Proxy sign-in bypass (high)
- CVE-XXXX-XXXX: Device login approval missing client info (high)
```

Then apply `commit-discipline` before pushing.

## Step 7: Close or dismiss alerts

After pushing a fix, Dependabot auto-closes resolved alerts within a few minutes.
For alerts that are genuinely unexploitable in this project (e.g., a vuln in a code path
that is never called), you can dismiss them on GitHub with a reason — but document why,
don't just dismiss to get a clean count.

## Qattice-specific notes

- **Rust crypto crates** (`chain-forge-crypto`, `chain-forge-keygen`): any update to PQ crypto
  libraries (e.g., `pqcrypto`, `ml-dsa`, `dilithium`) must go through `arch-guard` first —
  crypto primitive updates are locked decisions
- **`better-auth`** in `Qattice wallet`: auth vulnerabilities here affect real user accounts —
  treat critical/high as production incidents, not deferred maintenance
- **`zod`**: used for input validation across the wallet — a memory exhaustion vuln could be
  exploited via malformed form input, patch promptly
