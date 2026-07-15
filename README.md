# IAMHunter

An automated AWS IAM privilege-escalation scanner written in Python (boto3).
IAMHunter enumerates IAM identities and their policies and flags configurations
that allow an identity to escalate its own privileges.



## What it detects (Phase 1)

**Policy-version rollback privilege escalation.**

AWS managed policies are versioned: a single policy can hold up to five stored
versions, but only one is the *default* (active) version at a time. The API call
`iam:SetDefaultPolicyVersion` simply moves the pointer that decides which version
is active.

If an identity can call `iam:SetDefaultPolicyVersion` **and** one of the
policy's non-default versions grants more than the current default, that identity
can roll the pointer to the permissive version and instantly escalate — with no
new policy attached and no obvious change in the console.

IAMHunter flags exactly this: an identity whose attached policy grants the
rollback action *and* has a non-default version granting wildcard administrator
access (`Allow` + `Action:*` + `Resource:*`).

### Why this is non-trivial

In the CloudGoat test scenario, the target policy has five versions:

| Version | Grants | Escalation? |
|---------|--------|-------------|
| v1 (default) | `iam:Get*`, `iam:List*`, `iam:SetDefaultPolicyVersion` | current state |
| v2 | `Deny *` except from specific IPs | No — *more restrictive* |
| **v3** | `Allow * / *` (**full admin**) | **Yes — the target** |
| v4 | `iam:Get*` with an expired 2017 date condition | No — narrower + dead |
| v5 | three read-only S3 actions | No — narrower |

Four of the five versions are non-default, but only **one** is an actual
escalation. A naive "flag any non-default version" scanner produces three false
positives. IAMHunter compares each version against the default and flags only
versions that grant *more* — catching v3 while staying silent on v2, v4, and v5.

---

## Usage

```bash
pip install -r requirements.txt

# scan the calling identity (attacker's-eye view)
python3 iamhunter.py --profile <aws_profile>

# scan a specific user
python3 iamhunter.py --profile <aws_profile> --user <user_name>

# write reports
python3 iamhunter.py --profile <aws_profile> --json report.json --output report.txt
```

- Human-readable output by default.
- `--json` writes structured findings (scan metadata + findings) for use in
  automation or pipelines.
- `--output` writes the human-readable report to a file.

See [`sample_output/`](sample_output/) for example reports and
[`screenshots/`](screenshots/) for a validated run against CloudGoat.

---

## How it works

Each finding is produced by mirroring the manual reconnaissance an analyst would
perform, then automating the comparison:

1. `sts:GetCallerIdentity` — establish which identity is being scanned.
2. `iam:ListAttachedUserPolicies` — enumerate attached managed policies.
3. `iam:ListPolicyVersions` — list every version of each policy.
4. `iam:GetPolicyVersion` — fetch each version's actual permission document
   (version metadata alone doesn't include permissions).
5. Compare: does the *default* grant `iam:SetDefaultPolicyVersion`, and does any
   *non-default* version grant wildcard admin? If so → finding.

The detection rule lives in a single isolated function
(`grants_wildcard_admin`) so Phase 2 can replace it with fuller
permission-diffing without touching the enumeration code.

Each finding reports: affected principal, the risky policy and versions, a risk
explanation, and concrete remediation steps.

---

## Roadmap

Phase 1 is deliberately narrow — one detection path, working and tested — before
expanding coverage.

- [x] **Phase 1: policy-version rollback detection** (attached managed policies, users)
- [x] Structured JSON + human-readable reporting
- [x] Validated against live CloudGoat `iam_privesc_by_rollback`
- [ ] **Phase 2: expand scope** — inline policies, group-inherited policies, and roles
- [ ] **Phase 2: PassRole abuse detection**
- [ ] **Phase 2: self-attach-admin detection** (`iam:AttachUserPolicy` / `iam:AttachRolePolicy`)
- [ ] **Phase 2: fuller permission comparison** (wildcards, `NotAction`, conditions)

### Known limitations (current)

- Scans **attached managed policies on IAM users only** — not inline policies,
  group-inherited policies, or roles (Phase 2).
- The "more permissive" check flags **wildcard admin** specifically. Broader
  permission-diffing is Phase 2, because doing it imprecisely produces false
  confidence.

---

## Testing

Developed and tested against Rhino Security Labs'
[CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)
`iam_privesc_by_rollback` scenario in a personal AWS sandbox account.

**Responsible use:** CloudGoat deploys real, billable, deliberately-vulnerable
AWS resources. This project was developed with a strict deploy → test → destroy
workflow — every deployed scenario was torn down in the same session
(`cloudgoat destroy`). Only ever run this tool against accounts you own or are
explicitly authorized to assess.

---

## Reference

- [Rhino Security Labs — AWS IAM Privilege Escalation techniques](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)

## License

MIT
