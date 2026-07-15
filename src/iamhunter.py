#!/usr/bin/env python3
"""
IAMHunter - Phase 1
Detects the "policy-version rollback" privilege-escalation path:
an identity that can call iam:SetDefaultPolicyVersion AND is attached to a
managed policy that has a non-default version granting MORE than the current
default (Phase 1 = wildcard admin: Allow + Action:* + Resource:*).

Reference technique: Rhino Security Labs IAM privesc catalogue
(iam_privesc_by_rollback).

Usage:
    python3 iamhunter.py --profile raynor
    python3 iamhunter.py --profile raynor --user raynor-cgid...   # scan one user
"""

import argparse
import json
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


# --- The detection rule (isolated on purpose) ---------------------------------
# Phase 1 rule: a policy version is a "rollback escalation target" if it grants
# wildcard admin. Keeping this as its own function means Phase 2 can replace the
# logic (real permission-diffing) without touching the rest of the scanner.
def grants_wildcard_admin(policy_document: dict) -> bool:
    """Return True if the policy document allows Action:* on Resource:* (admin).

    AWS concept: a policy 'Statement' can be a single dict OR a list of dicts.
    'Action' and 'Resource' can each be a string OR a list of strings.
    We normalise both so the check is robust.
    """
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):          # single statement -> wrap in list
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            return True
    return False


# The specific action that makes rollback possible.
ROLLBACK_ACTION = "iam:SetDefaultPolicyVersion"


def action_allows_rollback(policy_document: dict) -> bool:
    """True if the policy grants iam:SetDefaultPolicyVersion (incl. via wildcard).

    Matches the literal action, an iam:* / iam:Set* style wildcard, or full *.
    """
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for a in actions:
            if a == ROLLBACK_ACTION or a == "*":
                return True
            # crude wildcard match: "iam:Set*" covers SetDefaultPolicyVersion
            if a.endswith("*") and ROLLBACK_ACTION.startswith(a[:-1]):
                return True
    return False


def get_default_and_all_versions(iam, policy_arn):
    """Return (default_version_id, [list of {VersionId, IsDefault, Document}]).

    AWS concept: iam:ListPolicyVersions returns version *metadata* only (no
    document). You must call iam:GetPolicyVersion per version to see the actual
    permissions. That two-step is why the rollback path is easy to miss by eye.
    """
    versions = []
    default_id = None
    paginator = iam.get_paginator("list_policy_versions")
    for page in paginator.paginate(PolicyArn=policy_arn):
        for v in page["Versions"]:
            vid = v["VersionId"]
            is_default = v["IsDefaultVersion"]
            if is_default:
                default_id = vid
            doc = iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=vid
            )["PolicyVersion"]["Document"]
            versions.append(
                {"VersionId": vid, "IsDefault": is_default, "Document": doc}
            )
    return default_id, versions


def scan_user(iam, user_name):
    """Scan one IAM user for the rollback privesc path. Returns list of findings."""
    findings = []

    # Step 1: enumerate the user's ATTACHED managed policies.
    # (Phase 2 TODO: also inline policies + group-inherited policies.)
    attached = iam.list_attached_user_policies(UserName=user_name)[
        "AttachedPolicies"
    ]

    for pol in attached:
        policy_arn = pol["PolicyArn"]
        policy_name = pol["PolicyName"]

        default_id, versions = get_default_and_all_versions(iam, policy_arn)

        # Does the CURRENT (default) version grant the rollback action?
        default_doc = next(
            v["Document"] for v in versions if v["VersionId"] == default_id
        )
        can_rollback = action_allows_rollback(default_doc)
        if not can_rollback:
            continue  # no rollback power here -> not this privesc path

        # Are any NON-default versions wildcard admin? Those are the targets.
        for v in versions:
            if v["IsDefault"]:
                continue
            if grants_wildcard_admin(v["Document"]):
                findings.append(
                    {
                        "principal": user_name,
                        "policy_name": policy_name,
                        "policy_arn": policy_arn,
                        "current_default": default_id,
                        "escalation_target_version": v["VersionId"],
                    }
                )
    return findings


def _finding_as_text(f):
    """Build the human-readable finding block as a string (screen + file share it)."""
    return (
        "=" * 70 + "\n"
        "  FINDING: IAM privilege escalation via policy-version rollback\n"
        + "=" * 70 + "\n"
        f"  Affected principal : {f['principal']}\n"
        f"  Policy             : {f['policy_name']}\n"
        f"                       {f['policy_arn']}\n"
        f"  Current default    : {f['current_default']} (low privilege)\n"
        f"  Escalation target  : {f['escalation_target_version']} "
        f"(grants Action:* / Resource:*)\n"
        "\n"
        "  Risk:\n"
        "    This identity can call iam:SetDefaultPolicyVersion. A more-\n"
        "    permissive, non-default version of the attached policy exists.\n"
        "    The identity can roll the default pointer forward to that admin\n"
        "    version, instantly gaining full administrator access -- with no\n"
        "    new policy attached and no obvious change in the console.\n"
        "\n"
        "  Remediation:\n"
        "    - Remove iam:SetDefaultPolicyVersion from this identity, OR\n"
        "      scope it to specific non-sensitive policy ARNs.\n"
        "    - Delete unused/over-permissive policy versions "
        "(iam:DeletePolicyVersion).\n"
        "    - Prefer least-privilege managed policies over wildcard admin.\n"
        + "=" * 70 + "\n\n"
    )


def print_finding(f):
    print(_finding_as_text(f), end="")


def main():
    parser = argparse.ArgumentParser(description="IAMHunter Phase 1 - rollback privesc")
    parser.add_argument("--profile", required=True, help="AWS CLI profile to use")
    parser.add_argument("--user", help="Scan a single user (default: the caller)")
    parser.add_argument("--json", metavar="FILE",
                        help="Write findings as structured JSON to FILE")
    parser.add_argument("--output", metavar="FILE",
                        help="Write the human-readable report to FILE")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile)
    iam = session.client("iam")
    sts = session.client("sts")

    # Establish WHO we are scanning as (same idea as get-caller-identity).
    identity = sts.get_caller_identity()
    caller_arn = identity["Arn"]
    print(f"[*] Scanning as: {caller_arn}\n")

    # Default target: the calling user itself (the attacker's-eye view).
    if args.user:
        user_name = args.user
    else:
        # caller_arn looks like arn:aws:iam::ACCOUNT:user/NAME
        if ":user/" not in caller_arn:
            print("[!] Caller is not an IAM user; pass --user to specify a target.")
            sys.exit(1)
        user_name = caller_arn.split(":user/")[-1]

    print(f"[*] Target user: {user_name}\n")

    try:
        findings = scan_user(iam, user_name)
    except ClientError as e:
        print(f"[!] AWS error: {e}")
        sys.exit(1)

    if findings:
        print(f"[!] {len(findings)} finding(s):\n")
        for f in findings:
            print_finding(f)
    else:
        print("[+] No policy-version rollback escalation found for this user.")

    # --- Optional structured JSON output ------------------------------------
    # A self-documenting report: metadata about the scan + the raw findings.
    # Structured output means these findings could feed another tool later.
    if args.json:
        report = {
            "tool": "IAMHunter",
            "phase": 1,
            "detection": "iam_privesc_by_rollback",
            "scanned_as": caller_arn,
            "target_user": user_name,
            "scan_time_utc": datetime.now(timezone.utc).isoformat(),
            "finding_count": len(findings),
            "findings": findings,
        }
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n[+] JSON report written to {args.json}")

    # --- Optional human-readable text output --------------------------------
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(f"IAMHunter Phase 1 report\n")
            fh.write(f"Scanned as: {caller_arn}\n")
            fh.write(f"Target user: {user_name}\n")
            fh.write(f"Scan time (UTC): "
                     f"{datetime.now(timezone.utc).isoformat()}\n")
            fh.write(f"Findings: {len(findings)}\n\n")
            for f in findings:
                fh.write(_finding_as_text(f))
        print(f"[+] Text report written to {args.output}")


if __name__ == "__main__":
    main()
