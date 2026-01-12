#!/usr/bin/env python3
import argparse
import hashlib
import os
import sys
from getpass import getpass
from typing import Dict, List, Optional, Tuple

import requests

PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"  # first 5 chars
HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"


class HibpError(RuntimeError):
    pass


def sha1_upper_hex(s: str) -> str:
    """SHA-1 hash of UTF-8 string, returned as uppercase hex (HIBP format)."""
    return hashlib.sha1(s.encode("utf-8")).hexdigest().upper()


def parse_range_response(text: str) -> Dict[str, int]:
    """
    Response format is lines like:
      <HASH_SUFFIX>:<COUNT>
    Returns dict of suffix -> count
    """
    out: Dict[str, int] = {}
    for line in text.splitlines():
        if not line or ":" not in line:
            continue
        suffix, count_str = line.split(":", 1)
        suffix = suffix.strip().upper()
        # With padding enabled, some entries may have count 0; harmless to keep or ignore
        try:
            out[suffix] = int(count_str.strip())
        except ValueError:
            continue
    return out


def pwned_password_count(password: str, *, add_padding: bool = True, timeout: int = 10) -> Tuple[int, str]:
    """
    Uses k-anonymity range API:
      GET https://api.pwnedpasswords.com/range/{first 5 hash chars}
    Returns (count, full_sha1)
    """
    full_hash = sha1_upper_hex(password)
    prefix, suffix = full_hash[:5], full_hash[5:]

    headers = {}
    # Optional privacy enhancement: request padding so response sizes are less informative
    if add_padding:
        headers["Add-Padding"] = "true"

    url = PWNED_RANGE_URL.format(prefix)
    resp = requests.get(url, headers=headers, timeout=timeout)
    if resp.status_code != 200:
        raise HibpError(f"Pwned Passwords range API failed: HTTP {resp.status_code} - {resp.text[:200]}")

    suffix_counts = parse_range_response(resp.text)
    return suffix_counts.get(suffix, 0), full_hash


def hibp_headers(api_key: str, user_agent: str) -> Dict[str, str]:
    # HIBP requires hibp-api-key for endpoints that search by email,
    # and also requires a proper User-Agent (or you may get 403).
    return {
        "hibp-api-key": api_key,
        "User-Agent": user_agent,
        "Accept": "application/json",
    }


def hibp_breached_account(email: str, api_key: str, user_agent: str, timeout: int = 15) -> List[dict]:
    """
    GET /breachedaccount/{account}
    Returns list of breaches for the account.
    """
    url = f"{HIBP_API_BASE}/breachedaccount/{email}"
    params = {
        "truncateResponse": "false",  # get full breach objects
    }
    resp = requests.get(url, headers=hibp_headers(api_key, user_agent), params=params, timeout=timeout)

    if resp.status_code == 404:
        return []  # Not pwned
    if resp.status_code == 401:
        raise HibpError("Unauthorized (401): Missing/invalid HIBP API key.")
    if resp.status_code == 403:
        raise HibpError("Forbidden (403): Missing/invalid User-Agent header.")
    if resp.status_code == 429:
        retry_after = resp.headers.get("Retry-After")
        raise HibpError(f"Rate limited (429). Retry-After: {retry_after} seconds.")
    if resp.status_code != 200:
        raise HibpError(f"HIBP breachedaccount failed: HTTP {resp.status_code} - {resp.text[:200]}")

    return resp.json()


def format_breach(b: dict) -> str:
    # Fields vary; these are common ones in HIBP breach model
    name = b.get("Name", "Unknown")
    title = b.get("Title", name)
    domain = b.get("Domain", "")
    breach_date = b.get("BreachDate", "")
    added = b.get("AddedDate", "")
    pwn_count = b.get("PwnCount", "")
    data_classes = b.get("DataClasses", [])
    verified = b.get("IsVerified", None)
    sensitive = b.get("IsSensitive", None)

    parts = [
        f"{title} ({name})",
        f"  Domain: {domain}" if domain else None,
        f"  BreachDate: {breach_date}" if breach_date else None,
        f"  AddedDate: {added}" if added else None,
        f"  PwnCount: {pwn_count}" if pwn_count != "" else None,
        f"  Verified: {verified}" if verified is not None else None,
        f"  Sensitive: {sensitive}" if sensitive is not None else None,
        f"  Data: {', '.join(data_classes)}" if data_classes else None,
    ]
    return "\n".join([p for p in parts if p is not None])


def cmd_check_password(args: argparse.Namespace) -> int:
    password = args.password
    if password is None:
        password = getpass("Enter password to check (input hidden): ")

    if not password:
        print("No password provided.")
        return 2

    try:
        count, full_hash = pwned_password_count(password, add_padding=not args.no_padding)
    except HibpError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1

    # Never print the raw password; hash is OK to show (optional)
    print(f"SHA-1: {full_hash[:5]}… (redacted)")
    if count > 0:
        print(f"❌ This password has appeared in data breaches {count} time(s).")
        print("Recommendation: change it everywhere and use a unique password + a password manager.")
        print(
            "\nNote: HIBP cannot tell you which specific breach/leak contained the password — "
            "the password API only provides prevalence counts."
        )
    else:
        print("✅ This password was NOT found in the Pwned Passwords dataset (based on HIBP).")
        print("Still: prefer long, unique passwords and enable MFA.")

    return 0


def cmd_check_email(args: argparse.Namespace) -> int:
    email = args.email
    api_key = args.api_key or os.getenv("HIBP_API_KEY")
    user_agent = args.user_agent or os.getenv("HIBP_USER_AGENT") or "hibp-checker/1.0 (contact: you@example.com)"

    if not api_key:
        print("Missing API key. Provide --api-key or set HIBP_API_KEY env var.", file=sys.stderr)
        return 2

    try:
        breaches = hibp_breached_account(email, api_key=api_key, user_agent=user_agent)
    except HibpError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1

    if not breaches:
        print(f"✅ No breaches found for: {email}")
        return 0

    print(f"❌ Breaches found for: {email} ({len(breaches)} total)\n")
    for b in breaches:
        print(format_breach(b))
        print("-" * 60)

    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Check passwords via HIBP Pwned Passwords (k-anonymity) and optionally check emails for breaches."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_pass = sub.add_parser("check-password", help="Check if a password is in HIBP Pwned Passwords dataset.")
    p_pass.add_argument("--password", help="Password to check (NOT recommended; will appear in shell history).")
    p_pass.add_argument("--no-padding", action="store_true", help="Disable Add-Padding header.")
    p_pass.set_defaults(func=cmd_check_password)

    p_email = sub.add_parser("check-email", help="Check if an email address appears in known breaches (requires API key).")
    p_email.add_argument("email", help="Email address to check.")
    p_email.add_argument("--api-key", help="HIBP API key (or set env var HIBP_API_KEY).")
    p_email.add_argument(
        "--user-agent",
        help="User-Agent string (or set env var HIBP_USER_AGENT). Required by HIBP API.",
    )
    p_email.set_defaults(func=cmd_check_email)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
