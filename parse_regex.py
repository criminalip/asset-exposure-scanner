# parse_regex.py
# -*- coding: utf-8 -*-
"""
Extracts identifiers from a long text string (including line breaks) using regex-based matching.

Extraction targets (primarily regex-based):
- emails
- Google IDs: GA4 (G-), UA, GTM, Google Ads (AW-), google-site-verification (meta tag)
- Facebook/Meta Pixel ID (fbq init context)
- reCAPTCHA site key (recaptcha context)
- Telegram URL (t.me / telegram.me)

Usage examples:
  python parse_regex.py --file sample.txt --pretty 
  type sample.txt | python parse_regex.py

Output: JSON (deduplicated + sorted)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from typing import Dict, List, Set, Pattern, Iterable, Literal


# ----------------------------
# Regex patterns (strict-ish)
# ----------------------------

# Email: practical pattern (TLD at least 2 characters, dot required in domain to reduce false positives)
RE_EMAIL: Pattern = re.compile(
    r"""
    (?<![A-Za-z0-9._%+-])                           # left boundary
    ([A-Za-z0-9._%+-]{1,64}@
     (?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63})            # domain + TLD
    (?![A-Za-z0-9._%+-])                            # right boundary
    """,
    re.VERBOSE,
)

# Google Analytics / Tag IDs
RE_GA4: Pattern = re.compile(r"(?<![A-Z0-9])G-[A-Z0-9]{8,12}(?![A-Z0-9])")
RE_UA: Pattern = re.compile(r"(?<![A-Z0-9])UA-\d{4,10}-\d{1,4}(?![A-Z0-9])")
RE_GTM: Pattern = re.compile(r"(?<![A-Z0-9])GTM-[A-Z0-9]{6,8}(?![A-Z0-9])")
RE_AW: Pattern = re.compile(r"(?<![A-Z0-9])AW-\d{6,12}(?![A-Z0-9])")

# google-site-verification meta tag (including tag context)
RE_GOOGLE_SITE_VERIFICATION: Pattern = re.compile(
    r"""
    <meta\s+[^>]*name\s*=\s*["']google-site-verification["'][^>]*content\s*=\s*["']([^"']{10,})["'][^>]*>
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Telegram URL (URL format only)
RE_TELEGRAM_URL: Pattern = re.compile(
    r"""
    (?:
      https?://
    )?
    (?:t\.me|telegram\.me)/
    ([A-Za-z0-9_]{5,64})                             # username
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Facebook Pixel ID: only when it appears in fbq('init', '123...') context
RE_FB_PIXEL: Pattern = re.compile(
    r"""
    fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,20})['"]\s*\)
    """,
    re.IGNORECASE | re.VERBOSE,
)

# reCAPTCHA site key: recaptcha context + key shape (most start with 6L)
RE_RECAPTCHA_SITEKEY: Pattern = re.compile(
    r"""
    (?:
        google\.com/recaptcha|gstatic\.com/recaptcha|recaptcha\.(?:net|com)
    )
    [^"'<>]{0,200}
    (?:
        (?:render=|sitekey=|data-sitekey\s*=\s*["']|['"]sitekey['"]\s*:\s*['"])
        \s*
        (6[LA][A-Za-z0-9_-]{35,})
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

@dataclass(frozen=True)
class ExtractResult:
    emails: List[str]
    google_analytics_ids: List[str]          # GA4 + UA
    google_tag_manager_ids: List[str]        # GTM
    google_ads_ids: List[str]                # AW
    google_site_verification_tokens: List[str]
    facebook_pixel_ids: List[str]
    recaptcha_site_keys: List[str]
    telegram_usernames: List[str]            # from URL
    telegram_urls: List[str]


def _unique_sorted(items: Iterable[str]) -> List[str]:
    s: Set[str] = set()
    for x in items:
        if not x:
            continue
        s.add(x.strip())
    return sorted(s)

def extract_all(text: str, phone_mode: PhoneMode = "off") -> ExtractResult:
    # Emails
    emails = _unique_sorted(m.group(1) for m in RE_EMAIL.finditer(text))

    # Google IDs
    ga4 = [m.group(0) for m in RE_GA4.finditer(text)]
    ua = [m.group(0) for m in RE_UA.finditer(text)]
    gtm = [m.group(0) for m in RE_GTM.finditer(text)]
    aw = [m.group(0) for m in RE_AW.finditer(text)]

    # google-site-verification
    gsv = _unique_sorted(m.group(1) for m in RE_GOOGLE_SITE_VERIFICATION.finditer(text))

    # FB pixel
    fb = _unique_sorted(m.group(1) for m in RE_FB_PIXEL.finditer(text))

    # reCAPTCHA site key
    recaptcha = _unique_sorted(m.group(1) for m in RE_RECAPTCHA_SITEKEY.finditer(text))

    # Telegram (URL -> username, and also store normalized URL)
    telegram_usernames = []
    telegram_urls = []
    for m in RE_TELEGRAM_URL.finditer(text):
        username = m.group(1)
        if username:
            telegram_usernames.append(username)
            telegram_urls.append(f"https://t.me/{username}")

    return ExtractResult(
        emails=emails,
        google_analytics_ids=_unique_sorted(ga4 + ua),
        google_tag_manager_ids=_unique_sorted(gtm),
        google_ads_ids=_unique_sorted(aw),
        google_site_verification_tokens=gsv,
        facebook_pixel_ids=fb,
        recaptcha_site_keys=recaptcha,
        telegram_usernames=_unique_sorted(telegram_usernames),
        telegram_urls=_unique_sorted(telegram_urls),
    )


def as_dict(res: ExtractResult) -> Dict[str, List[str]]:
    return {
        "emails": res.emails,
        "google_analytics_ids": res.google_analytics_ids,
        "google_tag_manager_ids": res.google_tag_manager_ids,
        "google_ads_ids": res.google_ads_ids,
        "google_site_verification_tokens": res.google_site_verification_tokens,
        "facebook_pixel_ids": res.facebook_pixel_ids,
        "recaptcha_site_keys": res.recaptcha_site_keys,
        "telegram_usernames": res.telegram_usernames,
        "telegram_urls": res.telegram_urls,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", help="Input file path (reads from stdin if omitted)")
    ap.add_argument("--pretty", action="store_true", help="pretty print JSON")
    args = ap.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    else:
        text = sys.stdin.read()

    res = extract_all(text, phone_mode=args.phone_mode)
    payload = as_dict(res)

    if args.pretty:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
