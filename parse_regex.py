# parse_regex.py
# -*- coding: utf-8 -*-
"""
긴 본문(개행 포함) 문자열에서 "정규식 기반"으로 식별자들을 추출합니다.

추출 대상(정규식 중심):
- emails
- Google IDs: GA4 (G-), UA, GTM, Google Ads (AW-), google-site-verification(meta tag)
- Facebook/Meta Pixel ID (fbq init 컨텍스트)
- reCAPTCHA site key (recaptcha 컨텍스트)
- Telegram URL (t.me / telegram.me)
- 한국 사업자등록번호 (컨텍스트 기반)
- 한국 휴대폰 010 번호 (모드별: strict/loose/context_required)

전화번호 모드:
- strict: 010-1234-5678 (하이픈 필수)
- loose: 01012345678 / 010-1234-5678 / 010 1234 5678 (구분자 선택)
- context_required: 'tel/phone/연락처/문의/☎' 등 키워드 근처에서만 추출(오진 최소)

사용 예:
  python parse_regex.py --file sample.txt --pretty --phone-mode strict
  python parse_regex.py --file sample.txt --pretty --phone-mode context_required
  type sample.txt | python parse_regex.py --phone-mode loose

출력: JSON (중복 제거 + 정렬)
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

# Email: 실무형(오진 낮추기 위해 TLD 최소 2자, 도메인 점 포함)
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

# google-site-verification meta tag (태그 컨텍스트 포함)
RE_GOOGLE_SITE_VERIFICATION: Pattern = re.compile(
    r"""
    <meta\s+[^>]*name\s*=\s*["']google-site-verification["'][^>]*content\s*=\s*["']([^"']{10,})["'][^>]*>
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Telegram URL (URL 형태로만)
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

# Facebook Pixel ID: fbq('init', '123...') 컨텍스트로만
RE_FB_PIXEL: Pattern = re.compile(
    r"""
    fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,20})['"]\s*\)
    """,
    re.IGNORECASE | re.VERBOSE,
)

# reCAPTCHA site key: recaptcha 컨텍스트 + key shape(대부분 6L로 시작)
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

# 한국 사업자등록번호: 컨텍스트 키워드 근처에서만
RE_KR_BIZNO_CONTEXT: Pattern = re.compile(
    r"""
    (?:
        사업자\s*등록\s*번호|사업자번호|사업자등록번호|Biz\s*No|Business\s*Registration\s*No
    )
    [^0-9]{0,30}
    (\d{3}-\d{2}-\d{5})
    """,
    re.IGNORECASE | re.VERBOSE,
)

# 한국 휴대폰 010: 모드별 정규식
RE_KR_PHONE_STRICT: Pattern = re.compile(r"(?<!\d)(010-\d{4}-\d{4})(?!\d)")
RE_KR_PHONE_LOOSE: Pattern = re.compile(r"(?<!\d)(010[- ]?\d{4}[- ]?\d{4})(?!\d)")

# 컨텍스트 기반(키워드 근처 0~40자 안에 010 번호가 등장하는 경우만)
RE_KR_PHONE_CONTEXT: Pattern = re.compile(
    r"""
    (?:
        tel|phone|mobile|contact|call|문의|연락|연락처|전화|상담|대표번호|고객센터|☎
    )
    [^0-9]{0,40}
    (010[- ]?\d{4}[- ]?\d{4})
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
    kr_business_registration_numbers: List[str]
    kr_mobile_phones_010: List[str]           # extracted (normalized optional)


def _unique_sorted(items: Iterable[str]) -> List[str]:
    s: Set[str] = set()
    for x in items:
        if not x:
            continue
        s.add(x.strip())
    return sorted(s)


def _normalize_010_phone(raw: str) -> str:
    """
    Normalize to 010-1234-5678
    Accepts:
      - 01012345678
      - 010-1234-5678
      - 010 1234 5678
      - 010-1234 5678, etc.
    """
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 11 and digits.startswith("010"):
        return f"{digits[0:3]}-{digits[3:7]}-{digits[7:11]}"
    # fallback: return trimmed raw if unexpected
    return raw.strip()


PhoneMode = Literal["off", "strict", "loose", "context_required"]


def extract_kr_phones(text: str, mode: PhoneMode) -> List[str]:
    if mode == "off":
        return []
    if mode == "strict":
        hits = [m.group(1) for m in RE_KR_PHONE_STRICT.finditer(text)]
        return _unique_sorted(_normalize_010_phone(x) for x in hits)
    if mode == "loose":
        hits = [m.group(1) for m in RE_KR_PHONE_LOOSE.finditer(text)]
        return _unique_sorted(_normalize_010_phone(x) for x in hits)
    if mode == "context_required":
        hits = [m.group(1) for m in RE_KR_PHONE_CONTEXT.finditer(text)]
        return _unique_sorted(_normalize_010_phone(x) for x in hits)
    raise ValueError(f"Unknown phone mode: {mode}")


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

    # KR BizNo (context-based)
    biznos = _unique_sorted(m.group(1) for m in RE_KR_BIZNO_CONTEXT.finditer(text))

    # KR phone 010 (mode-based)
    phones = extract_kr_phones(text, phone_mode)

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
        kr_business_registration_numbers=biznos,
        kr_mobile_phones_010=phones,
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
        "kr_business_registration_numbers": res.kr_business_registration_numbers,
        "kr_mobile_phones_010": res.kr_mobile_phones_010,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", help="입력 파일 경로(없으면 stdin에서 읽음)")
    ap.add_argument("--pretty", action="store_true", help="JSON pretty print")
    ap.add_argument(
        "--phone-mode",
        choices=["off", "strict", "loose", "context_required"],
        default="off",
        help="KR 010 휴대폰 추출 모드",
    )
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