# cip_privacy_check.py
# -*- coding: utf-8 -*-
"""
CIP Privacy Check (banner regex scan)

요구사항(대표님 요청대로):
- parse_regex.py / sample.py 는 그대로 둠
- cip_privacy_check.py 만 수정
- IP를 인자로 받아 Criminal IP /v1/asset/ip/report 호출
- "모든 포트"에 대해 (있는 경우에만) banner + ssl_info_raw 텍스트를 모아 정규식 파싱
- 결과가 "있는 것만" 최종 JSON에 기록 (매칭 없는 포트는 최종 파일에서 제외)
- criminalip_api_key.json 그대로 사용

추가:
- --rawfile 옵션: API 호출 없이 로컬 raw json으로 테스트 가능
- --phone-mode: parse_regex.py의 phone_mode 그대로 전달

실행:
  python cip_privacy_check.py --ip 1.1.1.1
  python cip_privacy_check.py --ip 1.1.1.1 --out out_privacy/1.1.1.1_privacy.json
  python cip_privacy_check.py --rawfile 1.1.1.1.raw.json --out out_privacy/1.1.1.1_privacy.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

# 기존 parse_regex.py 인터페이스 그대로 사용
import parse_regex


API_URL = "https://api.criminalip.io/v1/asset/ip/report"


def _parse_with_parse_regex(text: str, phone_mode: str) -> Dict[str, Any]:
    """
    parse_regex.py 버전에 따라 인터페이스가 다를 수 있습니다.
    - 확장 버전: extract_all(text, phone_mode) + as_dict()
    - 간단 버전: parse_text(text)
    둘 다 지원합니다.
    """
    if hasattr(parse_regex, "extract_all") and hasattr(parse_regex, "as_dict"):
        parsed = parse_regex.extract_all(text, phone_mode=phone_mode)
        return parse_regex.as_dict(parsed)
    if hasattr(parse_regex, "parse_text"):
        return parse_regex.parse_text(text)
    raise ImportError("parse_regex.py must provide either (extract_all+as_dict) or parse_text()")



# --------------------------
# Key file (as-is)
# --------------------------
def load_api_key(path: str) -> str:
    if not os.path.exists(path):
        raise FileNotFoundError(f"API key file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    key = (
        data.get("api_key")
        or data.get("API_KEY")
        or data.get("criminalip_api_key")
        or data.get("key")
    )
    if not key or not isinstance(key, str):
        raise ValueError("criminalip_api_key.json must contain a string field like {'api_key':'...'}")
    return key.strip()


def fetch_ip_report(api_key: str, ip: str, timeout: int = 30) -> Dict[str, Any]:
    headers = {"x-api-key": api_key, "Accept": "application/json"}
    params = {"ip": ip, "full": "true"}
    r = requests.get(API_URL, headers=headers, params=params, timeout=timeout)
    if r.status_code != 200:
        msg = (r.text or "")[:800]
        raise RuntimeError(f"HTTP {r.status_code} from CriminalIP API: {msg}")
    return r.json()


def extract_ports(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Common schema:
      report["port"] = {"count": N, "data": [ {...}, ... ]}
    """
    port_block = report.get("port")
    if isinstance(port_block, dict):
        data = port_block.get("data")
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
    return []


def _safe_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, ensure_ascii=False)
    except Exception:
        return str(v)


def _drop_empty_lists(d: Dict[str, Any]) -> Dict[str, Any]:
    """
    parse_regex.as_dict()는 모든 키를 포함하며 값이 []일 수 있음.
    "있는 것만" 남기기 위해 빈 리스트는 제거.
    """
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, list) and len(v) == 0:
            continue
        out[k] = v
    return out


def _to_epoch_seconds(v: Any) -> float:
    """Best-effort parse for confirmed_time.
    Supports:
      - int/float epoch seconds or milliseconds
      - numeric strings
      - ISO-8601 strings (with or without Z)
    Returns 0.0 when unknown.
    """
    if v in (None, "", [], {}):
        return 0.0

    # numeric types
    if isinstance(v, (int, float)):
        x = float(v)
        # heuristic: milliseconds
        if x > 10_000_000_000:  # ~2286-11-20 in seconds
            x = x / 1000.0
        return x if x > 0 else 0.0

    # numeric string
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return 0.0
        try:
            x = float(s)
            if x > 10_000_000_000:
                x = x / 1000.0
            return x if x > 0 else 0.0
        except Exception:
            pass

        # ISO string
        s2 = s.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s2)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return 0.0

    return 0.0


def dedupe_latest_ports(ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Criminal IP 포트 목록에는 과거 스캔 이력이 함께 섞여 들어오는 경우가 있습니다.
    동일 포트(및 프로토콜) 항목이 여러 개라면, confirmed_time 기준으로 가장 최신 1개만 남깁니다.
    confirmed_time 파싱이 실패하면, 리스트에서 더 뒤에 있는 항목을 '최신'으로 간주합니다.
    """
    best: Dict[tuple, tuple] = {}  # key -> (epoch, idx, port_dict)

    for i, p in enumerate(ports):
        if not isinstance(p, dict):
            continue
        port_no = p.get("open_port_no")
        proto = p.get("protocol") or ""  # tcp/udp etc
        key = (port_no, proto)

        t = _to_epoch_seconds(p.get("confirmed_time"))
        cur = (t, i)
        prev = best.get(key)
        if prev is None or cur > (prev[0], prev[1]):
            best[key] = (t, i, p)

    # keep original order of the chosen (latest) items for stable output
    chosen = [v[2] for v in sorted(best.values(), key=lambda x: x[1])]
    return chosen


def analyze_report(report: Dict[str, Any], phone_mode: str) -> Dict[str, Any]:
    ports_all = extract_ports(report)
    ports_total = len(ports_all)

    # 같은 포트(과거 이력 포함)는 가장 최신 1개만 검사
    ports = dedupe_latest_ports(ports_all)

    matched_ports: List[Dict[str, Any]] = []

    for p in ports:
        banner = _safe_str(p.get("banner")).strip()
        ssl_raw = _safe_str(p.get("ssl_info_raw")).strip()

        # "있는 텍스트만" 합침
        if not banner and not ssl_raw:
            continue

        combined = banner
        if ssl_raw:
            combined = (combined + "\n\n" + ssl_raw).strip() if combined else ssl_raw

        # 정규식 추출
        findings_raw = _parse_with_parse_regex(combined, phone_mode=phone_mode)
        findings = _drop_empty_lists(findings_raw)

        # "있는 것만": findings가 비어있으면 이 포트는 최종 결과에서 제외
        if not findings:
            continue

        # 포트 레코드도 "있는 필드만" 담기
        entry: Dict[str, Any] = {
            "open_port_no": p.get("open_port_no"),
            "protocol": p.get("protocol"),
            "socket": p.get("socket"),
            "port_status": p.get("port_status"),
            "matches": findings,
        }

        # optional fields (존재할 때만)
        for key in ("app_name", "app_version", "confirmed_time"):
            v = p.get(key)
            if v not in (None, "", [], {}):
                entry[key] = v

        matched_ports.append(entry)

    out: Dict[str, Any] = {
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "phone_mode": phone_mode,
        "ports_total": ports_total,
        "ports_scanned": len(ports),  # unique ports after de-dup

        "ports_matched": len(matched_ports),
        "matched_ports": matched_ports,  # 이미 match 있는 포트만 포함
    }

    # best-effort IP
    if isinstance(report.get("ip"), str):
        out["ip"] = report["ip"]
    elif isinstance(report.get("ip_address"), str):
        out["ip"] = report["ip_address"]

    return out


def ensure_dir(path: str) -> None:
    if not path:
        return
    os.makedirs(path, exist_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="CIP banner privacy/unique ID regex checker (minimal output)")
    ap.add_argument("--ip", help="Target IP address (API call)")
    ap.add_argument("--keyfile", default="criminalip_api_key.json", help="API key json file path")
    ap.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds")

    ap.add_argument("--rawfile", default=None, help="Use local raw json instead of calling API (test)")
    ap.add_argument("--out", default=None, help="Output json file path")
    ap.add_argument("--outdir", default="out_privacy", help="Output directory when --out not specified")

    ap.add_argument(
        "--phone-mode",
        choices=["off", "strict", "loose", "context_required"],
        default="context_required",
        help="Pass-through to parse_regex.py phone_mode",
    )
    args = ap.parse_args()

    try:
        if not args.rawfile and not args.ip:
            raise ValueError("Either --ip (API call) or --rawfile (local test) is required")

        if args.rawfile:
            with open(args.rawfile, "r", encoding="utf-8") as f:
                report = json.load(f)
            ip_for_name = args.ip or report.get("ip") or report.get("ip_address") or "unknown_ip"
        else:
            api_key = load_api_key(args.keyfile)
            report = fetch_ip_report(api_key, args.ip, timeout=args.timeout)
            ip_for_name = args.ip

        result = analyze_report(report, phone_mode=args.phone_mode)

        # output path
        out_path = args.out
        if not out_path:
            ensure_dir(args.outdir)
            safe_ip = str(ip_for_name).replace(":", "_")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_path = os.path.join(args.outdir, f"{safe_ip}_privacy_{ts}.json")

        ensure_dir(os.path.dirname(out_path))
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        print(f"[OK] saved: {out_path} (ports_matched={result.get('ports_matched', 0)})")
        return 0

    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
