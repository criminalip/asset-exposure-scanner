# sample.py
# -*- coding: utf-8 -*-

import json
from parse_regex import extract_all, as_dict


def main():
    # 다양한 케이스를 섞은 멀티라인 샘플(개행 포함)
    sample_text = r"""
[HTTP Headers]
Server: nginx/1.24.0
X-Powered-By: PHP/8.2
Contact: security-team@example.com
Support: helpdesk@corp.co.kr

[HTML]
<html>
<head>
  <meta name="google-site-verification" content="QqWErTyUiOpASDfGhJKlZxCvBnM1234567890" />
  <script async src="https://www.googletagmanager.com/gtm.js?id=GTM-AB12CDE"></script>
  <script>
    // GA4
    gtag('config', 'G-1A2B3C4D5E');
    // UA (legacy)
    ga('create', 'UA-1234567-8', 'auto');
    // Google Ads
    gtag('config', 'AW-123456789');
  </script>

  <!-- facebook pixel -->
  <script>
    !function(f,b,e,v,n,t,s){/* ... */};
    fbq('init', '123456789012345');
    fbq('track', 'PageView');
  </script>

  <!-- reCAPTCHA -->
  <script src="https://www.google.com/recaptcha/api.js?render=6Lc_aAABBBcccDDD___EEEfffGGGhhhIIIjjjKKKlllmmmNNN"></script>
</head>

<body>
  문의: 010-1234-5678
  전화: 010 2345 6789
  (이건 하이픈 없이) 01034567890

  텔레그램: https://t.me/CriminalIP_Official
  다른 텔레그램: telegram.me/Some_User123

  사업자등록번호: 123-45-67890
  Biz No: 234-56-78901

  이메일(주석): dev.ops+alerts@security-company.io

  아래는 @username 형태라서(서비스 불명) 텔레그램으로는 안 잡히는게 정상:
  @not_sure_username

  랜덤 숫자열(전화 오진 방지용): 010-9999-8888-7777 (이건 정상 번호 아님)
</body>
</html>
"""

    # phone_mode별로 결과 비교
    for mode in ["off", "strict", "loose", "context_required"]:
        res = extract_all(sample_text, phone_mode=mode)
        payload = as_dict(res)
        print("\n" + "=" * 80)
        print(f"phone_mode = {mode}")
        print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()