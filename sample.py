# sample.py
# -*- coding: utf-8 -*-

import json
from parse_regex import extract_all, as_dict


def main():
    # Multiline sample containing various identifier patterns
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
  Telegram: https://t.me/CriminalIP_Official
  Another Telegram: telegram.me/Some_User123

  Email in comment: dev.ops+alerts@security-company.io

  The following is only an @username format with no confirmed service context,
  so it is expected not to be detected as Telegram:
  @not_sure_username
</body>
</html>
"""

    res = extract_all(sample_text)
    payload = as_dict(res)
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
