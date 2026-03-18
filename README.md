# Privacy Exposure Scanner

Privacy Exposure Scanner is a lightweight cybersecurity utility for **structuring identifiers from Criminal IP Asset Search results** and analyzing **asset exposure context using the latest confirmed port records**.

Criminal IP Asset Search responses may include **open port data** alongside unstructured content such as banners, HTML fragments, SSL information, meta tags, and embedded scripts. These fields often contain operational or tracking-related identifiers, but because they are not structured, they are difficult to analyze directly.

This project extracts **format-defined identifiers** using conservative regular expressions and structures them for reliable **exposure analysis, threat intelligence enrichment, and reconnaissance data investigation**, while minimizing false positives.

---

## Project Structure

```
.
├── parse_regex.py
├── sample.py
├── cip_privacy_check.py
└── README.md
```

---

## What It Does

- Extracts **format-stable identifiers** from banner and SSL fields  
- Uses conservative and context-aware regular expressions  
- Deduplicates ports by `(open_port_no, protocol)`  
- Retains only the most recent record using `confirmed_time`  
- Structures **exposure-related signals from Asset Search results**

Criminal IP API responses may include **historical records for the same port**.  
Evaluating port exposure without temporal filtering may produce inaccurate conclusions.

This tool keeps only the **latest confirmed state per `(open_port_no, protocol)`** using `confirmed_time`.

Ports without matched identifiers are excluded from the final output to reduce unnecessary noise in structured results.

---

## Supported Identifier Types

The current implementation extracts identifiers that have clearly defined formats:

- Email addresses  
- Google Analytics IDs (UA / GA4)  
- Google Tag Manager IDs (GTM)  
- Google Ads IDs (AW)  
- Facebook Pixel IDs  
- reCAPTCHA site keys  
- Telegram URLs (`t.me`, `telegram.me`)   

Only identifiers with **stable formats** are extracted to avoid excessive false positives.

---

## API Key Setup

Create a file named:

```
criminalip_api_key.json
```

Add the following content:

```json
{
  "api_key": "YOUR_CRIMINALIP_API_KEY"
}
```

Ensure that this file is **not committed to version control**.

---

## ⚡Usage

### 1. Test Regex Extraction

```
python sample.py
```

This script demonstrates how identifier extraction behaves with different **phone number extraction modes**.

---

### 2. Run Privacy Exposure Check

```
python cip_privacy_check.py --ip <TARGET_IP>
```

Optional arguments:

```
--pretty
--phone-mode off | strict | loose | context_required
--rawfile <path>
--out <file>
--outdir <directory>
```

**Options**

`--rawfile`  
Use a saved raw JSON response instead of calling the Criminal IP API.

`--out`  
Specify the output JSON file.

`--outdir`  
Directory where output files will be stored (default: `out_privacy`).

`--phone-mode`  
Deprecated compatibility option retained for older integrations.
It is currently passed through for compatibility and does not affect extraction behavior in the current implementation.

---

## Output Behavior

- Only ports containing matched identifiers are included  
- Empty identifier categories are removed  
- Ports are deduplicated by `(open_port_no, protocol)`  
- Only the most recent `confirmed_time` record is evaluated  
- Results are written as **UTF-8 encoded JSON**

---

## Design Principles

- Deterministic logic over heuristic interpretation  
- Conservative extraction to minimize false positives  
- Clear separation between raw Asset Search data and structured analysis results  
- Reproducible exposure analysis using the latest confirmed port state

---

## Intended Use

This project is intended for:

- **Asset exposure analysis**
- **Threat intelligence enrichment**
- **Reconnaissance data investigation**
- **Authorized external asset review**

---

## Disclaimer

This tool is provided for **defensive security research and authorized asset analysis only**.  
Users are responsible for complying with applicable laws and regulations when using this software.
