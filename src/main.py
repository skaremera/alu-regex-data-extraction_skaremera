"""
ALU Regex Data Extraction & Secure Validation
=============================================
Author : Junior Frontend Developer
Date   : 2024-06-10
Purpose: Extract and validate structured data from raw API text using regex.
         All input is treated as untrusted. Sensitive data is masked in output.

Security note
-------------
Input may contain SQL injection attempts, XSS payloads, HTTP response splitting,
or other hostile content. This program:
  1. Sanitises raw lines before matching (strips control characters).
  2. Validates matched values against strict allow-lists / deny-lists.
  3. Masks credit-card numbers in all output (PCI-DSS principle of least exposure).
  4. Rejects patterns that contain HTML/JS injection markers.
  5. Rejects URLs with embedded HTML angle brackets.
  6. Phone numbers are validated by digit-count range (E.164).
  7. Never eval()s or exec()s any content from the input file.
"""

import re
import json
import unicodedata
from pathlib import Path
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# PATHS
# ---------------------------------------------------------------------------
BASE_DIR    = Path(__file__).resolve().parent.parent
INPUT_FILE  = BASE_DIR / "input" / "raw-text.txt"
OUTPUT_FILE = BASE_DIR / "output" / "sample-output.json"

# ---------------------------------------------------------------------------
# SECURITY HELPERS
# ---------------------------------------------------------------------------

# Patterns that signal known injection payloads.
INJECTION_DENY_PATTERNS = re.compile(
    r"(<script|</script|javascript:|onerror=|onload=|<iframe|<img\s|"
    r"DROP\s+TABLE|INSERT\s+INTO|SELECT\s+\*|UNION\s+SELECT|'--|;\s*--|"
    r"document\.cookie|window\.location|fetch\(|eval\(|exec\()",
    re.IGNORECASE,
)

def sanitise_line(raw: str) -> str:
    """
    Remove non-printable control characters (null bytes, carriage returns used
    in HTTP response-splitting, ANSI escape sequences, etc.).
    Tabs are preserved. Unicode is NFC-normalised.
    """
    normalised = unicodedata.normalize("NFC", raw)
    return "".join(ch for ch in normalised
                   if unicodedata.category(ch)[0] != "C" or ch == "\t")


def is_safe(value: str) -> bool:
    """Return False if value contains a known injection marker."""
    return not INJECTION_DENY_PATTERNS.search(value)


def mask_card(number: str) -> str:
    """
    Mask all but the last four digits — PCI-DSS 3.3.
    Preserves the separator character used in the original (space or hyphen).
    """
    digits = re.sub(r"\D", "", number)
    visible = digits[-4:]
    sep = " " if " " in number else ("-" if "-" in number else "")

    if len(digits) == 16:
        return f"{'*' * 4}{sep}{'*' * 4}{sep}{'*' * 4}{sep}{visible}"
    elif len(digits) == 15:          # Amex 4-6-5
        return f"{'*' * 4} {'*' * 6} {visible[0]}{'*' * 0}{visible}"
    else:
        return ("*" * (len(digits) - 4)) + visible

# ---------------------------------------------------------------------------
# REGEX PATTERNS
# ---------------------------------------------------------------------------

# ---- 1. EMAIL (general) --------------------------------------------------
# Local part: alphanumeric, dots, hyphens, underscores, plus.
# No consecutive dots; no leading/trailing dot.
EMAIL_GENERAL = re.compile(
    r"""
    (?<![=@\w])          # not preceded by =, @ or word char (avoids mailto:/double-@ leakage)
    (
        [a-zA-Z0-9]      # local part must start with alphanumeric
        (?:[a-zA-Z0-9._+\-]*[a-zA-Z0-9])?   # middle + must end with alphanumeric
        @
        (?:[a-zA-Z0-9\-]+\.)+   # domain labels
        [a-zA-Z]{2,6}           # TLD
    )
    (?!\.)               # not followed immediately by a dot
    """,
    re.VERBOSE,
)

CONSECUTIVE_DOTS = re.compile(r"\.\.")   # rejects james..bond@ or domain..com

# ---- 2. ALU-SPECIFIC EMAIL VALIDATORS ------------------------------------
ALU_DOMAINS = {
    "staff":  re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9._\-]*[a-zA-Z0-9])?@alueducation\.com$"),
    "alumni": re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9._\-]*[a-zA-Z0-9])?@alumni\.alueducation\.com$"),
    "si":     re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9._\-]*[a-zA-Z0-9])?@si\.alueducation\.com$"),
}

def classify_alu_email(email: str) -> str | None:
    """Return the ALU category ('staff'|'alumni'|'si') or None."""
    if CONSECUTIVE_DOTS.search(email):
        return None
    for category, pattern in ALU_DOMAINS.items():
        if pattern.match(email):
            return category
    return None


# ---- 3. URL --------------------------------------------------------------
# http/https only. Host must have at least one dot (or be localhost).
# Path/query component excludes angle brackets (blocks embedded HTML injection).
URL_PATTERN = re.compile(
    r"""
    \b
    (
        https?://                          # scheme — http or https ONLY
        (?:
            (?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}   # domain
            |localhost
        )
        (?::\d{1,5})?                      # optional port
        (?:/[^\s<>"'{}|\\^`\[\]]*)?        # optional path/query (no angle brackets)
    )
    (?=[\s,\)"'\]]|$)                      # must be followed by whitespace or punctuation
    """,
    re.VERBOSE,
)


# ---- 4. PHONE NUMBERS ----------------------------------------------------
# Anchored to avoid matching plain date strings (YYYY-MM-DD) or card fragments.
# Pattern requires at least two digit groups separated by a recognised delimiter,
# or a leading + country code.
#
# Accepted formats (examples):
#   +250 788 123 456   +1 (415) 867-5309   +44 20 7946 0321
#   +49 30 901820      078-456-7890         0722-555-678
#   1-800-555-0199     +33 (0)1 42 86 83 26
#
# Key exclusions:
#   - 4-digit-only sequences (years)
#   - Sequences of only two digit groups (matches dates like 2024-06-10)
#   - Strings whose digit count falls outside 7–15 (E.164)
PHONE_PATTERN = re.compile(
    r"""
    (?<!\d)              # not preceded by digit
    (
        # International: leading + country code (always safe)
        \+\d{1,3}[\s\-]?
        (?:\(?\d{1,4}\)?[\s\-]?)?
        \d{2,4}[\s\-]?
        \d{2,4}
        (?:[\s\-]\d{2,4})*
        |
        # Local / North-American: must have at least 3 delimited groups
        \(?\d{3,4}\)?[\s\-]
        \d{3,4}[\s\-]
        \d{3,4}
        (?:[\s\-]\d{1,4})?
    )
    (?!\d)               # not followed by digit
    """,
    re.VERBOSE,
)

# Reject phone matches that look like partial card numbers (three groups of 4 digits)
CARD_FRAGMENT = re.compile(r"^\d{4}[\s\-]\d{4}[\s\-]\d{4}$")

def validate_phone(raw: str) -> bool:
    """Accept only if digit count is between 7 and 15 (E.164)."""
    digits = re.sub(r"\D", "", raw)
    return 7 <= len(digits) <= 15


# ---- 5. CREDIT CARD NUMBERS ----------------------------------------------
# Visa / MC / Discover: 16 digits (grouped 4-4-4-4 or unseparated).
# Amex: 15 digits (grouped 4-6-5 or unseparated).
# Separator must be uniform (all spaces OR all hyphens).
CARD_PATTERN = re.compile(
    r"""
    (?<!\d)
    (
        \d{4}[ ]\d{4}[ ]\d{4}[ ]\d{4}    # 16-digit space-separated
        | \d{4}-\d{4}-\d{4}-\d{4}         # 16-digit hyphen-separated
        | \d{4}[ ]\d{6}[ ]\d{5}           # Amex 4-6-5 space
        | \d{4}-\d{6}-\d{5}               # Amex 4-6-5 hyphen
        | \d{16}                           # 16-digit unseparated
        | \d{15}                           # 15-digit unseparated (Amex)
    )
    (?!\d)
    """,
    re.VERBOSE,
)

def luhn_check(number: str) -> bool:
    """
    ISO/IEC 7812 Luhn algorithm.
    Returns True if the card number passes the checksum.
    This is a necessary (not sufficient) validity test.
    """
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    odd_digits  = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10 == 0


# ---- 6. TIME (12-hour and 24-hour) ---------------------------------------
# 12-hour: 1:00 AM – 12:59 PM  (case-insensitive, space before AM/PM optional)
# 24-hour: 00:00 – 23:59  (no am/pm)
TIME_PATTERN = re.compile(
    r"""
    \b
    (
        (?:1[0-2]|0?[1-9]):[0-5]\d\s?[APap][Mm]   # 12-hour with AM/PM
        |
        (?:[01]\d|2[0-3]):[0-5]\d                   # 24-hour HH:MM
    )
    \b
    """,
    re.VERBOSE,
)

def validate_time(t: str) -> bool:
    """Secondary validation to ensure value is genuinely in range."""
    t = t.strip()
    if re.match(r"^(1[0-2]|0?[1-9]):[0-5]\d\s?[APap][Mm]$", t):
        return True
    if re.match(r"^([01]\d|2[0-3]):[0-5]\d$", t):
        return True
    return False


# ---- 7. HTML TAGS --------------------------------------------------------
# Matches opening, closing, and self-closing tags.
# Tag name must begin with a letter.
HTML_TAG_PATTERN = re.compile(
    r"<(/?)([a-zA-Z][a-zA-Z0-9\-]*)(\s[^<>]*)?(/)?>",
    re.IGNORECASE,
)

DANGEROUS_TAGS = re.compile(
    r"^(script|iframe|object|embed|form|svg|math|template|link|meta|base)$",
    re.IGNORECASE,
)
DANGEROUS_ATTR = re.compile(
    r"(on\w+=|javascript:|srcdoc=|data:text/html)",
    re.IGNORECASE,
)

def classify_html_tag(tag_string: str) -> str:
    """Return 'safe', 'dangerous', or 'suspicious'."""
    m = re.match(r"<(/?)([a-zA-Z][a-zA-Z0-9\-]*)(\s[^<>]*)?(/)?>", tag_string)
    if not m:
        return "suspicious"
    _, tag_name, attrs, _ = m.groups()
    if DANGEROUS_TAGS.match(tag_name):
        return "dangerous"
    if attrs and DANGEROUS_ATTR.search(attrs):
        return "suspicious"
    return "safe"


# ---- 8. HASHTAGS ---------------------------------------------------------
# Must start with a letter after #. Pure-numeric hashtags are rejected.
HASHTAG_PATTERN = re.compile(
    r"""
    (?<![&\w])           # not preceded by & (avoids HTML entities)
    \#
    ([a-zA-Z]            # first char must be a letter
    [a-zA-Z0-9_]*)       # rest: letters, digits, underscores
    \b
    """,
    re.VERBOSE,
)


# ---- 9. CURRENCY AMOUNTS -------------------------------------------------
# $, €, £ — leading or trailing symbol.
CURRENCY_PATTERN = re.compile(
    r"""
    (
        [\$€£]
        \d{1,3}(?:,\d{3})*(?:\.\d{2})?   # leading symbol + amount
        |
        \d{1,3}(?:,\d{3})*(?:\.\d{2})?
        \s?[\$€£]                          # trailing symbol
    )
    """,
    re.VERBOSE,
)

# ---------------------------------------------------------------------------
# MAIN EXTRACTION ENGINE
# ---------------------------------------------------------------------------

def extract_all(text: str) -> dict:
    results = {
        "emails": {
            "alu_staff":  [],
            "alu_alumni": [],
            "alu_si":     [],
            "other":      [],
            "rejected":   [],
        },
        "urls":         {"valid": [], "rejected": []},
        "phones":       {"valid": []},
        "credit_cards": {"valid": [], "rejected": []},   # cards masked (PCI-DSS)
        "times":        {"valid": [], "rejected": []},
        "html_tags":    {"safe": [], "dangerous": [], "suspicious": []},
        "hashtags":     {"valid": [], "rejected": []},
        "currency":     {"valid": []},
        "meta": {
            "extracted_at":    datetime.now(timezone.utc).isoformat(),
            "source_file":     str(INPUT_FILE),
            "lines_processed": 0,
        },
    }

    # Seen-sets prevent duplicate entries across lines
    seen = {k: set() for k in
            ("emails", "urls", "phones", "cards", "times", "tags", "hashes", "curr")}

    lines = text.splitlines()
    results["meta"]["lines_processed"] = len(lines)

    for raw_line in lines:
        line = sanitise_line(raw_line)

        # ---- EMAILS -------------------------------------------------------
        for m in EMAIL_GENERAL.finditer(line):
            email = m.group(1)
            if email in seen["emails"]:
                continue
            seen["emails"].add(email)

            if not is_safe(email):
                results["emails"]["rejected"].append(
                    {"value": "[REDACTED — injection attempt]", "reason": "injection marker"}
                )
                continue
            if CONSECUTIVE_DOTS.search(email):
                results["emails"]["rejected"].append(
                    {"value": email, "reason": "consecutive dots"}
                )
                continue

            alu_cat = classify_alu_email(email)
            if alu_cat:
                results["emails"][f"alu_{alu_cat}"].append(email)
            else:
                results["emails"]["other"].append(email)

        # ---- URLS ---------------------------------------------------------
        # Security: skip URL extraction entirely if the line itself is hostile.
        # This catches URLs embedded inside <script>, <iframe onerror=...>, etc.
        line_is_safe_for_urls = is_safe(line)
        for m in URL_PATTERN.finditer(line):
            url = m.group(1).rstrip(".,;:)")   # strip trailing punctuation artefacts
            if url in seen["urls"]:
                continue
            seen["urls"].add(url)

            if not line_is_safe_for_urls or not is_safe(url) or "<" in url or ">" in url:
                results["urls"]["rejected"].append(
                    {"value": "[REDACTED]", "reason": "injection marker in URL"}
                )
            else:
                results["urls"]["valid"].append(url)

        # ---- PHONES -------------------------------------------------------
        for m in PHONE_PATTERN.finditer(line):
            phone = m.group(1).strip()
            if not phone or phone in seen["phones"]:
                continue
            if not validate_phone(phone):
                continue
            if CARD_FRAGMENT.match(phone):   # reject partial card-number fragments
                continue
            seen["phones"].add(phone)
            results["phones"]["valid"].append(phone)

        # ---- CREDIT CARDS ------------------------------------------------
        for m in CARD_PATTERN.finditer(line):
            raw_card = m.group(1)
            if raw_card in seen["cards"]:
                continue
            seen["cards"].add(raw_card)

            if not is_safe(raw_card):
                results["credit_cards"]["rejected"].append(
                    {"masked": "[REDACTED]", "reason": "injection in card field"}
                )
                continue

            if luhn_check(raw_card):
                results["credit_cards"]["valid"].append(
                    {"masked": mask_card(raw_card), "luhn_pass": True}
                )
            else:
                results["credit_cards"]["rejected"].append(
                    {"masked": mask_card(raw_card), "reason": "failed Luhn check"}
                )

        # ---- TIMES --------------------------------------------------------
        for m in TIME_PATTERN.finditer(line):
            t = m.group(1).strip()
            if t in seen["times"]:
                continue
            seen["times"].add(t)
            if validate_time(t):
                results["times"]["valid"].append(t)
            else:
                results["times"]["rejected"].append(
                    {"value": t, "reason": "out of valid range"}
                )

        # ---- HTML TAGS ----------------------------------------------------
        for m in HTML_TAG_PATTERN.finditer(line):
            tag_str = m.group(0)
            if tag_str in seen["tags"]:
                continue
            seen["tags"].add(tag_str)
            category = classify_html_tag(tag_str)
            results["html_tags"][category].append(tag_str)

        # ---- HASHTAGS -----------------------------------------------------
        for m in HASHTAG_PATTERN.finditer(line):
            hashtag = "#" + m.group(1)
            if hashtag in seen["hashes"]:
                continue
            seen["hashes"].add(hashtag)
            if not is_safe(hashtag):
                results["hashtags"]["rejected"].append(
                    {"value": "[REDACTED]", "reason": "injection attempt"}
                )
            else:
                results["hashtags"]["valid"].append(hashtag)

        # ---- CURRENCY -----------------------------------------------------
        for m in CURRENCY_PATTERN.finditer(line):
            amount = m.group(1).strip()
            if not amount or amount in seen["curr"]:
                continue
            seen["curr"].add(amount)
            results["currency"]["valid"].append(amount)

    return results


# ---------------------------------------------------------------------------
# CONSOLE SUMMARY
# ---------------------------------------------------------------------------

def print_summary(r: dict) -> None:
    emails   = r["emails"]
    urls     = r["urls"]
    phones   = r["phones"]
    cards    = r["credit_cards"]
    times    = r["times"]
    tags     = r["html_tags"]
    hashes   = r["hashtags"]
    currency = r["currency"]
    meta     = r["meta"]

    bar = "=" * 70
    print(f"\n{bar}")
    print("  ALU DATA EXTRACTION — SUMMARY REPORT")
    print(f"  Extracted at : {meta['extracted_at']}")
    print(f"  Source file  : {meta['source_file']}")
    print(f"  Lines parsed : {meta['lines_processed']}")
    print(bar)

    print(f"\n📧  EMAILS")
    print(f"   ALU Staff   ({len(emails['alu_staff'])}): {emails['alu_staff']}")
    print(f"   ALU Alumni  ({len(emails['alu_alumni'])}): {emails['alu_alumni']}")
    print(f"   ALU SI      ({len(emails['alu_si'])}): {emails['alu_si']}")
    print(f"   Other valid ({len(emails['other'])}): {emails['other']}")
    print(f"   Rejected    ({len(emails['rejected'])}): {[r['reason'] for r in emails['rejected']]}")

    print(f"\n🌐  URLS")
    print(f"   Valid    ({len(urls['valid'])}): {urls['valid']}")
    print(f"   Rejected ({len(urls['rejected'])}): {[r['reason'] for r in urls['rejected']]}")

    print(f"\n📞  PHONE NUMBERS")
    print(f"   Valid ({len(phones['valid'])}): {phones['valid']}")

    print(f"\n💳  CREDIT CARDS  [masked — PCI-DSS 3.3]")
    print(f"   Luhn-valid ({len(cards['valid'])}): {[c['masked'] for c in cards['valid']]}")
    print(f"   Rejected   ({len(cards['rejected'])}): "
          f"{[{'masked': c['masked'], 'reason': c['reason']} for c in cards['rejected']]}")

    print(f"\n🕐  TIMES")
    print(f"   Valid    ({len(times['valid'])}): {times['valid']}")
    print(f"   Rejected ({len(times['rejected'])}): {times['rejected']}")

    print(f"\n🏷️   HTML TAGS")
    print(f"   Safe       ({len(tags['safe'])}): {tags['safe']}")
    print(f"   Dangerous  ({len(tags['dangerous'])}): {tags['dangerous']}")
    print(f"   Suspicious ({len(tags['suspicious'])}): {tags['suspicious']}")

    print(f"\n#️⃣   HASHTAGS")
    print(f"   Valid    ({len(hashes['valid'])}): {hashes['valid']}")
    print(f"   Rejected ({len(hashes['rejected'])}): {hashes['rejected']}")

    print(f"\n💰  CURRENCY AMOUNTS")
    print(f"   Found ({len(currency['valid'])}): {currency['valid']}")

    print(f"\n{bar}\n")


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

def main():
    if not INPUT_FILE.exists():
        print(f"[ERROR] Input file not found: {INPUT_FILE}")
        return

    raw_text = INPUT_FILE.read_text(encoding="utf-8")
    results  = extract_all(raw_text)

    print_summary(results)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[✓] JSON output written to: {OUTPUT_FILE}\n")


if __name__ == "__main__":
    main()
