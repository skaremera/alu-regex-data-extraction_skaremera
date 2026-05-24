# ALU Regex Data Extraction & Secure Validation

A Python program that extracts and validates eight types of structured data
from raw, production-style text using regular expressions. All input is
treated as untrusted, and security considerations are applied at every step.

---

## Project Structure

```
alu-regex-data-extraction_darcy113/
├── input/
│   └── raw-text.txt        ← Realistic messy input (HR records, payments, HTML, etc.)
├── src/
│   └── main.py             ← Extraction engine with all regex patterns + security logic
├── output/
│   └── sample-output.json  ← Structured JSON output from a full run
└── README.md
```

---

## Requirements

- Python 3.10 or higher
- No third-party libraries — only the Python standard library:
  - `re` — regular expressions
  - `json` — structured output
  - `unicodedata` — input sanitisation
  - `pathlib` — file path handling
  - `datetime` — timestamp generation

---

## How to Run

```bash
# From the project root directory:
python src/main.py
```

The program will:
1. Read `input/raw-text.txt`
2. Print a summary report to the console
3. Write full structured results to `output/sample-output.json`

---

## Data Types Extracted

| # | Type | Details |
|---|------|---------|
| 1 | **Email addresses** | General + ALU-specific domain validation |
| 2 | **URLs** | `http`/`https` only; injection-containing lines skipped |
| 3 | **Phone numbers** | E.164 (7–15 digits); international and local formats |
| 4 | **Credit card numbers** | Visa, MC, Amex, Discover; Luhn-checked; masked in output |
| 5 | **Time (12h & 24h)** | `09:00 AM`, `14:00` etc.; invalid times rejected |
| 6 | **HTML tags** | Classified as safe / dangerous / suspicious |
| 7 | **Hashtags** | Must start with a letter; pure-numeric tags rejected |
| 8 | **Currency amounts** | `$`, `€`, `£`; leading or trailing symbol |

---

## ALU-Specific Email Validation

Three domain patterns are validated independently using dedicated regex patterns:

| Category | Domain | Example |
|----------|--------|---------|
| Staff    | `@alueducation.com` | `amara.diallo@alueducation.com` |
| Alumni   | `@alumni.alueducation.com` | `tunde.oke@alumni.alueducation.com` |
| SI       | `@si.alueducation.com` | `lena.fischer@si.alueducation.com` |

All three patterns additionally reject:
- Addresses with no local part (e.g. `@alueducation.com`)
- Consecutive dots anywhere (e.g. `james..bond@alueducation.com`)
- Double `@` signs (e.g. `noreply@@alueducation.com`)
- Any value containing an injection marker

---

## Key Functions in `main.py`

| Function | Purpose |
|----------|---------|
| `sanitise_line(raw)` | Strips control characters from every line before processing |
| `is_safe(value)` | Checks extracted value against injection deny-list |
| `mask_card(number)` | Masks all but last 4 digits of a card number (PCI-DSS) |
| `classify_alu_email(email)` | Returns ALU category or None for non-ALU emails |
| `luhn_check(number)` | Validates card numbers using the ISO/IEC 7812 algorithm |
| `validate_phone(raw)` | Ensures digit count is within E.164 range (7–15) |
| `validate_time(t)` | Secondary check that time values are genuinely in range |
| `classify_html_tag(tag)` | Labels each HTML tag as safe, dangerous, or suspicious |
| `extract_all(text)` | Main engine — runs all extractors over the full input |
| `print_summary(results)` | Prints a human-readable report to the console |
| `main()` | Entry point — reads input, runs extraction, writes JSON |

---

## Security Design

### 1. Input Sanitisation
Every line is passed through `sanitise_line()` before pattern matching.
This strips all Unicode control characters including null bytes and carriage
returns, which are used in HTTP response-splitting and null-byte injection attacks.

### 2. Injection Deny-List
`is_safe(value)` applies a deny-list regex to every extracted value before
accepting it. Rejected markers include:

- **XSS vectors:** `<script`, `onerror=`, `javascript:`, `<iframe`
- **SQL injection:** `DROP TABLE`, `UNION SELECT`, `'--`, `;--`
- **Code execution:** `eval(`, `exec(`, `fetch(`
- **Data exfiltration:** `document.cookie`, `window.location`

### 3. Context-Aware URL Filtering
URLs are not extracted from lines that contain injection markers at all.
This catches URLs embedded inside `<script>fetch(...)` or `<iframe onerror=...>`
even when the URL substring itself looks clean.

### 4. Credit Card Masking (PCI-DSS 3.3)
Card numbers are **never stored or displayed in plain text**.
`mask_card()` replaces all but the last four digits with `*`:

```
4111 1111 1111 1111  →  **** **** **** 1111
5500-0000-0000-0004  →  ****-****-****-0004
```

### 5. Luhn Algorithm Validation
All matched card candidates are run through the ISO/IEC 7812 Luhn checksum.
Cards that fail (e.g. `9999 9999 9999 9999`) are moved to the `rejected` list.

### 6. Phone Number Validation
After regex matching, digit count is verified to be within the E.164 range
(7–15 digits). A secondary filter (`CARD_FRAGMENT`) rejects strings matching
the pattern `NNNN NNNN NNNN` which are partial card numbers, not phone numbers.

### 7. HTML Tag Classification
Every matched HTML tag is classified as:
- **safe** — standard display tags (`<p>`, `<h1>`, `<strong>`, etc.)
- **dangerous** — `<script>`, `<iframe>`, `<object>`, `<embed>`, etc.
- **suspicious** — any tag with an `on*=` event handler or `javascript:` href

### 8. No Code Evaluation
The program never calls `eval()`, `exec()`, `subprocess`, or any dynamic
code runner on input content. All input is treated strictly as data.

---

## Sample Output (excerpt)

```json
{
  "emails": {
    "alu_staff": [
      "records@alueducation.com",
      "amara.diallo@alueducation.com",
      "billing@alueducation.com"
    ],
    "alu_alumni": ["tunde.oke@alumni.alueducation.com"],
    "alu_si": ["lena.fischer@si.alueducation.com"],
    "other": ["info@partner-university.edu"],
    "rejected": [
      {"value": "james..bond@alueducation.com", "reason": "consecutive dots"},
      {"value": "[REDACTED — injection attempt]", "reason": "injection marker"}
    ]
  },
  "credit_cards": {
    "valid": [
      {"masked": "**** **** **** 1111", "luhn_pass": true},
      {"masked": "****-****-****-0004", "luhn_pass": true}
    ],
    "rejected": [
      {"masked": "**** **** **** 9999", "reason": "failed Luhn check"}
    ]
  },
  "html_tags": {
    "safe": ["<h1>", "<p>", "<strong>", "<br/>"],
    "dangerous": ["<script>", "<iframe src=\"https://phishing.example.com\">"],
    "suspicious": ["<img src=\"x\" onerror=\"...\">"]
  },
  "meta": {
    "extracted_at": "2024-06-10T08:00:00+00:00",
    "source_file": ".../input/raw-text.txt",
    "lines_processed": 151
  }
}
```

---

## What the Input File Contains

`input/raw-text.txt` is modelled on a real-world internal communications
digest. It intentionally includes:

- Valid and invalid ALU staff, alumni, and SI email addresses
- Payment transaction records with real and fake credit card numbers
- Curated resource URLs alongside malformed and injection-containing URLs
- Event schedules with 12-hour and 24-hour times (including one invalid time)
- Phone numbers in international, North-American, and local African formats
- Raw HTML fragments from a CMS, including dangerous and suspicious tags
- Social media hashtags with edge cases (empty, numeric-only)
- Currency amounts in USD, EUR, and GBP
- Deliberate injection payloads (XSS, SQL injection, HTTP response-splitting,
  card-field comment injection) to verify the security filters work correctly
