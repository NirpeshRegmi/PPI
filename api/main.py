import gc
import io
import re
import base64
from typing import List

import usaddress
import docx
from docx import Document
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import openpyxl
import pdfplumber
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI(title="Transcend PII Processor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class GCMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        gc.collect()
        return response

app.add_middleware(GCMiddleware)

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

PII_ENTITIES = [
    "PERSON",
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "LOCATION",
    "US_SSN",
    "US_ITIN",
    "US_DRIVER_LICENSE",
    "US_PASSPORT",
    "US_BANK_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "URL",
    "DATE_TIME",
    "NRP",
    "MEDICAL_LICENSE",
    "CRYPTO",
]

DOLLAR_RE = re.compile(r'\$[\d,]+(?:\.\d+)?(?:[KkMmBb])?')
PERCENT_RE = re.compile(r'\b\d+(?:\.\d+)?%')
TAX_DATE_RE = re.compile(
    r'\b(?:20[0-2]\d)\b'
    r'|\b(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\d|3[01])/(?:20[0-2]\d)\b'
    r'|\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?'
    r'|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)'
    r'\s+(?:20[0-2]\d)\b'
    r'|\bQ[1-4]\s+(?:20[0-2]\d)\b',
    re.IGNORECASE
)
FINANCIAL_PATTERNS = [DOLLAR_RE, PERCENT_RE, TAX_DATE_RE]


def shield_financials(text: str) -> tuple[str, dict]:
    placeholder_map = {}
    counter = [0]

    def replace(m):
        token = f"__FIN_{counter[0]}__"
        placeholder_map[token] = m.group(0)
        counter[0] += 1
        return token

    for pattern in FINANCIAL_PATTERNS:
        text = pattern.sub(replace, text)
    return text, placeholder_map


def restore_financials(text: str, placeholder_map: dict) -> str:
    for token, original in placeholder_map.items():
        text = text.replace(token, original)
    return text


# ---------------------------------------------------------------------------
# Address redaction — three-layer approach
#
# Layer 1: LOOSE_ADDRESS_RE  — broad candidate finder (high recall, low precision)
#           Catches numeric-prefix + street-type patterns regardless of casing.
#
# Layer 2: usaddress.tag()   — CRF-based validator applied to each candidate.
#           Confirms the span really is a US address and expands it if needed.
#           Falls back gracefully if usaddress raises RepeatedLabelError.
#
# Layer 3: ZIP_RE            — standalone ZIP codes that slipped through layers 1/2.
#
# IMPORTANT: Address redaction now runs on the *restored* text (after
# financials are put back), so tokenised placeholders like __FIN_0__ never
# interfere with the address regex.
# ---------------------------------------------------------------------------

# Loose finder: number + optional direction + word(s) + street suffix.
# re.IGNORECASE handles ALL-CAPS PDFs and lower-case prose.
LOOSE_ADDRESS_RE = re.compile(
    r'\b\d{1,6}'                                    # house number
    r'(?:\s+[NSEWnsew]\.?)?\s+'                     # optional directional
    r'[A-Za-z0-9]+(?:\s+[A-Za-z0-9]+){0,4}\s+'     # street name (1–5 words)
    r'(?:street|st|avenue|ave|boulevard|blvd|road|rd|drive|dr|lane|ln'
    r'|court|ct|circle|cir|place|pl|way|wy|terrace|ter|trail|trl'
    r'|highway|hwy|parkway|pkwy|square|sq|loop|lp|run|path|row'
    r'|alley|aly|crossing|xing)\.?'                 # street type
    r'(?:\s+(?:apt|suite|ste|unit|#)\s*[A-Za-z0-9-]+)?'  # optional unit
    r'(?:[,\s]+'                                    # optional city/state/zip
    r'[A-Za-z]+(?:\s+[A-Za-z]+){0,2}'
    r'(?:[,\s]+'
    r'(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI'
    r'|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT'
    r'|VT|VA|WA|WV|WI|WY|DC)'
    r'(?:\s+\d{5}(?:-\d{4})?)?'
    r')?)?',
    re.IGNORECASE,
)

# P.O. Box patterns — usaddress handles these, but catch them up-front too
POBOX_RE = re.compile(
    r'\bP\.?\s*O\.?\s*Box\s+\d+\b',
    re.IGNORECASE,
)

# Standalone ZIP — 5-digit or ZIP+4, word-bounded
ZIP_RE = re.compile(r'\b\d{5}(?:-\d{4})?\b')

# State abbreviation list for quick sanity-check
_US_STATES = {
    'AL','AK','AZ','AR','CA','CO','CT','DE','FL','GA','HI','ID','IL','IN',
    'IA','KS','KY','LA','ME','MD','MA','MI','MN','MS','MO','MT','NE','NV',
    'NH','NJ','NM','NY','NC','ND','OH','OK','OR','PA','RI','SC','SD','TN',
    'TX','UT','VT','VA','WA','WV','WI','WY','DC',
}

# usaddress component labels that confirm a real address
_ADDRESS_LABELS = {
    'AddressNumber', 'StreetName', 'StreetNamePostType',
    'StreetNamePreType', 'StreetNamePreDirectional', 'StreetNamePostDirectional',
    'OccupancyType', 'OccupancyIdentifier',
    'PlaceName', 'StateName', 'ZipCode',
}


def _usaddress_confirms(span: str) -> bool:
    """Return True if usaddress parses the span as a US address."""
    try:
        tagged, addr_type = usaddress.tag(span)
        labels = set(tagged.values())
        # Must contain at least a street name or address number plus one more field
        if addr_type == 'Street Address' or addr_type == 'PO Box':
            return True
        if len(labels & _ADDRESS_LABELS) >= 2:
            return True
        return False
    except usaddress.RepeatedLabelError:
        # Ambiguous — treat as address to err on the side of redaction
        return True


def redact_addresses(text: str) -> tuple[str, int]:
    """
    Three-layer address redaction.
    Returns (redacted_text, count_of_redactions).
    """
    count = [0]

    # Layer 1 + 2: regex candidate → usaddress confirmation
    def _validate_and_replace(m: re.Match) -> str:
        span = m.group(0).strip()
        if not span:
            return m.group(0)
        if _usaddress_confirms(span):
            count[0] += 1
            return "[REDACTED]"
        return m.group(0)

    text = LOOSE_ADDRESS_RE.sub(_validate_and_replace, text)

    # P.O. Boxes (regex only — usaddress catches them too, but belt-and-suspenders)
    def _replace(m):
        count[0] += 1
        return "[REDACTED]"

    text = POBOX_RE.sub(_replace, text)

    # Layer 3: bare ZIPs that survived
    text = ZIP_RE.sub(_replace, text)

    return text, count[0]


ADDRESS_RE = LOOSE_ADDRESS_RE   # keep name alias so nothing downstream breaks


# ---------------------------------------------------------------------------
# Sensitive ID redaction — SSNs, EINs, account numbers, routing numbers,
# credit/debit card numbers, ITIN, member/policy IDs.
#
# Strategy:
#   Layer A — LABELED_SENSITIVE_RE: any number (6–19 digits, any delimiter)
#             that follows an identifying label. High recall, very safe because
#             the label provides context. Fires even on bare unformatted numbers.
#
#   Layer B — SSN_RE: bare SSN in all three formats (dashes / spaces / raw)
#             with prefix validation (no 000/666/9xx area codes).
#             Does NOT require a label — SSN shape is distinctive enough.
#
#   Layer C — EIN_RE: bare EIN (XX-XXXXXXX) without a label. Shape is
#             distinctive (2-digit prefix, dash, 7 digits).
#
#   Layer D — ROUTING_RE: bare 9-digit numbers that pass the ABA checksum.
#             Routing numbers have a strict checksum so false-positive rate
#             is very low even without a label.
#
#   Layer E — CARD_RE: 13–19 digit sequences (with optional spaces/dashes)
#             near card-related context, plus bare Luhn-valid 16-digit numbers.
#
# All patterns run on the *shielded* text so financial values ($12,453.00,
# percentages, dated tokens) are already replaced by __FIN_N__ placeholders
# and cannot be accidentally matched.
# ---------------------------------------------------------------------------

# --- Layer A: labeled sensitive numbers ---
LABELED_SENSITIVE_RE = re.compile(
    r'(?:'
    # account identifiers
    r'acct(?:ount)?(?:\s+no\.?|\s+#|\s+number|\s+num\.?)?'
    r'|account(?:\s+no\.?|\s+#|\s+number|\s+num\.?)?'
    r'|bank(?:\s+acct)?(?:\s+no\.?|\s+#|\s+number)?'
    r'|checking(?:\s+acct)?(?:\s+no\.?|\s+#|\s+number)?'
    r'|savings(?:\s+acct)?(?:\s+no\.?|\s+#|\s+number)?'
    # routing
    r'|routing(?:\s+no\.?|\s+#|\s+number|\s+num\.?)?'
    r'|aba(?:\s+no\.?|\s+#|\s+number)?'
    r'|transit(?:\s+no\.?|\s+#|\s+number)?'
    # tax / government IDs
    r'|ssn|s\.s\.n\.?|social\s+security(?:\s+no\.?|\s+number|\s+num\.?)?'
    r'|itin'
    r'|ein|e\.i\.n\.?|employer\s+id(?:entification)?(?:\s+no\.?|\s+number)?'
    r'|tax\s+id(?:\s+no\.?|\s+number)?'
    r'|tin'
    # card
    r'|card(?:\s+no\.?|\s+#|\s+number|\s+num\.?)?'
    r'|credit\s+card(?:\s+no\.?|\s+#|\s+number)?'
    r'|debit\s+card(?:\s+no\.?|\s+#|\s+number)?'
    r'|cc\s*#?'
    # member / policy / loan / case IDs
    r'|member(?:\s+id|\s+no\.?|\s+#|\s+number)?'
    r'|policy(?:\s+no\.?|\s+#|\s+number)?'
    r'|loan(?:\s+no\.?|\s+#|\s+number)?'
    r'|case(?:\s+no\.?|\s+#|\s+number)?'
    r'|ref(?:erence)?(?:\s+no\.?|\s+#|\s+number)?'
    r'|claim(?:\s+no\.?|\s+#|\s+number)?'
    r'|contract(?:\s+no\.?|\s+#|\s+number)?'
    r'|id(?:\s+no\.?|\s+#|\s+number)?'
    r')'
    r'\s*[:\-#]?\s*'
    r'([\d][\d\s\-]{4,17}[\d])',   # 6–19 digit number, any spacing/dashes
    re.IGNORECASE,
)

# --- Layer B: bare SSN (all formats, with prefix sanity check) ---
# Covers: 123-45-6789 | 123 45 6789 | 123456789
SSN_RE = re.compile(
    r'\b'
    r'(?!000|666|9\d{2})'       # invalid area codes
    r'(?P<area>\d{3})'
    r'(?P<sep1>[\s\-]?)'
    r'(?!00)(?P<group>\d{2})'
    r'(?P=sep1)'                 # separator must be consistent
    r'(?!0000)(?P<serial>\d{4})'
    r'\b'
)

# --- Layer C: bare EIN (XX-XXXXXXX) ---
EIN_RE = re.compile(
    r'\b(?:0[1-9]|[1-9]\d)-\d{7}\b'
)


def _aba_checksum(n: str) -> bool:
    """Return True if the 9-digit string passes the ABA routing checksum."""
    if len(n) != 9 or not n.isdigit():
        return False
    d = [int(c) for c in n]
    return (3*(d[0]+d[3]+d[6]) + 7*(d[1]+d[4]+d[7]) + (d[2]+d[5]+d[8])) % 10 == 0


# --- Layer D: bare 9-digit routing numbers (ABA checksum validated) ---
ROUTING_CANDIDATE_RE = re.compile(r'\b(\d{9})\b')

# --- Layer E: credit/debit card numbers ---
# Labeled: 13–19 digits with optional spaces/dashes after a card keyword
LABELED_CARD_RE = re.compile(
    r'(?:card(?:\s+no\.?|\s+#|\s+number)?|credit|debit|cc\s*#?)'
    r'\s*[:\-#]?\s*'
    r'(\d[\d\s\-]{11,21}\d)',
    re.IGNORECASE,
)

# Bare: classic 4×4 grouped formats (Visa/MC/Amex/Discover shapes)
BARE_CARD_RE = re.compile(
    r'\b(?:\d{4}[\s\-]){3}\d{4}\b'          # 4-4-4-4
    r'|\b\d{4}[\s\-]\d{6}[\s\-]\d{5}\b'     # Amex 4-6-5
    r'|\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{1,4}\b',  # other variants
)


def _luhn(number: str) -> bool:
    """Return True if the digit string passes the Luhn check."""
    digits = [int(d) for d in number if d.isdigit()]
    odd = digits[-1::-2]
    even = [d*2 - 9 if d*2 > 9 else d*2 for d in digits[-2::-2]]
    return (sum(odd) + sum(even)) % 10 == 0


def redact_sensitive_ids(text: str) -> tuple[str, int]:
    """
    Four-layer sensitive ID redaction.
    Runs on shielded text — financial placeholders are safe.
    Returns (redacted_text, count).
    """
    count = [0]

    def _replace(m: re.Match) -> str:
        count[0] += 1
        return "[REDACTED]"

    # Layer A: labeled numbers (replaces the whole label+number span)
    def _replace_labeled(m: re.Match) -> str:
        count[0] += 1
        # Keep the label text, redact only the number portion
        full = m.group(0)
        number = m.group(len(m.groups()))  # last capture group = the number
        return full[: full.rfind(number)] + "[REDACTED]"

    text = LABELED_SENSITIVE_RE.sub(_replace_labeled, text)

    # Layer B: bare SSNs
    text = SSN_RE.sub(_replace, text)

    # Layer C: bare EINs
    text = EIN_RE.sub(_replace, text)

    # Layer D: bare routing numbers (ABA checksum)
    def _routing_replace(m: re.Match) -> str:
        if _aba_checksum(m.group(1)):
            count[0] += 1
            return "[REDACTED]"
        return m.group(0)

    text = ROUTING_CANDIDATE_RE.sub(_routing_replace, text)

    # Layer E: card numbers
    text = LABELED_CARD_RE.sub(_replace_labeled, text)

    def _card_replace(m: re.Match) -> str:
        digits = re.sub(r'[\s\-]', '', m.group(0))
        if _luhn(digits):
            count[0] += 1
            return "[REDACTED]"
        return m.group(0)

    text = BARE_CARD_RE.sub(_card_replace, text)

    return text, count[0]


LABELED_NAME_RE = re.compile(
    r'(?:client|prepared\s+for|account\s+holder|account\s+name|name'
    r'|beneficiary|advisor|rep(?:resentative)?|agent|owner|trustee'
    r'|grantor|member|participant|insured|subscriber|contact)\s*[:\-]\s*'
    r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)',
    re.IGNORECASE,
)


def extract_names_from_labels(text: str) -> List[str]:
    return LABELED_NAME_RE.findall(text)


def build_name_pattern(names: List[str]) -> re.Pattern | None:
    tokens = set()
    for name in names:
        full = name.strip()
        if len(full) > 2:
            tokens.add(re.escape(full))

        parts = full.split()
        for part in parts:
            part = part.strip(".,")
            if len(part) > 2:
                tokens.add(re.escape(part))
            if '-' in part:
                for sub in part.split('-'):
                    if len(sub) > 2:
                        tokens.add(re.escape(sub))

        if len(parts) >= 2:
            first_initial = parts[0][0]
            last = parts[-1].strip(".,")
            if len(last) > 2:
                tokens.add(re.escape(f"{first_initial}. {last}"))
                tokens.add(re.escape(f"{first_initial} {last}"))

    if not tokens:
        return None

    sorted_tokens = sorted(tokens, key=len, reverse=True)
    pattern = r'(?:' + '|'.join(sorted_tokens) + r')'
    return re.compile(r'\b' + pattern + r'\b', re.IGNORECASE)


def redact_client_names(text: str, names: List[str]) -> tuple[str, int]:
    pattern = build_name_pattern(names)
    if not pattern:
        return text, 0
    count = [0]

    def replacer(m):
        count[0] += 1
        return "[REDACTED]"

    return pattern.sub(replacer, text), count[0]


def redact_text(text: str, client_names: List[str]) -> str:
    # Step 1: shield financial tokens so they don't interfere with PII detection
    shielded, placeholder_map = shield_financials(text)

    # Step 2: custom sensitive ID redaction on shielded text.
    # Runs BEFORE Presidio so our patterns get first pass while financial
    # placeholders still protect balances/values from being touched.
    id_redacted, _ = redact_sensitive_ids(shielded)
    del shielded

    # Step 3: run Presidio on the already-ID-redacted shielded text.
    # Presidio adds coverage for anything our patterns missed.
    analysis_results = analyzer.analyze(
        text=id_redacted,
        entities=PII_ENTITIES,
        language="en",
    )

    anonymized = anonymizer.anonymize(
        text=id_redacted,
        analyzer_results=analysis_results,
        operators={"DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"})},
    )

    del id_redacted
    del analysis_results

    # Step 4: restore financials BEFORE address redaction so placeholders
    # like __FIN_0__ don't corrupt address regex matching
    restored = restore_financials(anonymized.text, placeholder_map)
    del anonymized
    del placeholder_map

    # Step 5: address redaction on clean, fully-restored text
    addr_redacted, _ = redact_addresses(restored)
    del restored

    # Step 6: client name redaction
    name_redacted, _ = redact_client_names(addr_redacted, client_names)
    del addr_redacted

    return name_redacted


def redact_paragraph(para, client_names: List[str]) -> None:
    full_text = "".join(run.text for run in para.runs)
    if not full_text.strip():
        return

    redacted = redact_text(full_text, client_names)

    if para.runs:
        para.runs[0].text = redacted
        for run in para.runs[1:]:
            run.text = ""

    del full_text
    del redacted


def process_pdf(content: bytes, client_names: List[str]) -> bytes:
    text_parts = []

    buf_in = io.BytesIO(content)
    try:
        with pdfplumber.open(buf_in) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
    finally:
        buf_in.close()

    full_text = "\n\n".join(text_parts)
    del text_parts

    discovered = extract_names_from_labels(full_text)
    all_names = list(set(client_names + discovered))
    del discovered

    redacted = redact_text(full_text, all_names)
    del full_text
    del all_names

    buf_out = io.BytesIO()
    try:
        doc = SimpleDocTemplate(buf_out, pagesize=letter,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=72)
        styles = getSampleStyleSheet()
        story = []
        for line in redacted.split("\n"):
            story.append(Paragraph(
                line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") or "&nbsp;",
                styles["Normal"]
            ))
        doc.build(story)
        del story
        del redacted
        return buf_out.getvalue()
    finally:
        buf_out.close()


def process_docx(content: bytes, client_names: List[str]) -> bytes:
    buf_in = io.BytesIO(content)
    try:
        doc = Document(buf_in)
    finally:
        buf_in.close()

    full_doc_text = "\n".join(para.text for para in doc.paragraphs)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                full_doc_text += "\n" + cell.text

    discovered = extract_names_from_labels(full_doc_text)
    all_names = list(set(client_names + discovered))
    del full_doc_text
    del discovered

    for para in doc.paragraphs:
        redact_paragraph(para, all_names)

    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for para in cell.paragraphs:
                    redact_paragraph(para, all_names)

    del all_names

    buf_out = io.BytesIO()
    try:
        doc.save(buf_out)
        del doc
        return buf_out.getvalue()
    finally:
        buf_out.close()


def process_xlsx(content: bytes, client_names: List[str]) -> bytes:
    buf_in = io.BytesIO(content)
    try:
        wb = openpyxl.load_workbook(buf_in)
    finally:
        buf_in.close()

    full_sheet_text = ""
    for sheet in wb.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                if isinstance(cell.value, str) and cell.value.strip():
                    full_sheet_text += "\n" + cell.value

    discovered = extract_names_from_labels(full_sheet_text)
    all_names = list(set(client_names + discovered))
    del full_sheet_text
    del discovered

    for sheet in wb.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                if isinstance(cell.value, str) and cell.value.strip():
                    cell.value = redact_text(cell.value, all_names)

    del all_names

    buf_out = io.BytesIO()
    try:
        wb.save(buf_out)
        del wb
        return buf_out.getvalue()
    finally:
        buf_out.close()


@app.post("/process")
async def process_documents(
    files: List[UploadFile] = File(...),
    client_names: List[str] = Form(default=[]),
):
    results = []

    for file in files:
        content = await file.read()
        filename = file.filename
        name_lower = filename.lower()

        try:
            if name_lower.endswith(".pdf"):
                redacted_bytes = process_pdf(content, client_names)
                mime = "application/pdf"
            elif name_lower.endswith(".docx"):
                redacted_bytes = process_docx(content, client_names)
                mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            elif name_lower.endswith(".xlsx"):
                redacted_bytes = process_xlsx(content, client_names)
                mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            else:
                results.append({
                    "filename": filename,
                    "error": "Unsupported file type.",
                    "download": None,
                })
                del content
                continue

            encoded = base64.b64encode(redacted_bytes).decode("utf-8")
            del redacted_bytes

            results.append({
                "filename": filename,
                "error": None,
                "mime": mime,
                "download": encoded,
            })

        except Exception as exc:
            results.append({
                "filename": filename,
                "error": f"Processing failed: {exc}",
                "download": None,
            })
        finally:
            del content
            gc.collect()

    return JSONResponse({"results": results, "client_names": client_names})


@app.get("/health")
def health():
    return {"status": "ok"}
