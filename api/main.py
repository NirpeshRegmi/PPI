import gc
import io
import re
import base64
from typing import List, Optional

import fitz  # pymupdf
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

# Pre-compiled token restore pattern — used for single-pass restoration
# instead of one str.replace call per token (O(n) vs O(n*tokens))
_FIN_TOKEN_RE = re.compile(r'__FIN_\d+__')


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
    # Single regex pass instead of one str.replace per token —
    # O(n) over the text regardless of how many tokens exist
    if not placeholder_map:
        return text
    return _FIN_TOKEN_RE.sub(lambda m: placeholder_map.get(m.group(0), m.group(0)), text)


# ---------------------------------------------------------------------------
# ADDRESS REDACTION
# ---------------------------------------------------------------------------

LOOSE_ADDRESS_RE = re.compile(
    r'\b\d{1,6}'
    r'(?:\s+[NSEWnsew]\.?)?\s+'
    r'[A-Za-z0-9]+(?:\s+[A-Za-z0-9]+){0,4}\s+'
    r'(?:street|st|avenue|ave|boulevard|blvd|road|rd|drive|dr|lane|ln'
    r'|court|ct|circle|cir|place|pl|way|wy|terrace|ter|trail|trl'
    r'|highway|hwy|parkway|pkwy|square|sq|loop|lp|run|path|row'
    r'|alley|aly|crossing|xing)\.?'
    r'(?:\s+(?:apt|apartment|suite|ste|unit|#|no\.?)\s*[A-Za-z0-9-]+)?'
    r'(?:[,\s]+'
    r'[A-Za-z]+(?:\s+[A-Za-z]+){0,2}'
    r'(?:[,\s]+'
    r'(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI'
    r'|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT'
    r'|VT|VA|WA|WV|WI|WY|DC)'
    r'(?:\s+\d{5}(?:-\d{4})?)?'
    r')?)?',
    re.IGNORECASE,
)

UNIT_ONLY_RE = re.compile(
    r'\b(?:suite|ste|unit|apt|apartment|floor|fl)\s+[A-Za-z0-9-]+'
    r'(?:[,\s]+[A-Za-z]+(?:\s+[A-Za-z]+){0,2})?'
    r'(?:[,\s]+'
    r'(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI'
    r'|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT'
    r'|VT|VA|WA|WV|WI|WY|DC)'
    r'(?:\s+\d{5}(?:-\d{4})?)?'
    r')?',
    re.IGNORECASE,
)

RURAL_ROUTE_RE = re.compile(
    r'\b(?:rural\s+route|rr|r\.r\.|hc|highway\s+contract)\s*\d+'
    r'(?:\s+box\s+\d+)?'
    r'(?:[,\s]+[A-Za-z]+(?:\s+[A-Za-z]+){0,2})?'
    r'(?:[,\s]+'
    r'(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI'
    r'|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT'
    r'|VT|VA|WA|WV|WI|WY|DC)'
    r'(?:\s+\d{5}(?:-\d{4})?)?'
    r')?',
    re.IGNORECASE,
)

POBOX_RE = re.compile(r'\bP\.?\s*O\.?\s*Box\s+\d+\b', re.IGNORECASE)
ZIP_RE = re.compile(r'\b\d{5}(?:-\d{4})?\b')

_ADDRESS_LABELS = {
    'AddressNumber', 'StreetName', 'StreetNamePostType',
    'StreetNamePreType', 'StreetNamePreDirectional', 'StreetNamePostDirectional',
    'OccupancyType', 'OccupancyIdentifier',
    'PlaceName', 'StateName', 'ZipCode',
}


def _usaddress_confirms(span: str) -> bool:
    try:
        tagged, addr_type = usaddress.tag(span)
        labels = set(tagged.values())
        if addr_type in ('Street Address', 'PO Box'):
            return True
        if len(labels & _ADDRESS_LABELS) >= 2:
            return True
        return False
    except usaddress.RepeatedLabelError:
        return True


def redact_addresses(text: str) -> tuple[str, int]:
    count = [0]

    def _validate_and_replace(m: re.Match) -> str:
        span = m.group(0).strip()
        if not span:
            return m.group(0)
        if _usaddress_confirms(span):
            count[0] += 1
            return "[REDACTED]"
        return m.group(0)

    def _replace(m):
        count[0] += 1
        return "[REDACTED]"

    text = LOOSE_ADDRESS_RE.sub(_validate_and_replace, text)
    text = UNIT_ONLY_RE.sub(_validate_and_replace, text)
    text = RURAL_ROUTE_RE.sub(_replace, text)
    text = POBOX_RE.sub(_replace, text)
    text = ZIP_RE.sub(_replace, text)
    return text, count[0]


ADDRESS_RE = LOOSE_ADDRESS_RE


# ---------------------------------------------------------------------------
# SENSITIVE ID REDACTION
# ---------------------------------------------------------------------------

LABELED_SENSITIVE_RE = re.compile(
    r'(?:'
    r'acct(?:ount)?(?:\s+no\.?|\s+#|\s+number|\s+num\.?)?'
    r'|account(?:\s+no\.?|\s+#|\s+number|\s+num\.?)?'
    r'|bank(?:\s+acct)?(?:\s+no\.?|\s+#|\s+number)?'
    r'|checking(?:\s+acct)?(?:\s+no\.?|\s+#|\s+number)?'
    r'|savings(?:\s+acct)?(?:\s+no\.?|\s+#|\s+number)?'
    r'|brokerage(?:\s+acct)?(?:\s+no\.?|\s+#|\s+number)?'
    r'|investment(?:\s+acct)?(?:\s+no\.?|\s+#|\s+number)?'
    r'|portfolio(?:\s+no\.?|\s+#|\s+number)?'
    r'|ira(?:\s+acct)?(?:\s+no\.?|\s+#|\s+number)?'
    r'|roth(?:\s+ira)?(?:\s+no\.?|\s+#|\s+number)?'
    r'|401k(?:\s+no\.?|\s+#|\s+number)?'
    r'|routing(?:\s+no\.?|\s+#|\s+number|\s+num\.?)?'
    r'|aba(?:\s+no\.?|\s+#|\s+number)?'
    r'|transit(?:\s+no\.?|\s+#|\s+number)?'
    r'|ssn|s\.s\.n\.?|social\s+security(?:\s+no\.?|\s+number|\s+num\.?)?'
    r'|itin'
    r'|ein|e\.i\.n\.?|employer\s+id(?:entification)?(?:\s+no\.?|\s+number)?'
    r'|tax\s+id(?:\s+no\.?|\s+number)?'
    r'|tin'
    r'|card(?:\s+no\.?|\s+#|\s+number|\s+num\.?)?'
    r'|credit\s+card(?:\s+no\.?|\s+#|\s+number)?'
    r'|debit\s+card(?:\s+no\.?|\s+#|\s+number)?'
    r'|cc\s*#?'
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
    r'([\d][\d\s\-]{4,17}[\d])',
    re.IGNORECASE,
)

SSN_RE = re.compile(
    r'\b'
    r'(?!000|666|9\d{2})'
    r'(?P<area>\d{3})'
    r'(?P<sep1>[\s\-]?)'
    r'(?!00)(?P<group>\d{2})'
    r'(?P=sep1)'
    r'(?!0000)(?P<serial>\d{4})'
    r'\b'
)

EIN_RE = re.compile(r'\b(?:0[1-9]|[1-9]\d)-\d{7}\b')
ROUTING_CANDIDATE_RE = re.compile(r'\b(\d{9})\b')

LABELED_CARD_RE = re.compile(
    r'(?:card(?:\s+no\.?|\s+#|\s+number)?|credit|debit|cc\s*#?)'
    r'\s*[:\-#]?\s*'
    r'(\d[\d\s\-]{11,21}\d)',
    re.IGNORECASE,
)

BARE_CARD_RE = re.compile(
    r'\b(?:\d{4}[\s\-]){3}\d{4}\b'
    r'|\b\d{4}[\s\-]\d{6}[\s\-]\d{5}\b'
    r'|\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{1,4}\b',
)

BROKERAGE_ACCOUNT_RE = re.compile(
    r'\b\d{4}-\d{4}\b'
    r'|\b\d{3}-\d{5}\b'
    r'|\b\d{3}-\d{6}-\d{3}\b'
    r'|\b\d{3}-\d{5}-\d{1}\b'
    r'|\bZ\d{8}\b'
    r'|\bRH-[A-Z0-9]{6,12}\b'
)

BROKERAGE_CONTEXT_RE = re.compile(
    r'(?:account|acct|portfolio|position|holding|registration|statement)\b'
    r'.{0,40}'
    r'\b(\d{8,12})\b',
    re.IGNORECASE,
)

# Pre-compiled phone shape to filter false positives in brokerage context
_PHONE_RE = re.compile(r'^[2-9]\d{2}[2-9]\d{6}$')


def _is_brokerage_account(candidate: str) -> bool:
    return not _PHONE_RE.match(candidate)


def _aba_checksum(n: str) -> bool:
    if len(n) != 9 or not n.isdigit():
        return False
    d = [int(c) for c in n]
    return (3*(d[0]+d[3]+d[6]) + 7*(d[1]+d[4]+d[7]) + (d[2]+d[5]+d[8])) % 10 == 0


def _luhn(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    odd = digits[-1::-2]
    even = [d*2 - 9 if d*2 > 9 else d*2 for d in digits[-2::-2]]
    return (sum(odd) + sum(even)) % 10 == 0


# Pre-compiled strip pattern for card digit extraction
_STRIP_RE = re.compile(r'[\s\-]')


def redact_sensitive_ids(text: str) -> tuple[str, int]:
    count = [0]

    def _replace(m: re.Match) -> str:
        count[0] += 1
        return "[REDACTED]"

    def _replace_labeled(m: re.Match) -> str:
        count[0] += 1
        full = m.group(0)
        number = m.group(len(m.groups()))
        return full[: full.rfind(number)] + "[REDACTED]"

    text = LABELED_SENSITIVE_RE.sub(_replace_labeled, text)
    text = SSN_RE.sub(_replace, text)
    text = EIN_RE.sub(_replace, text)

    def _routing_replace(m: re.Match) -> str:
        if _aba_checksum(m.group(1)):
            count[0] += 1
            return "[REDACTED]"
        return m.group(0)

    text = ROUTING_CANDIDATE_RE.sub(_routing_replace, text)
    text = LABELED_CARD_RE.sub(_replace_labeled, text)

    def _card_replace(m: re.Match) -> str:
        digits = _STRIP_RE.sub('', m.group(0))
        if _luhn(digits):
            count[0] += 1
            return "[REDACTED]"
        return m.group(0)

    text = BARE_CARD_RE.sub(_card_replace, text)
    text = BROKERAGE_ACCOUNT_RE.sub(_replace, text)

    def _brokerage_context_replace(m: re.Match) -> str:
        candidate = m.group(1)
        if _is_brokerage_account(candidate):
            count[0] += 1
            full = m.group(0)
            return full[: full.rfind(candidate)] + "[REDACTED]"
        return m.group(0)

    text = BROKERAGE_CONTEXT_RE.sub(_brokerage_context_replace, text)
    return text, count[0]


# ---------------------------------------------------------------------------
# NAME REDACTION
# ---------------------------------------------------------------------------

LABELED_NAME_RE = re.compile(
    r'(?:client|prepared\s+for|account\s+holder|account\s+name|name'
    r'|beneficiary|advisor|rep(?:resentative)?|agent|owner|trustee'
    r'|grantor|member|participant|insured|subscriber|contact'
    r'|primary\s+(?:account\s+holder|owner|contact)'
    r'|secondary\s+(?:account\s+holder|owner)'
    r'|joint\s+(?:account\s+holder|owner)'
    r'|registered\s+(?:owner|holder)'
    r')\s*[:\-]\s*'
    r'([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)+)',
    re.IGNORECASE,
)

SALUTATION_NAME_RE = re.compile(
    r'\bDear\s+'
    r'(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)?\s*'
    r'([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*)'
    r'[,:\s]',
    re.IGNORECASE,
)

TITLE_NAME_RE = re.compile(
    r'\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)\s+'
    r'([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)?)',
    re.IGNORECASE,
)

SIGNATURE_RE = re.compile(
    r'(?:sincerely|regards|best\s+regards|respectfully|yours\s+truly'
    r'|warm\s+regards|thank\s+you)[,\s]+'
    r'([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)+)',
    re.IGNORECASE,
)

ALLCAPS_NAME_RE = re.compile(
    r'(?:client|name|holder|owner|insured|member|beneficiary|contact)'
    r'\s*[:\-]\s*'
    r'([A-Z]{2,}(?:\s+[A-Z]{2,})+)',
)

# All name discovery patterns in one list for clean iteration
_NAME_DISCOVERY_PATTERNS = [
    LABELED_NAME_RE,
    SALUTATION_NAME_RE,
    TITLE_NAME_RE,
    SIGNATURE_RE,
    ALLCAPS_NAME_RE,
]

# All inline redaction patterns (subset — only patterns that fire on
# occurrences, not just labels we use for discovery)
_NAME_INLINE_PATTERNS = [
    SALUTATION_NAME_RE,
    TITLE_NAME_RE,
    SIGNATURE_RE,
    ALLCAPS_NAME_RE,
]


def extract_names_from_labels(text: str) -> List[str]:
    seen: set = set()
    unique: List[str] = []
    for pattern in _NAME_DISCOVERY_PATTERNS:
        for name in pattern.findall(text):
            key = name.strip().lower()
            if key not in seen and len(key) > 2:
                seen.add(key)
                unique.append(name.strip())
    return unique


def _redact_inline_name_patterns(text: str) -> tuple[str, int]:
    count = [0]

    def _replace_group1(m: re.Match) -> str:
        count[0] += 1
        full = m.group(0)
        name = m.group(1)
        return full.replace(name, "[REDACTED]", 1)

    for pattern in _NAME_INLINE_PATTERNS:
        text = pattern.sub(_replace_group1, text)
    return text, count[0]


def build_name_pattern(names: List[str]) -> Optional[re.Pattern]:
    tokens: set = set()
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


def redact_client_names(text: str, names: List[str], name_pattern: Optional[re.Pattern] = None) -> tuple[str, int]:
    # Inline pass: salutations, titles, signatures, all-caps labels
    text, inline_count = _redact_inline_name_patterns(text)

    # Named pattern pass: redact discovered names anywhere they appear.
    # Accepts a pre-built pattern so callers processing many paragraphs
    # don't rebuild the same compiled regex on every call.
    if name_pattern is None:
        name_pattern = build_name_pattern(names)
    if not name_pattern:
        return text, inline_count

    count = [0]

    def replacer(m):
        count[0] += 1
        return "[REDACTED]"

    return name_pattern.sub(replacer, text), inline_count + count[0]


# ---------------------------------------------------------------------------
# CORE REDACTION PIPELINE
# Accepts an optional pre-built name_pattern so document processors can
# build it once and reuse it across paragraphs / cells.
# ---------------------------------------------------------------------------

def redact_text(text: str, client_names: List[str], name_pattern: Optional[re.Pattern] = None) -> str:
    # Step 1: shield financial tokens
    shielded, placeholder_map = shield_financials(text)

    # Step 2: sensitive ID redaction
    id_redacted, _ = redact_sensitive_ids(shielded)
    del shielded

    # Step 3: Presidio
    analysis_results = analyzer.analyze(text=id_redacted, entities=PII_ENTITIES, language="en")
    anonymized = anonymizer.anonymize(
        text=id_redacted,
        analyzer_results=analysis_results,
        operators={"DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"})},
    )
    del id_redacted
    del analysis_results

    # Step 4: restore financials (single-pass via regex)
    restored = restore_financials(anonymized.text, placeholder_map)
    del anonymized
    del placeholder_map

    # Step 5: address redaction
    addr_redacted, _ = redact_addresses(restored)
    del restored

    # Step 6: name redaction (reuses pre-built pattern if supplied)
    name_redacted, _ = redact_client_names(addr_redacted, client_names, name_pattern)
    del addr_redacted

    return name_redacted


def redact_paragraph(para, client_names: List[str], name_pattern: Optional[re.Pattern] = None) -> None:
    full_text = "".join(run.text for run in para.runs)
    if not full_text.strip():
        return
    redacted = redact_text(full_text, client_names, name_pattern)
    if para.runs:
        para.runs[0].text = redacted
        for run in para.runs[1:]:
            run.text = ""


# ---------------------------------------------------------------------------
# PDF TEXT EXTRACTION
#
# Key change: open pdfplumber and fitz ONCE per document, not once per page.
# _extract_all_pages takes already-open handles and iterates — eliminates
# the per-page open/close overhead that was the biggest performance issue.
# fitz document is always closed in a finally block to release native memory.
# ---------------------------------------------------------------------------

def _extract_all_pages(pdf_bytes: bytes) -> List[str]:
    """
    Extract text from all pages in one pass.
    Opens pdfplumber and fitz once each — not once per page.
    Falls back to pymupdf text layer then OCR on a per-page basis
    only for pages where pdfplumber returns nothing.
    """
    text_parts: List[str] = []
    fitz_doc = None

    buf = io.BytesIO(pdf_bytes)
    try:
        with pdfplumber.open(buf) as plumber_pdf:
            for i, page in enumerate(plumber_pdf.pages):
                text = page.extract_text()
                if text and text.strip():
                    text_parts.append(text)
                    continue

                # Page needs pymupdf — open fitz doc lazily once
                if fitz_doc is None:
                    fitz_doc = fitz.open(stream=pdf_bytes, filetype="pdf")

                fitz_page = fitz_doc[i]

                # Pass 2: pymupdf text layer
                text = fitz_page.get_text("text")
                if text and text.strip():
                    text_parts.append(text)
                    continue

                # Pass 3: OCR
                try:
                    tp = fitz_page.get_textpage_ocr(
                        flags=fitz.TEXT_PRESERVE_WHITESPACE, dpi=300
                    )
                    text = fitz_page.get_text("text", textpage=tp)
                    if text:
                        text_parts.append(text)
                except Exception:
                    pass  # page unreadable — skip rather than crash

    finally:
        buf.close()
        if fitz_doc is not None:
            fitz_doc.close()  # always release native fitz memory

    return text_parts


def process_pdf(content: bytes, client_names: List[str]) -> bytes:
    text_parts = _extract_all_pages(content)
    full_text = "\n\n".join(text_parts)
    text_parts.clear()  # release list contents before heavy processing

    discovered = extract_names_from_labels(full_text)
    all_names = list(set(client_names + discovered))
    name_pattern = build_name_pattern(all_names)  # build once

    redacted = redact_text(full_text, all_names, name_pattern)
    del full_text

    buf_out = io.BytesIO()
    try:
        doc = SimpleDocTemplate(
            buf_out, pagesize=letter,
            rightMargin=72, leftMargin=72,
            topMargin=72, bottomMargin=72,
        )
        styles = getSampleStyleSheet()
        story = [
            Paragraph(
                line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") or "&nbsp;",
                styles["Normal"],
            )
            for line in redacted.split("\n")
        ]
        doc.build(story)
        return buf_out.getvalue()
    finally:
        buf_out.close()


def process_docx(content: bytes, client_names: List[str]) -> bytes:
    buf_in = io.BytesIO(content)
    try:
        doc = Document(buf_in)
    finally:
        buf_in.close()

    # Collect full text for name discovery
    parts: List[str] = [para.text for para in doc.paragraphs]
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                parts.append(cell.text)
    full_doc_text = "\n".join(parts)
    parts.clear()

    discovered = extract_names_from_labels(full_doc_text)
    all_names = list(set(client_names + discovered))
    name_pattern = build_name_pattern(all_names)  # build once, reuse per paragraph
    del full_doc_text

    for para in doc.paragraphs:
        redact_paragraph(para, all_names, name_pattern)

    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for para in cell.paragraphs:
                    redact_paragraph(para, all_names, name_pattern)

    buf_out = io.BytesIO()
    try:
        doc.save(buf_out)
        return buf_out.getvalue()
    finally:
        buf_out.close()
        del doc


def process_xlsx(content: bytes, client_names: List[str]) -> bytes:
    buf_in = io.BytesIO(content)
    try:
        wb = openpyxl.load_workbook(buf_in)
    finally:
        buf_in.close()

    # Use list join instead of string += (O(n) vs O(n²))
    parts: List[str] = []
    for sheet in wb.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                if isinstance(cell.value, str) and cell.value.strip():
                    parts.append(cell.value)
    full_sheet_text = "\n".join(parts)
    parts.clear()

    discovered = extract_names_from_labels(full_sheet_text)
    all_names = list(set(client_names + discovered))
    name_pattern = build_name_pattern(all_names)  # build once, reuse per cell
    del full_sheet_text

    for sheet in wb.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                if isinstance(cell.value, str) and cell.value.strip():
                    cell.value = redact_text(cell.value, all_names, name_pattern)

    buf_out = io.BytesIO()
    try:
        wb.save(buf_out)
        return buf_out.getvalue()
    finally:
        buf_out.close()
        del wb


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
                continue

            encoded = base64.b64encode(redacted_bytes).decode("utf-8")
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
            # Release the raw upload bytes immediately after processing
            del content
            gc.collect()

    return JSONResponse({"results": results, "client_names": client_names})


@app.get("/health")
def health():
    return {"status": "ok"}