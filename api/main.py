import io
import re
from typing import List

import docx
from docx import Document
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import openpyxl
import pdfplumber
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

app = FastAPI(title="Transcend PII Processor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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

# ---------------------------------------------------------------------------
# Financial shield (preserve these through Presidio)
# ---------------------------------------------------------------------------

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
# Street address redaction — full address (regex-based, runs before Presidio)
# ---------------------------------------------------------------------------

ADDRESS_RE = re.compile(
    r"(?:"
    r"\bP\.?O\.?\s+Box\s+\d+"
    r"|"
    r"\b\d{1,6}\s+"
    r"(?:[NSEWnsew]\.?\s+)?"
    r"[A-Za-z0-9]+(?:\s+[A-Za-z0-9]+){0,4}\s+"
    r"(?:street|st|avenue|ave|boulevard|blvd|road|rd|drive|dr|lane|ln|court|ct"
    r"|circle|cir|place|pl|way|wy|terrace|ter|trail|trl|highway|hwy|parkway|pkwy"
    r"|square|sq|loop|lp|run|path|row|alley|aly|crossing|xing)\.?"
    r"(?:\s+(?:Apt|Suite|Ste|Unit|#)\s*[A-Za-z0-9-]+)?"
    r")"
    r"(?:[,\s]+"
    r"[A-Za-z]+(?:\s+[A-Za-z]+){0,2}"
    r"[,\s]+"
    r"(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI"
    r"|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT"
    r"|VT|VA|WA|WV|WI|WY|DC)"
    r"(?:\s+\d{5}(?:-\d{4})?)?"
    r")?",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# FIX: Bare address (no city/state required) — second pass
# ---------------------------------------------------------------------------

BARE_ADDRESS_RE = re.compile(
    r'\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s+'
    r'(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln'
    r'|Court|Ct|Circle|Cir|Place|Pl|Way|Terrace|Ter|Trail|Trl'
    r'|Highway|Hwy|Parkway|Pkwy|Loop|Path|Row|Alley|Crossing)\.?\b',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# FIX: Standalone zip code redaction — runs after address passes
# ---------------------------------------------------------------------------

ZIP_RE = re.compile(r'\b\d{5}(?:-\d{4})?\b')


def redact_addresses(text: str) -> tuple[str, int]:
    count = [0]

    def replacer(m):
        count[0] += 1
        return "[REDACTED]"

    # Pass 1: full address with optional city/state/zip
    text = ADDRESS_RE.sub(replacer, text)
    # Pass 2: bare street address fragments missed by pass 1
    text = BARE_ADDRESS_RE.sub(replacer, text)
    # Pass 3: any surviving standalone zip codes
    text = ZIP_RE.sub(replacer, text)

    return text, count[0]


# ---------------------------------------------------------------------------
# FIX: Auto-extract names from labeled fields in document text
# ---------------------------------------------------------------------------

LABELED_NAME_RE = re.compile(
    r'(?:client|prepared\s+for|account\s+holder|account\s+name|name'
    r'|beneficiary|advisor|rep(?:resentative)?|agent|owner|trustee'
    r'|grantor|member|participant|insured|subscriber|contact)\s*[:\-]\s*'
    r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)',
    re.IGNORECASE,
)


def extract_names_from_labels(text: str) -> List[str]:
    """Pull names from labeled fields like 'Client: John Smith'."""
    return LABELED_NAME_RE.findall(text)


# ---------------------------------------------------------------------------
# Client name redaction — FIX: handles initials and hyphenated names
# ---------------------------------------------------------------------------

def build_name_pattern(names: List[str]) -> re.Pattern | None:
    tokens = set()
    for name in names:
        # Add full name as a phrase match (highest precision)
        full = name.strip()
        if len(full) > 2:
            tokens.add(re.escape(full))

        parts = full.split()
        for part in parts:
            part = part.strip(".,")

            # Regular token (len > 2, not a common word that would over-redact)
            if len(part) > 2:
                tokens.add(re.escape(part))

            # FIX: Handle hyphenated names (Mary-Anne -> both halves)
            if '-' in part:
                for sub in part.split('-'):
                    if len(sub) > 2:
                        tokens.add(re.escape(sub))

        # FIX: Handle initials like "J. Smith" or "J Smith"
        if len(parts) >= 2:
            first_initial = parts[0][0]
            last = parts[-1].strip(".,")
            if len(last) > 2:
                # "J. Smith" and "J Smith"
                tokens.add(re.escape(f"{first_initial}. {last}"))
                tokens.add(re.escape(f"{first_initial} {last}"))

    if not tokens:
        return None

    # Sort longest first so full-name phrases match before individual tokens
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


# ---------------------------------------------------------------------------
# Core redaction pipeline (text in, text out)
# ---------------------------------------------------------------------------

def redact_text(text: str, client_names: List[str]) -> str:
    # 1. Shield financial data so Presidio doesn't touch it
    shielded, placeholder_map = shield_financials(text)

    # 2. Redact street addresses via regex (Presidio NER misses these)
    addr_redacted, _ = redact_addresses(shielded)

    # 3. Run Presidio over the result
    analysis_results = analyzer.analyze(
        text=addr_redacted,
        entities=PII_ENTITIES,
        language="en",
    )

    anonymized = anonymizer.anonymize(
        text=addr_redacted,
        analyzer_results=analysis_results,
        operators={"DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"})},
    )

    # 4. Redact client names
    name_redacted, _ = redact_client_names(anonymized.text, client_names)

    # 5. Restore financial data
    return restore_financials(name_redacted, placeholder_map)


# ---------------------------------------------------------------------------
# FIX: DOCX paragraph-level reconstruction to catch cross-run names
# ---------------------------------------------------------------------------

def redact_paragraph(para, client_names: List[str]) -> None:
    """
    Reconstruct full paragraph text, redact it, then write the result back
    into the first run (preserving its formatting) and zero out remaining runs.

    This prevents names split across runs (e.g. ['John ', 'Smith']) from
    slipping through pattern matching.
    """
    full_text = "".join(run.text for run in para.runs)
    if not full_text.strip():
        return

    redacted = redact_text(full_text, client_names)

    if para.runs:
        para.runs[0].text = redacted
        for run in para.runs[1:]:
            run.text = ""


# ---------------------------------------------------------------------------
# Format-specific redaction + file rebuilding
# ---------------------------------------------------------------------------

def process_pdf(content: bytes, client_names: List[str]) -> bytes:
    text_parts = []
    with pdfplumber.open(io.BytesIO(content)) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)

    full_text = "\n\n".join(text_parts)

    # FIX: Auto-discover names from labeled fields before redacting
    discovered = extract_names_from_labels(full_text)
    all_names = list(set(client_names + discovered))

    redacted = redact_text(full_text, all_names)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
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
    return buf.getvalue()


def process_docx(content: bytes, client_names: List[str]) -> bytes:
    doc = Document(io.BytesIO(content))

    # FIX: Auto-discover names from labeled fields across all paragraphs
    full_doc_text = "\n".join(
        para.text for para in doc.paragraphs
    )
    # Also scan table cells
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                full_doc_text += "\n" + cell.text

    discovered = extract_names_from_labels(full_doc_text)
    all_names = list(set(client_names + discovered))

    # FIX: Use paragraph-level reconstruction instead of per-run redaction
    for para in doc.paragraphs:
        redact_paragraph(para, all_names)

    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for para in cell.paragraphs:
                    redact_paragraph(para, all_names)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def process_xlsx(content: bytes, client_names: List[str]) -> bytes:
    wb = openpyxl.load_workbook(io.BytesIO(content))

    # FIX: Auto-discover names from labeled fields across all sheets first
    full_sheet_text = ""
    for sheet in wb.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                if isinstance(cell.value, str) and cell.value.strip():
                    full_sheet_text += "\n" + cell.value

    discovered = extract_names_from_labels(full_sheet_text)
    all_names = list(set(client_names + discovered))

    for sheet in wb.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                if isinstance(cell.value, str) and cell.value.strip():
                    cell.value = redact_text(cell.value, all_names)

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

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

            import base64
            results.append({
                "filename": filename,
                "error": None,
                "mime": mime,
                "download": base64.b64encode(redacted_bytes).decode("utf-8"),
            })

        except Exception as exc:
            results.append({
                "filename": filename,
                "error": f"Processing failed: {exc}",
                "download": None,
            })

    return JSONResponse({"results": results, "client_names": client_names})


@app.get("/health")
def health():
    return {"status": "ok"}