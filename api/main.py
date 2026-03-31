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
# Financial shield
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
# Client name redaction
# ---------------------------------------------------------------------------

def build_name_pattern(names: List[str]) -> re.Pattern | None:
    tokens = set()
    for name in names:
        for part in name.strip().split():
            part = part.strip(".,")
            if len(part) > 2:
                tokens.add(re.escape(part))
    if not tokens:
        return None
    pattern = r'\b(?:' + '|'.join(tokens) + r')\b'
    return re.compile(pattern, re.IGNORECASE)


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
    shielded, placeholder_map = shield_financials(text)

    analysis_results = analyzer.analyze(
        text=shielded,
        entities=PII_ENTITIES,
        language="en",
    )

    anonymized = anonymizer.anonymize(
        text=shielded,
        analyzer_results=analysis_results,
        operators={"DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"})},
    )

    name_redacted, _ = redact_client_names(anonymized.text, client_names)
    return restore_financials(name_redacted, placeholder_map)


# ---------------------------------------------------------------------------
# Format-specific redaction + file rebuilding
# ---------------------------------------------------------------------------

def process_pdf(content: bytes, client_names: List[str]) -> bytes:
    # Extract text, redact, write clean readable PDF
    text_parts = []
    with pdfplumber.open(io.BytesIO(content)) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)

    full_text = "\n\n".join(text_parts)
    redacted = redact_text(full_text, client_names)

    # Build new PDF with reportlab
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            rightMargin=72, leftMargin=72,
                            topMargin=72, bottomMargin=72)
    styles = getSampleStyleSheet()
    story = []
    for line in redacted.split("\n"):
        story.append(Paragraph(line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") or "&nbsp;",
                               styles["Normal"]))
    doc.build(story)
    return buf.getvalue()


def process_docx(content: bytes, client_names: List[str]) -> bytes:
    # Redact in-place preserving paragraph/run structure
    doc = Document(io.BytesIO(content))

    for para in doc.paragraphs:
        for run in para.runs:
            if run.text:
                run.text = redact_text(run.text, client_names)

    # Also redact table cells
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for para in cell.paragraphs:
                    for run in para.runs:
                        if run.text:
                            run.text = redact_text(run.text, client_names)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def process_xlsx(content: bytes, client_names: List[str]) -> bytes:
    # Redact cell values in-place
    wb = openpyxl.load_workbook(io.BytesIO(content))

    for sheet in wb.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                if isinstance(cell.value, str) and cell.value.strip():
                    cell.value = redact_text(cell.value, client_names)

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