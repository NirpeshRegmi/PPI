import gc
import io
import re
import base64
from typing import list

import docx
from docx import document
from reportlab.lib.pagesizes import letter
from reportlab.platypus import simpledoctemplate, paragraph
from reportlab.lib.styles import getsamplestylesheet
import openpyxl
import pdfplumber
from fastapi import fastapi, file, form, uploadfile
from fastapi.middleware.cors import corsmiddleware
from fastapi.responses import jsonresponse
from presidio_analyzer import analyzerengine
from presidio_anonymizer import anonymizerengine
from presidio_anonymizer.entities import operatorconfig
from starlette.middleware.base import basehttpmiddleware

app = fastapi(title="transcend pii processor")

app.add_middleware(
    corsmiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# fix: gc middleware — force garbage collection after every request
# ---------------------------------------------------------------------------

class gcmiddleware(basehttpmiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        gc.collect()
        return response

app.add_middleware(gcmiddleware)

analyzer = analyzerengine()
anonymizer = anonymizerengine()

pii_entities = [
    "person",
    "phone_number",
    "email_address",
    "location",
    "us_ssn",
    "us_itin",
    "us_driver_license",
    "us_passport",
    "us_bank_number",
    "credit_card",
    "iban_code",
    "ip_address",
    "url",
    "date_time",
    "nrp",
    "medical_license",
    "crypto",
]

# ---------------------------------------------------------------------------
# financial shield (preserve these through presidio)
# ---------------------------------------------------------------------------

dollar_re = re.compile(r'\$[\d,]+(?:\.\d+)?(?:[kkmmbb])?')
percent_re = re.compile(r'\b\d+(?:\.\d+)?%')
tax_date_re = re.compile(
    r'\b(?:20[0-2]\d)\b'
    r'|\b(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\d|3[01])/(?:20[0-2]\d)\b'
    r'|\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?'
    r'|jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)'
    r'\s+(?:20[0-2]\d)\b'
    r'|\bq[1-4]\s+(?:20[0-2]\d)\b',
    re.ignorecase
)
financial_patterns = [dollar_re, percent_re, tax_date_re]


def shield_financials(text: str) -> tuple[str, dict]:
    placeholder_map = {}
    counter = [0]

    def replace(m):
        token = f"__fin_{counter[0]}__"
        placeholder_map[token] = m.group(0)
        counter[0] += 1
        return token

    for pattern in financial_patterns:
        text = pattern.sub(replace, text)
    return text, placeholder_map


def restore_financials(text: str, placeholder_map: dict) -> str:
    for token, original in placeholder_map.items():
        text = text.replace(token, original)
    return text


# ---------------------------------------------------------------------------
# street address redaction
# ---------------------------------------------------------------------------

address_re = re.compile(
    r"(?:"
    r"\bp\.?o\.?\s+box\s+\d+"
    r"|"
    r"\b\d{1,6}\s+"
    r"(?:[nsewnsew]\.?\s+)?"
    r"[a-za-z0-9]+(?:\s+[a-za-z0-9]+){0,4}\s+"
    r"(?:street|st|avenue|ave|boulevard|blvd|road|rd|drive|dr|lane|ln|court|ct"
    r"|circle|cir|place|pl|way|wy|terrace|ter|trail|trl|highway|hwy|parkway|pkwy"
    r"|square|sq|loop|lp|run|path|row|alley|aly|crossing|xing)\.?"
    r"(?:\s+(?:apt|suite|ste|unit|#)\s*[a-za-z0-9-]+)?"
    r")"
    r"(?:[,\s]+"
    r"[a-za-z]+(?:\s+[a-za-z]+){0,2}"
    r"[,\s]+"
    r"(?:al|ak|az|ar|ca|co|ct|de|fl|ga|hi|id|il|in|ia|ks|ky|la|me|md|ma|mi"
    r"|mn|ms|mo|mt|ne|nv|nh|nj|nm|ny|nc|nd|oh|ok|or|pa|ri|sc|sd|tn|tx|ut"
    r"|vt|va|wa|wv|wi|wy|dc)"
    r"(?:\s+\d{5}(?:-\d{4})?)?"
    r")?",
    re.ignorecase,
)

bare_address_re = re.compile(
    r'\b\d{1,5}\s+[a-z][a-z]+(?:\s+[a-z][a-z]+)?\s+'
    r'(?:street|st|avenue|ave|boulevard|blvd|road|rd|drive|dr|lane|ln'
    r'|court|ct|circle|cir|place|pl|way|terrace|ter|trail|trl'
    r'|highway|hwy|parkway|pkwy|loop|path|row|alley|crossing)\.?\b',
    re.ignorecase,
)

zip_re = re.compile(r'\b\d{5}(?:-\d{4})?\b')


def redact_addresses(text: str) -> tuple[str, int]:
    count = [0]

    def replacer(m):
        count[0] += 1
        return "[redacted]"

    text = address_re.sub(replacer, text)
    text = bare_address_re.sub(replacer, text)
    text = zip_re.sub(replacer, text)
    return text, count[0]


# ---------------------------------------------------------------------------
# auto-extract names from labeled fields
# ---------------------------------------------------------------------------

labeled_name_re = re.compile(
    r'(?:client|prepared\s+for|account\s+holder|account\s+name|name'
    r'|beneficiary|advisor|rep(?:resentative)?|agent|owner|trustee'
    r'|grantor|member|participant|insured|subscriber|contact)\s*[:\-]\s*'
    r'([a-z][a-z]+(?:\s+[a-z][a-z]+)+)',
    re.ignorecase,
)


def extract_names_from_labels(text: str) -> list[str]:
    return labeled_name_re.findall(text)


# ---------------------------------------------------------------------------
# client name redaction
# ---------------------------------------------------------------------------

def build_name_pattern(names: list[str]) -> re.pattern | none:
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
        return none

    sorted_tokens = sorted(tokens, key=len, reverse=true)
    pattern = r'(?:' + '|'.join(sorted_tokens) + r')'
    return re.compile(r'\b' + pattern + r'\b', re.ignorecase)


def redact_client_names(text: str, names: list[str]) -> tuple[str, int]:
    pattern = build_name_pattern(names)
    if not pattern:
        return text, 0
    count = [0]

    def replacer(m):
        count[0] += 1
        return "[redacted]"

    return pattern.sub(replacer, text), count[0]


# ---------------------------------------------------------------------------
# core redaction pipeline
# ---------------------------------------------------------------------------

def redact_text(text: str, client_names: list[str]) -> str:
    shielded, placeholder_map = shield_financials(text)
    addr_redacted, _ = redact_addresses(shielded)

    analysis_results = analyzer.analyze(
        text=addr_redacted,
        entities=pii_entities,
        language="en",
    )

    anonymized = anonymizer.anonymize(
        text=addr_redacted,
        analyzer_results=analysis_results,
        operators={"default": operatorconfig("replace", {"new_value": "[redacted]"})},
    )

    # fix: explicitly delete large intermediate objects
    del addr_redacted
    del analysis_results

    name_redacted, _ = redact_client_names(anonymized.text, client_names)

    del anonymized

    result = restore_financials(name_redacted, placeholder_map)

    del placeholder_map
    del name_redacted

    return result


# ---------------------------------------------------------------------------
# docx paragraph-level reconstruction
# ---------------------------------------------------------------------------

def redact_paragraph(para, client_names: list[str]) -> none:
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


# ---------------------------------------------------------------------------
# format-specific redaction + file rebuilding
# ---------------------------------------------------------------------------

def process_pdf(content: bytes, client_names: list[str]) -> bytes:
    text_parts = []

    # fix: use context manager to ensure pdfplumber releases file handle
    buf_in = io.bytesio(content)
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

    buf_out = io.bytesio()
    try:
        doc = simpledoctemplate(buf_out, pagesize=letter,
                                rightmargin=72, leftmargin=72,
                                topmargin=72, bottommargin=72)
        styles = getsamplestylesheet()
        story = []
        for line in redacted.split("\n"):
            story.append(paragraph(
                line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") or "&nbsp;",
                styles["normal"]
            ))
        doc.build(story)
        del story
        del redacted
        return buf_out.getvalue()
    finally:
        buf_out.close()


def process_docx(content: bytes, client_names: list[str]) -> bytes:
    buf_in = io.bytesio(content)
    try:
        doc = document(buf_in)
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

    buf_out = io.bytesio()
    try:
        doc.save(buf_out)
        del doc
        return buf_out.getvalue()
    finally:
        buf_out.close()


def process_xlsx(content: bytes, client_names: list[str]) -> bytes:
    buf_in = io.bytesio(content)
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

    buf_out = io.bytesio()
    try:
        wb.save(buf_out)
        del wb
        return buf_out.getvalue()
    finally:
        buf_out.close()


# ---------------------------------------------------------------------------
# endpoints
# ---------------------------------------------------------------------------

@app.post("/process")
async def process_documents(
    files: list[uploadfile] = file(...),
    client_names: list[str] = form(default=[]),
):
    results = []

    for file in files:
        # fix: read content then explicitly delete after processing
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
                # FIX: delete content even on unsupported type
                del content
                continue

            # FIX: encode then immediately delete raw bytes
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
            # FIX: ALWAYS delete content bytes after each file regardless of outcome
            del content
            gc.collect()

    return JSONResponse({"results": results, "client_names": client_names})


@app.get("/health")
def health():
    return {"status": "ok"}
    return {"status": "ok"}