import streamlit as st
import re
import datetime
import csv
import pandas as pd
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# Constants for Verhoeff (Aadhaar)
verhoeff_d = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,2,3,4,0,6,7,8,9,5],
    [2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],
    [4,0,1,2,3,9,5,6,7,8],
    [5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],
    [7,6,5,9,8,2,1,0,4,3],
    [8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0]
]
verhoeff_p = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,5,7,6,2,8,3,0,9,4],
    [5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],
    [9,4,5,3,1,2,6,8,7,0],
    [4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],
    [7,0,4,6,9,1,3,2,5,8]
]

CODE_POINTS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def validate_aadhaar(num: str) -> bool:
    if not re.fullmatch(r'^[2-9]\d{11}$', num):
        return False
    c = 0
    for i, digit in enumerate(reversed(num)):
        c = verhoeff_d[c][verhoeff_p[i % 8][int(digit)]]
    return c == 0

def luhn_mod10(num: str) -> bool:
    total = 0
    reverse_digits = num[::-1]
    for i, d in enumerate(reverse_digits):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return (total % 10) == 0

def gstin_checksum(gstin_without_checksum):
    factor = 2
    total = 0
    charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    modulus = 36

    for char in reversed(gstin_without_checksum):
        code_point = charset.index(char)
        addend = factor * code_point
        addend = (addend // modulus) + (addend % modulus)
        total += addend
        factor = 1 if factor == 2 else 2

    check_code_point = (modulus - (total % modulus)) % modulus
    return charset[check_code_point]

def validate_gstin(gstin):
    gstin = gstin.upper()
    pattern = r'^\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]$'
    if not re.match(pattern, gstin):
        return False
    gstin_without_checksum = gstin[:-1]
    return gstin[-1] == gstin_checksum(gstin_without_checksum)

def detect_type(num: str):
    num = num.upper()
    if re.fullmatch(r'^[2-9]\d{11}$', num):
        return "Aadhaar"
    elif re.fullmatch(r'^\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]$', num) and len(num) == 15:
        return "GSTIN"
    elif re.fullmatch(r'^\d{15}$', num):
        return "IMEI"
    elif re.fullmatch(r'^\d{13,19}$', num):
        return "Card"
    else:
        return None

def validate_id(num: str, id_type: str) -> bool:
    if id_type == "Aadhaar":
        return validate_aadhaar(num)
    elif id_type == "GSTIN":
        return validate_gstin(num)
    elif id_type in ["IMEI", "Card"]:
        return luhn_mod10(num)
    return False

def fraud_flags(num: str, id_type: str) -> list:
    flags = []
    if len(set(num)) <= 2:
        flags.append("Repeated digits")
    if id_type == "Aadhaar" and num[0] in "01":
        flags.append("Invalid Aadhaar start digit")
    if id_type == "GSTIN" and not num[:2].isdigit():
        flags.append("Invalid GSTIN state code")
    return flags

def log_attempt(num: str, id_type: str, valid: bool, flags: list):
    with open("validation_log.csv", "a", newline='') as f:
        writer = csv.writer(f)
        writer.writerow([datetime.datetime.now().isoformat(), num, id_type, valid, ";".join(flags)])

def generate_pdf(df: pd.DataFrame) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []

    styles = getSampleStyleSheet()
    elements.append(Paragraph("Validation Report", styles['Title']))
    elements.append(Spacer(1, 12))

    # Convert DataFrame to list of lists
    data = [df.columns.tolist()] + df.values.tolist()

    # Create table
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#003366")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))

    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()

# Streamlit UI
st.title("🇮🇳 Indian ID Validator")
st.markdown("**Instant & Accurate Validation for Aadhaar, GSTIN, IMEI, and  Credit/Debit Card Numbers.**")

#st.markdown("### Multiple ID Validator")
st.markdown("Enter multiple IDs separated by commas or new lines:")

raw_input = st.text_area("Enter IDs here:")

if st.button("Validate All") and raw_input.strip():
    ids = [x.strip() for x in re.split(r'[\n,]+', raw_input) if x.strip()]
    results = []

    for id_num in ids:
        id_type = detect_type(id_num)
        if not id_type:
            valid = False
            flags = ["Unrecognized or invalid format"]
        else:
            valid = validate_id(id_num, id_type)
            flags = fraud_flags(id_num, id_type)
        log_attempt(id_num, id_type if id_type else "Unknown", valid, flags)

        if valid:
            st.success(f"✅ {id_type if id_type else 'Unknown'} number **{id_num}** is VALID")
        else:
            st.error(f"❌ {id_type if id_type else 'Unknown'} number **{id_num}** is INVALID")

        for flag in flags:
            st.warning(f"⚠️ Fraud flag: {flag}")

        results.append({
            "ID Number": id_num,
            "Type": id_type if id_type else "Unknown",
            "Valid": "Yes" if valid else "No",
            "Flags": ", ".join(flags) if flags else "-"
        })

    df = pd.DataFrame(results)
    st.markdown("### Summary Table")
    st.dataframe(df)

    pdf_bytes = generate_pdf(df)
    st.download_button("📥 Download PDF Report", data=pdf_bytes, file_name="validation_report.pdf", mime="application/pdf")
