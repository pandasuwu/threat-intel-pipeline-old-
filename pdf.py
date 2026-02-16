"""early PDF -> text dump using pdfplumber. crude. just for exploring.

NOTE: pdfplumber loses structure on tables in the threat reports. Pivoting to
docling — see parse/parse.py.
"""
import pdfplumber
import sys

def dump(path):
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            text = page.extract_text() or ""
            print(text)

if __name__ == "__main__":
    dump(sys.argv[1])
