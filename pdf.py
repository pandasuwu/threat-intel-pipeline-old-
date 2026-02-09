"""early PDF -> text dump using pdfplumber. crude. just for exploring."""
import pdfplumber
import sys

def dump(path):
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            text = page.extract_text() or ""
            print(text)

if __name__ == "__main__":
    dump(sys.argv[1])

# TODO: pipe extracted text -> gemini for summary
# def summarize_with_gemini(text): ...
