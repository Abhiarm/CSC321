#!/usr/bin/env python3
"""
Generate a PDF report containing all source code and output for the
Public Key Cryptography assignment.
"""

import subprocess
import sys
from fpdf import FPDF


class ReportPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 8, "CPE-321 Public Key Cryptography Implementation", align="C", new_x="LMARGIN", new_y="NEXT")
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(2)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def section_title(self, title):
        self.set_font("Helvetica", "B", 14)
        self.ln(4)
        self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def sub_title(self, title):
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def code_block(self, code_text):
        self.set_font("Courier", "", 7)
        self.set_fill_color(245, 245, 245)
        for line in sanitize(code_text).split("\n"):
            if len(line) > 120:
                line = line[:117] + "..."
            self.cell(0, 3.5, line, new_x="LMARGIN", new_y="NEXT", fill=True)
        self.ln(2)

    def output_block(self, output_text):
        self.set_font("Courier", "", 6.5)
        self.set_fill_color(235, 245, 255)
        for line in sanitize(output_text).split("\n"):
            if len(line) > 130:
                line = line[:127] + "..."
            self.cell(0, 3.3, line, new_x="LMARGIN", new_y="NEXT", fill=True)
        self.ln(2)

    def body_text(self, text):
        self.set_font("Helvetica", "", 10)
        self.multi_cell(0, 5, text)
        self.ln(1)


def sanitize(text):
    """Replace Unicode characters that standard PDF fonts can't render."""
    replacements = {
        "\u2014": "--",   # em dash
        "\u2013": "-",    # en dash
        "\u2018": "'",    # left single quote
        "\u2019": "'",    # right single quote
        "\u201c": '"',    # left double quote
        "\u201d": '"',    # right double quote
        "\u2192": "->",   # right arrow
        "\u2190": "<-",   # left arrow
        "\u21d2": "=>",   # double right arrow
        "\u27f9": "==>",  # long double right arrow
        "\u2208": "in",   # element of
        "\u2124": "Z",    # integers
        "\u2265": ">=",   # greater than or equal
        "\u2264": "<=",   # less than or equal
        "\u2260": "!=",   # not equal
        "\u2713": "[ok]", # check mark
        "\u2714": "[ok]", # heavy check mark
        "\u2717": "[x]",  # ballot x
        "\u2022": "*",    # bullet
        "\u00d7": "x",    # multiplication sign
        "\u2026": "...",  # ellipsis
        "\u221e": "inf",  # infinity
        "\u2203": "E",    # there exists
        "\u2200": "A",    # for all
        "\u2228": "v",    # logical or
        "\u2227": "^",    # logical and
        "\u00b7": ".",    # middle dot
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    # Fallback: replace any remaining non-latin1 chars with '?'
    result = []
    for ch in text:
        try:
            ch.encode("latin-1")
            result.append(ch)
        except UnicodeEncodeError:
            result.append("?")
    return "".join(result)


def read_file(path):
    with open(path, "r") as f:
        return f.read()


def run_script(path):
    """Run a Python script using the venv interpreter and capture output."""
    result = subprocess.run(
        [sys.executable, path],
        capture_output=True, text=True, timeout=120
    )
    return result.stdout + result.stderr


def main():
    pdf = ReportPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)

    # ── Title Page ──
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.ln(40)
    pdf.cell(0, 12, "Public Key Cryptography", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 12, "Implementation Report", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 8, "CPE-321 Introduction to Computer Security", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(20)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, "Tasks Implemented:", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, "Task 1: Diffie-Hellman Key Exchange", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, "Task 2: MITM Key Fixing & Negotiated Groups", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, "Task 3: Textbook RSA & MITM via Malleability", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(20)
    pdf.set_font("Helvetica", "I", 9)
    pdf.cell(0, 7, "Tools: Python 3, PyCryptodome. AI coding assistant (Claude) used for implementation.", align="C", new_x="LMARGIN", new_y="NEXT")

    # ── Task 1 ──
    pdf.add_page()
    pdf.section_title("Task 1: Diffie-Hellman Key Exchange")
    pdf.body_text(
        "This program implements the Diffie-Hellman key exchange protocol. "
        "Alice and Bob agree on public parameters (q, a), each pick a random "
        "private key, compute public values, exchange them, and derive a shared "
        "secret. The shared secret is hashed with SHA-256 (truncated to 16 bytes) "
        "to produce an AES-128 key. Both parties then encrypt and decrypt messages "
        "using AES-CBC.\n\n"
        "The protocol is tested first with small parameters (q=37, a=5) and then "
        "with the IETF-recommended 1024-bit parameters."
    )

    pdf.sub_title("Source Code: task1_diffie_hellman.py")
    pdf.code_block(read_file("task1_diffie_hellman.py"))

    pdf.add_page()
    pdf.sub_title("Output")
    output1 = run_script("task1_diffie_hellman.py")
    pdf.output_block(output1)

    # ── Task 2 ──
    pdf.add_page()
    pdf.section_title("Task 2: MITM Key Fixing & Negotiated Groups")
    pdf.body_text(
        "This program demonstrates two man-in-the-middle attacks on Diffie-Hellman.\n\n"
        "Part 1 (Key Fixing): Mallory intercepts the exchange and replaces both "
        "public values Y_A and Y_B with q. Since q^X mod q = 0 for any X, both "
        "Alice and Bob compute s = 0. Mallory knows s = 0 and can derive the same "
        "symmetric key to decrypt all messages.\n\n"
        "Part 2 (Generator Tampering): Mallory tampers with the generator a:\n"
        "- a = 1: All public values become 1, so s = 1.\n"
        "- a = q: All public values become 0 (q mod q), so s = 0.\n"
        "- a = q-1: Public values are in {1, q-1}, so s is in {1, q-1}. "
        "Mallory tries both candidates."
    )

    pdf.sub_title("Source Code: task2_mitm_attack.py")
    pdf.code_block(read_file("task2_mitm_attack.py"))

    pdf.add_page()
    pdf.sub_title("Output")
    output2 = run_script("task2_mitm_attack.py")
    pdf.output_block(output2)

    # ── Task 3 ──
    pdf.add_page()
    pdf.section_title("Task 3: Textbook RSA & MITM via Malleability")
    pdf.body_text(
        "Part 1 (Textbook RSA): Implements RSA key generation with variable-length "
        "primes and e=65537. The modular multiplicative inverse is computed using "
        "the Extended Euclidean Algorithm (implemented from scratch). Messages are "
        "converted from strings to integers and encrypted/decrypted successfully.\n\n"
        "Part 2 (MITM via Malleability): Mallory intercepts Bob's ciphertext c and "
        "replaces it with c' = r^e mod n for a known r. When Alice decrypts c', she "
        "gets s' = r. Mallory knows r, derives the same AES key, and decrypts "
        "Alice's message.\n\n"
        "Signature Malleability: Given signatures sig1 = m1^d mod n and "
        "sig2 = m2^d mod n, Mallory computes sig3 = sig1 * sig2 mod n, which is "
        "a valid signature for m3 = m1 * m2 mod n. This works because "
        "(m1^d)(m2^d) = (m1*m2)^d mod n."
    )

    pdf.sub_title("Source Code: task3_rsa.py")
    pdf.code_block(read_file("task3_rsa.py"))

    pdf.add_page()
    pdf.sub_title("Output")
    output3 = run_script("task3_rsa.py")
    pdf.output_block(output3)

    # ── Save ──
    out_path = "Public_Key_Crypto_Report.pdf"
    pdf.output(out_path)
    print(f"PDF saved to: {out_path}")


if __name__ == "__main__":
    main()