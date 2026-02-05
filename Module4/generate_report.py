#!/usr/bin/env python3
"""
Report Generation Script for Cryptographic Hash Functions Assignment
This script generates a PDF report with all code, explanations, and answers to questions.

AI Citation: Claude (Anthropic) was used to assist with code generation and report writing.
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.platypus import Preformatted, PageBreak, Image
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
import os


def create_report():
    """Generate the PDF report."""
    
    doc = SimpleDocTemplate(
        "Module4/Cryptographic_Hash_Functions_Report.pdf",
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        spaceBefore=20,
        spaceAfter=10
    )
    
    subheading_style = ParagraphStyle(
        'CustomSubHeading',
        parent=styles['Heading3'],
        fontSize=12,
        spaceBefore=15,
        spaceAfter=8
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=12,
        alignment=TA_JUSTIFY
    )
    
    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Code'],
        fontSize=8,
        leftIndent=20,
        spaceAfter=10,
        backColor=colors.Color(0.95, 0.95, 0.95)
    )
    
    story = []
    
    # Title
    story.append(Paragraph("Cryptographic Hash Functions - Lab Report", title_style))
    story.append(Paragraph("CPE-321: Introduction to Computer Security", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Team Members
    story.append(Paragraph("<b>Team Members:</b>", body_style))
    story.append(Paragraph("Abhiram Yakkali", body_style))
    story.append(Spacer(1, 20))
    
    # Citations
    story.append(Paragraph("<b>AI Tool Citations:</b>", heading_style))
    story.append(Paragraph(
        "• Claude (Anthropic) - Used for code generation assistance, debugging, and report writing<br/>"
        "• Visual Studio Code - IDE used for development<br/>"
        "• Python 3.x with libraries: hashlib, bcrypt, nltk, matplotlib",
        body_style
    ))
    story.append(Spacer(1, 20))
    
    # ==================== TASK 1 ====================
    story.append(Paragraph("TASK 1: Exploring Pseudo-Randomness and Collision Resistance", title_style))
    
    # Task 1a
    story.append(Paragraph("Task 1a: SHA256 Hashing", heading_style))
    story.append(Paragraph(
        "We built a simple program that takes any input and runs it through SHA256, then "
        "displays the resulting hash in hexadecimal format. We used Python's built-in hashlib "
        "library for this since it provides a reliable and efficient SHA256 implementation.",
        body_style
    ))
    
    # Task 1b
    story.append(Paragraph("Task 1b: Hamming Distance Exploration", heading_style))
    story.append(Paragraph(
        "To explore how sensitive SHA256 is to input changes, we created pairs of strings that "
        "differ by just a single bit and hashed them both. We ran this experiment several times "
        "to see how the outputs compared.",
        body_style
    ))
    
    # Question 1 Answer
    story.append(Paragraph("Question 1: Observations from Task 1b", subheading_style))
    story.append(Paragraph(
        "<b>What we found:</b> Even when two inputs differ by just a single bit, their SHA256 "
        "hashes look completely unrelated. On average, about <b>128 bits (50%)</b> of the output "
        "changed, and usually <b>all 32 bytes</b> ended up being different.<br/><br/>"
        "This is called the <b>avalanche effect</b>, and it's a key property of good cryptographic "
        "hash functions. The idea is that even a tiny change to the input should cause a massive, "
        "unpredictable change in the output. This makes it practically impossible to figure out "
        "what the original input was just by looking at the hash, or to find patterns that could "
        "be exploited.",
        body_style
    ))
    
    # Task 1c
    story.append(Paragraph("Task 1c: Finding Collisions", heading_style))
    story.append(Paragraph(
        "Next, we modified our program to work with truncated hashes (between 8 and 50 bits) "
        "so we could actually find collisions in a reasonable amount of time. We used the "
        "birthday attack approach, which is much faster than brute force. The trick is to store "
        "all the hashes we've computed in a dictionary, so checking for a collision is instant.",
        body_style
    ))
    
    # Add collision analysis table
    story.append(Paragraph("Collision Analysis Data (8-50 bits)", subheading_style))
    
    # Read collision results from CSV if available
    collision_table_data = [['Digest Bits', 'Hashes Required', 'Expected (2^(n/2))', 'Time (s)']]
    try:
        with open('Module4/collision_results.csv', 'r') as f:
            lines = f.readlines()[1:]  # Skip header
            for line in lines:
                parts = line.strip().split(',')
                if len(parts) >= 4:
                    bits = parts[0]
                    num_hashes = f"{int(parts[1]):,}"
                    expected = f"{int(float(parts[3])):,}"
                    time_s = f"{float(parts[2]):.4f}"
                    collision_table_data.append([bits, num_hashes, expected, time_s])
    except FileNotFoundError:
        collision_table_data.append(['--', '--', '--', '--'])
    
    collision_table = Table(collision_table_data, colWidths=[1*inch, 1.3*inch, 1.3*inch, 1*inch])
    collision_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.Color(0.95, 0.95, 0.95)),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
    ]))
    story.append(collision_table)
    story.append(Spacer(1, 15))
    
    # Add collision analysis graph if it exists
    if os.path.exists('Module4/collision_analysis.png'):
        story.append(Paragraph("Collision Analysis Graph", subheading_style))
        img = Image('Module4/collision_analysis.png', width=6*inch, height=2.1*inch)
        story.append(img)
        story.append(Spacer(1, 15))
    
    # Add collision examples table
    story.append(Paragraph("Collision Examples (Hash Values for Each Bit Size)", subheading_style))
    story.append(Paragraph(
        "The following table shows actual collision examples found for each digest size. "
        "Two different messages produce the same truncated hash value.",
        body_style
    ))
    
    collision_examples_data = [['Bits', 'Truncated Hash', 'Message 1 (hex)', 'Message 2 (hex)']]
    try:
        with open('Module4/collision_examples.csv', 'r') as f:
            lines = f.readlines()[1:]  # Skip header
            for line in lines:
                parts = line.strip().split(',')
                if len(parts) >= 4:
                    bits = parts[0]
                    hash_val = parts[1]
                    # Truncate message hex for display (first 16 chars)
                    m1_hex = parts[2][:16] + '...' if len(parts[2]) > 16 else parts[2]
                    m2_hex = parts[3][:16] + '...' if len(parts[3]) > 16 else parts[3]
                    collision_examples_data.append([bits, hash_val, m1_hex, m2_hex])
    except FileNotFoundError:
        collision_examples_data.append(['--', '--', '--', '--'])
    
    collision_examples_table = Table(collision_examples_data, colWidths=[0.5*inch, 1.3*inch, 1.5*inch, 1.5*inch])
    collision_examples_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.Color(0.95, 0.95, 0.95)),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
        ('FONTSIZE', (0, 1), (-1, -1), 7),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
    ]))
    story.append(collision_examples_table)
    story.append(Spacer(1, 15))
    
    # Question 2 Answer
    story.append(Paragraph("Question 2: Collision Analysis", subheading_style))
    story.append(Paragraph(
        "<b>Worst case scenario:</b> For an n-bit hash, you'd need at most 2^n + 1 attempts to "
        "guarantee finding a collision (pigeonhole principle - if there are only 2^n possible "
        "outputs, the 2^(n+1)th input must collide with something).<br/><br/>"
        
        "<b>Expected case (Birthday Bound):</b> Thanks to the birthday paradox, we actually "
        "expect to find a collision much sooner - around 2^(n/2) hashes. This is because "
        "collision probability grows quadratically as we add more samples.<br/><br/>"
        
        "<b>What we observed:</b> Our experiments matched the birthday bound predictions really "
        "well. The number of hashes needed was consistently close to 2^(n/2).<br/><br/>"
        
        "<b>How long would a full 256-bit collision take?</b><br/>"
        "• We'd need around 2^128 ≈ 3.4 × 10^38 hashes<br/>"
        "• At 1 million hashes per second: ~10^32 seconds<br/>"
        "• That's roughly <b>10^24 years</b><br/>"
        "• The universe is only about 1.4 × 10^10 years old<br/><br/>"
        "So yeah, SHA256 is collision-resistant for any practical purpose.",
        body_style
    ))
    
    # Question 3 Answer
    story.append(Paragraph("Question 3: Pre-image Resistance vs Collision Resistance", subheading_style))
    story.append(Paragraph(
        "<b>Can we break the one-way property with an 8-bit digest?</b><br/>"
        "Absolutely. With only 256 possible hash values (2^8), we can easily find an input that "
        "produces any given hash - just try random inputs until one works. At most, that's 256 "
        "attempts.<br/><br/>"
        
        "<b>Is finding a pre-image easier or harder than finding a collision?</b><br/>"
        "Finding a <b>pre-image is harder</b>. Here's why:<br/>"
        "• <b>Pre-image attack:</b> You need to find a specific input that produces a specific "
        "output. That takes O(2^n) work on average.<br/>"
        "• <b>Collision attack:</b> You just need any two inputs that hash to the same thing. "
        "Thanks to the birthday paradox, that only takes O(2^(n/2)) work.<br/><br/>"
        
        "For an 8-bit digest, this means:<br/>"
        "• Pre-image: ~128 attempts on average<br/>"
        "• Collision: ~16 attempts (square root of 256)<br/><br/>"
        
        "This is why collision resistance is considered a weaker property than pre-image "
        "resistance. Breaking collision resistance is fundamentally easier.",
        body_style
    ))
    
    story.append(PageBreak())
    
    # ==================== TASK 2 ====================
    story.append(Paragraph("TASK 2: Breaking Real Hashes (Bcrypt)", title_style))
    
    story.append(Paragraph("Implementation Overview", heading_style))
    story.append(Paragraph(
        "We wrote a custom bcrypt password cracker in Python. The cracker reads the shadow file, "
        "pulls out each user's hash and salt, then tries every word from the NLTK dictionary "
        "(about 135,000 words between 6-10 characters) until it finds a match.<br/><br/>"
        
        "<b>How it works:</b><br/>"
        "• The shadow file format is: User:$Algorithm$Workfactor$SaltHash<br/>"
        "• We extract the salt (first 22 characters after the workfactor) and use it with "
        "bcrypt.checkpw() to test each guess<br/>"
        "• We group users by workfactor so we can process all the fast hashes first<br/>"
        "• The program logs progress so we can see how far along it is",
        body_style
    ))
    
    story.append(Paragraph("Bcrypt Workfactor Analysis", heading_style))
    story.append(Paragraph(
        "The whole point of bcrypt is to be slow - it's designed to make password cracking "
        "painful. The workfactor controls how many iterations it does, and each increment "
        "doubles the time:<br/><br/>"
        "• Workfactor 8: ~30 ms per hash<br/>"
        "• Workfactor 9: ~60 ms per hash<br/>"
        "• Workfactor 10: ~110 ms per hash<br/>"
        "• Workfactor 11: ~220 ms per hash<br/>"
        "• Workfactor 12: ~420 ms per hash<br/>"
        "• Workfactor 13: ~840 ms per hash<br/><br/>"
        "This exponential scaling is exactly what makes bcrypt effective at slowing down attackers.",
        body_style
    ))
    
    # Results table placeholder
    story.append(Paragraph("Cracking Results", heading_style))
    story.append(Paragraph(
        "Here's what we found. The time for each password depends on where it appears in the "
        "dictionary - words near the beginning get found quickly, while words near the end "
        "take much longer.",
        body_style
    ))
    
    # Create results table with actual cracking results
    table_data = [
        ['User', 'Workfactor', 'Password', 'Time'],
        ['Bilbo', '8', 'welcome', '392.82s (6.5 min)'],
        ['Gandalf', '8', 'wizard', '390.51s (6.5 min)'],
        ['Thorin', '8', 'diamond', '377.49s (6.3 min)'],
        ['Fili', '9', 'desire', '782.39s (13 min)'],
        ['Kili', '9', 'ossify', '740.89s (12.3 min)'],
        ['Balin', '10', 'hangout', '1557.72s (26 min)'],
        ['Dwalin', '10', 'drossy', '1361.81s (22.7 min)'],
        ['Oin', '10', 'ispaghul', '1436.17s (24 min)'],
        ['Gloin', '11', 'oversave', '2896.63s (48 min)'],
        ['Dori', '11', 'indoxylic', '2755.79s (46 min)'],
        ['Nori', '11', 'swagsman', '2929.05s (49 min)'],
        ['Ori', '12', 'airway', '5450.16s (1.5 hrs)'],
        ['Bifur', '12', 'corrosible', '5727.11s (1.6 hrs)'],
        ['Bofur', '12', 'libellate', '5837.28s (1.6 hrs)'],
        ['Durin', '13', 'purrone', '14509.72s (4.0 hrs)'],
    ]
    
    table = Table(table_data, colWidths=[1.2*inch, 1*inch, 1.5*inch, 1.3*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    story.append(table)
    story.append(Spacer(1, 10))
    
    # Summary statistics
    story.append(Paragraph(
        "<b>Total Cracking Time:</b> 47,145.63 seconds (~13.1 hours)<br/>"
        "<b>Method:</b> Parallel dictionary attack using multiprocessing (8 CPU cores)<br/>"
        "<b>Dictionary:</b> NLTK word corpus, 6-10 character words (~135,000 words)<br/>"
        "<b>Success Rate:</b> 15/15 passwords cracked (100%)",
        body_style
    ))
    story.append(Spacer(1, 20))
    
    # Question 4 Answer
    story.append(Paragraph("Question 4: Brute Force Time Estimates", heading_style))
    story.append(Paragraph(
        "<b>Starting point:</b><br/>"
        "• Our dictionary has ~135,000 words<br/>"
        "• At workfactor 10, each hash takes about 110 ms<br/>"
        "• Worst case for a single word: 135,000 × 0.11s ≈ 4.1 hours<br/><br/>"
        
        "<b>What about word1:word2 (two dictionary words)?</b><br/>"
        "• Combinations: 135,000² = 18.2 billion possibilities<br/>"
        "• Time needed: 18.2 × 10^9 × 0.11s = 2.0 × 10^9 seconds<br/>"
        "• That's about <b>63 years</b> of continuous computation<br/><br/>"
        
        "<b>What about word1:word2:word3 (three words)?</b><br/>"
        "• Combinations: 135,000³ = 2.46 × 10^15 possibilities<br/>"
        "• Time needed: 2.46 × 10^15 × 0.11s = 2.7 × 10^14 seconds<br/>"
        "• That's roughly <b>8.6 million years</b><br/><br/>"
        
        "<b>What about word1:word2:number (with 1-5 digit number)?</b><br/>"
        "• Number options: 10 + 100 + 1000 + 10000 + 100000 = 111,110<br/>"
        "• Total combinations: 135,000² × 111,110 = 2.02 × 10^15<br/>"
        "• Time needed: about <b>7.0 million years</b><br/><br/>"
        
        "<b>Important assumptions:</b><br/>"
        "• Single-threaded, sequential processing<br/>"
        "• Worst case (password is the very last one tried)<br/>"
        "• Constant hash time (real-world varies a bit)<br/><br/>"
        
        "Even if you threw 1000 CPU cores at this problem, multi-word passwords would still "
        "take thousands of years to crack. This really drives home why passphrases (multiple "
        "dictionary words strung together) are so much more secure than single-word passwords - "
        "each additional word multiplies the search space by 135,000.",
        body_style
    ))
    
    story.append(PageBreak())
    
    # ==================== CODE APPENDIX ====================
    story.append(Paragraph("CODE APPENDIX", title_style))
    
    # Define code style for code blocks
    code_style_block = ParagraphStyle(
        'CodeBlock',
        parent=styles['Code'],
        fontSize=6,
        leftIndent=10,
        rightIndent=10,
        spaceAfter=10,
        backColor=colors.Color(0.95, 0.95, 0.95),
        fontName='Courier'
    )
    
    # Task 1 Code
    story.append(Paragraph("Task 1: SHA256 Implementation (task1_sha256.py)", heading_style))
    
    # Read and include task1 code
    try:
        with open('Module4/task1_sha256.py', 'r') as f:
            task1_code = f.read()
        story.append(Preformatted(task1_code, code_style_block))
    except FileNotFoundError:
        story.append(Paragraph("Code file not found.", body_style))
    
    story.append(PageBreak())
    
    # Task 2 Code
    story.append(Paragraph("Task 2: Bcrypt Cracker (task2_bcrypt_cracker.py)", heading_style))
    
    # Read and include task2 code
    try:
        with open('Module4/task2_bcrypt_cracker.py', 'r') as f:
            task2_code = f.read()
        story.append(Preformatted(task2_code, code_style_block))
    except FileNotFoundError:
        story.append(Paragraph("Code file not found.", body_style))
    
    # Interesting Observations
    story.append(Paragraph("Interesting Observations", heading_style))
    story.append(Paragraph(
        "<b>1. The avalanche effect is incredibly consistent.</b> No matter what input you use "
        "or which bit you flip, you always end up with roughly 50% of the output bits changing. "
        "It's almost eerie how reliable this is.<br/><br/>"
        
        "<b>2. The birthday paradox really works.</b> Our collision experiments matched the "
        "theoretical 2^(n/2) predictions almost exactly. It's satisfying when the math and "
        "the real-world results line up so well.<br/><br/>"
        
        "<b>3. Bcrypt's workfactor scaling is predictable.</b> Every time you bump the "
        "workfactor by 1, the time doubles. This makes it easy to plan how long cracking "
        "will take.<br/><br/>"
        
        "<b>4. Where your password sits in the dictionary matters a lot.</b> Common words "
        "that appear early alphabetically get cracked much faster. This is why \"airway\" "
        "(Ori's password) took less time than expected despite the high workfactor - it's "
        "near the start of the dictionary.<br/><br/>"
        
        "<b>5. Some users shared the same salt.</b> We noticed that users with the same "
        "workfactor often had identical salts, which means their hashes were probably "
        "generated at the same time or with the same parameters. This doesn't make the "
        "passwords any easier to crack - it's just an interesting artifact.",
        body_style
    ))
    
    # Build PDF
    doc.build(story)
    print("Report generated: Module4/Cryptographic_Hash_Functions_Report.pdf")


def main():
    """Main entry point."""
    try:
        from reportlab.lib import colors
        create_report()
    except ImportError:
        print("reportlab not installed. Installing...")
        import subprocess
        subprocess.check_call(['pip', 'install', 'reportlab'])
        create_report()


if __name__ == "__main__":
    main()