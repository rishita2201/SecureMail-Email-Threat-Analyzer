import re
import whois
import tkinter as tk
from tkinter import scrolledtext, messagebox
from email.parser import Parser

SPAM_KEYWORDS = ['free', 'win', 'prize', 'urgent', 'claim now','limited time','your account has been suspensed','free gift','money back','order now','double your income','zero risk','one time offer','call now','once in a lifetime']
ATTACHMENT_KEYWORDS = ['attachment', 'attached', 'file', 'document', 'see the file']

def parse_email_header(email_content):
    email = Parser().parsestr(email_content)
    header = {
        'from': email['From'],
        'subject': email['Subject'],
        'date': email['Date']
    }
    return header

def detect_spam(content):
    for keyword in SPAM_KEYWORDS:
        if keyword.lower() in content.lower():
            return True
    return False

def find_phishing_urls(content):
    urls = re.findall(r'http[s]?://\S+', content)
    phishing_urls = []
    for url in urls:
        try:
            domain = url.split('/')[2]
            whois_info = whois.whois(domain)
            if not whois_info.domain_name:
                phishing_urls.append(url)
        except:
            phishing_urls.append(url)
    return phishing_urls

def check_email_domain(email_from):
    if not email_from or '@' not in email_from:
        return False
    try:
        domain = email_from.split('@')[1]
        w = whois.whois(domain)
        if w.domain_name:
            return True
    except:
        pass
    return False

def check_for_attachments(content):
    for keyword in ATTACHMENT_KEYWORDS:
        if keyword.lower() in content.lower():
            return True
    return False

def analyze_email(email_content):
    results = {}
    header = parse_email_header(email_content)
    results['header'] = header
    results['is_spam'] = detect_spam(email_content)
    results['phishing_urls'] = find_phishing_urls(email_content)
    results['sender_domain_ok'] = check_email_domain(header['from'])
    results['has_attachment'] = check_for_attachments(email_content)
    return results

# GUI Code Below
def analyze():
    email_content = input_text.get("1.0", tk.END).strip()
    if not email_content:
        messagebox.showwarning("Input Error", "Please paste the email content.")
        return

    results = analyze_email(email_content)

    output = f"--- Email Header ---\n"
    output += f"From: {results['header'].get('from', 'N/A')}\n"
    output += f"Subject: {results['header'].get('subject', 'N/A')}\n"
    output += f"Date: {results['header'].get('date', 'N/A')}\n\n"

    output += f"--- Analysis ---\n"
    output += "SPAM: " + ("Yes, detected as spam" if results['is_spam'] else "No, this is a legit email") + "\n"
    output += "Phishing URLs: " + (', '.join(results['phishing_urls']) if results['phishing_urls'] else "None ") + "\n"
    output += "Sender's Domain: " + ("Legit email" if results['sender_domain_ok'] else "Suspicious email") + "\n"
    output += "Mentions Attachments: " + ("Yes, this email has attachments" if results['has_attachment'] else "No") + "\n"

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, output)


window = tk.Tk()
window.title("Email Threat Analyzer")
window.geometry("750x650")


tk.Label(window, text="Paste Raw Email Content Below:", font=('Arial', 12, 'bold')).pack(pady=5)


input_text = scrolledtext.ScrolledText(window, height=15, width=90, font=('Courier', 10))
input_text.pack(padx=10, pady=5)


tk.Button(window, text="Analyze Email", command=analyze, bg="skyblue", font=('Arial', 12, 'bold')).pack(pady=10)


tk.Label(window, text="Analysis Result:", font=('Arial', 12, 'bold')).pack(pady=5)


output_text = scrolledtext.ScrolledText(window, height=15, width=90, font=('Courier', 10))
output_text.pack(padx=10, pady=5)


window.mainloop()
