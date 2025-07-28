# Final Full Smart Password Audit Tool with 30+ Features
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
import os, re, math, time, random, string, hashlib, requests
from zxcvbn import zxcvbn
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from email.message import EmailMessage
from cryptography.fernet import Fernet
import base64, smtplib

# ============ CONFIG ============
SENDER_EMAIL = "srushtinikam8042@gmail.com"
APP_PASSWORD = "rzatbyhqxpgeobsy"
# ============ SESSION + THEME ============
session_stats = {"Weak": 0, "Medium": 0, "Strong": 0}
is_dark_mode = False
light_theme = {"bg": "#f0f0f0", "frame": "#ffffff", "fg": "black"}
dark_theme = {"bg": "#222222", "frame": "#333333", "fg": "white"}

# ============ FUNCTIONS ============
def calculate_entropy(pwd):
    if not pwd: return 0
    pool = len(set(pwd))
    entropy = -sum(pwd.count(c)/len(pwd) * math.log2(pwd.count(c)/len(pwd)) for c in set(pwd))
    return round(entropy * len(pwd), 2)

def classify_password(pwd):
    if len(pwd) < 6: return "Very Short"
    if re.fullmatch(r"[a-zA-Z]+", pwd): return "Dictionary Word"
    if re.fullmatch(r"\d+", pwd): return "Only Numbers"
    if re.fullmatch(r"[A-Za-z0-9]+", pwd): return "Alphanumeric"
    return "Complex / Random"

def detect_patterns(pwd):
    patterns = []
    if re.search(r"(.)\1{2,}", pwd): patterns.append("Repeated chars")
    if re.search(r"\d{4}", pwd): patterns.append("Year")
    if re.search(r"[A-Za-z]+\d+", pwd): patterns.append("Letters+Numbers")
    if re.search(r"(password|admin|qwerty)", pwd, re.I): patterns.append("Common Word")
    return patterns or ["No obvious patterns"]

def generate_ai_tip(pwd, score, entropy, patterns):
    if len(pwd) < 6: return "❌ Too short. Use longer passphrases."
    if score <= 1: return "⚠️ Weak. Add length, symbols, and mix cases."
    if score == 2: return "🟡 Medium. Add randomness or symbols."
    if score >= 3 and entropy >= 50:
        if "Year" in patterns or "Repeated chars" in patterns:
            return "✅ Strong, but avoid dates or repeats."
        return "✅ Strong password with high entropy!"
    return "🧠 Secure, but can improve."

def breach_check(pwd):
    sha1 = hashlib.sha1(pwd.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        for line in res.text.splitlines():
            if line.startswith(suffix): return f"⚠️ Found in {line.split(':')[1]} breaches"
        return "✅ Not found in known breaches."
    except:
        return "⚠️ Network error"

def suggest_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(chars) for _ in range(length))

def derive_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def log_password(pwd, score, entropy, crack_time):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    masked = '*' * len(pwd)
    with open("password_history_log.txt", "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {masked} | Score: {score} | Entropy: {entropy} | Crack Time: {crack_time}\n")

def export_session_stats():
    with open("session_summary.txt", "w") as f:
        f.write("🔐 Session Summary:\n")
        for k, v in session_stats.items():
            f.write(f"{k}: {v}\n")
    messagebox.showinfo("Saved", "Session summary saved.")

def export_encrypted_wordlist():
    words = [suggest_password(10) for _ in range(20)]
    password = simpledialog.askstring("Encrypt", "Enter password to encrypt:", show="*")
    if not password: return
    key = derive_key(password)
    fernet = Fernet(key)
    encrypted = fernet.encrypt('\n'.join(words).encode())
    with open("encrypted_wordlist.bin", "wb") as f:
        f.write(encrypted)
    messagebox.showinfo("Saved", "Encrypted wordlist saved.")

def view_log():
    if not os.path.exists("password_history_log.txt"):
        messagebox.showinfo("Log", "No log found.")
        return
    win = tk.Toplevel(root)
    win.title("📜 Password History Log")
    text = tk.Text(win, wrap="word", font=("Consolas", 10))
    text.pack(expand=True, fill="both")
    with open("password_history_log.txt", "r", encoding="utf-8") as f:
        text.insert("1.0", f.read())

def copy_suggestion():
    pwd = suggest_password()
    entry.delete(0, tk.END)
    entry.insert(0, pwd)
    root.clipboard_clear()
    root.clipboard_append(pwd)
    messagebox.showinfo("Copied", f"Suggested password copied:\n{pwd}")

def toggle_theme():
    global is_dark_mode
    is_dark_mode = not is_dark_mode
    theme = dark_theme if is_dark_mode else light_theme
    root.config(bg=theme["bg"])
    canvas_frame.config(bg=theme["bg"])
    for w in root.winfo_children():
        try: w.config(bg=theme["bg"], fg=theme["fg"])
        except: pass
    for w in output_frame.winfo_children():
        w.config(bg=theme["frame"], fg=theme["fg"])

def show_graph(score, entropy):
    for w in canvas_frame.winfo_children():
        w.destroy()
    fig, ax = plt.subplots(figsize=(3.5, 2.5))
    bars = ax.bar(["Score", "Entropy"], [score, entropy], color=["#ff5722", "#00c853"])
    for bar in bars:
        ax.annotate(f"{bar.get_height():.1f}", (bar.get_x()+0.2, bar.get_height()+1))
    ax.set_ylim(0, max(5, entropy + 10))
    canvas = FigureCanvasTkAgg(fig, master=canvas_frame)
    canvas.draw()
    canvas.get_tk_widget().pack()

def analyze():
    pwd = entry.get()
    if not pwd: return
    result = zxcvbn(pwd)
    score = result['score']
    crack = result['crack_times_display']['offline_fast_hashing_1e10_per_second']
    entropy = calculate_entropy(pwd)
    patterns = detect_patterns(pwd)
    tip = generate_ai_tip(pwd, score, entropy, patterns)
    breach = breach_check(pwd)
    category = classify_password(pwd)

    # Update session stats
    if score <= 1: session_stats["Weak"] += 1
    elif score == 2: session_stats["Medium"] += 1
    else: session_stats["Strong"] += 1
    log_password(pwd, score, entropy, crack)
    show_graph(score, entropy)

    # Update UI
    output_text.set(f"""\
🧠 Score: {score}        Entropy: {entropy:.2f} bits
⏳ Crack Time: {crack}
🔎 Patterns: {", ".join(patterns)}
📂 Category: {category}
📢 Advice: {tip}
🧬 Breach: {breach}

""")
    strength_msg = ["🟥 Very Weak", "🟥 Weak", "🟨 Medium", "🟩 Strong", "🟩 Very Strong"][score]
    strength_color = ["red", "red", "orange", "green", "green"][score]
    strength_label.config(text=f"Password Strength: {strength_msg}", fg=strength_color)

# ============ GUI SETUP ============
root = tk.Tk()
root.title("Smart Password Audit Tool")
root.geometry("750x780")
theme = light_theme
root.config(bg=theme["bg"])

tk.Label(root, text="Enter Password:", font=("Helvetica", 13), bg=theme["bg"]).pack()
entry = tk.Entry(root, font=("Helvetica", 13), width=40, show="*")
entry.pack(pady=6)

tk.Button(root, text="👁 Show/Hide", command=lambda: entry.config(show='' if entry.cget('show') == '*' else '*')).pack(pady=2)

output_frame = tk.Frame(root, bg=theme["frame"], bd=2, relief="sunken")
output_frame.pack(pady=10, padx=10, fill="both", expand=False)
output_text = tk.StringVar()
strength_label = tk.Label(output_frame, text="", font=("Helvetica", 13, "bold"), bg=theme["frame"])
strength_label.pack(anchor="w", pady=5)
 
tk.Label(output_frame, textvariable=output_text, justify="left", font=("Consolas", 11), bg=theme["frame"], anchor="w").pack(anchor="w")

canvas_frame = tk.Frame(root, bg=theme["bg"])
canvas_frame.pack(pady=10)

# ============ BUTTONS ============
button_frame = tk.Frame(root, bg=theme["bg"])
button_frame.pack(pady=10)

buttons = [
    ("Analyze", analyze, "#2196f3"),
    ("Suggest Password", copy_suggestion, "#ff5722"),
    ("Copy Pw", lambda: root.clipboard_append(entry.get()), "#009688"),
    ("Export PDF", export_session_stats, "#4caf50"),
    ("Encrypt Log", export_encrypted_wordlist, "#9c27b0"),
    ("Export Stats", export_session_stats, "#795548"),
    ("View Log", view_log, "#607d8b"),
    ("Toggle Theme", toggle_theme, "#212121"),
]

for text, cmd, color in buttons:
    tk.Button(button_frame, text=text, command=cmd, bg=color, fg="white", font=("Helvetica", 11), width=16).pack(pady=3)

# ============ RUN ============
root.mainloop()
