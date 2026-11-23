import csv
import hashlib
import hmac
import html
import json
import os
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk

CHUNK_SIZE = 64 * 1024            
PBKDF2_ROUNDS = 200_000           
LOG_FILE = "integrity_log.txt"

STATUS_MODIFIED = "MODIFIED"
STATUS_DELETED = "DELETED"
STATUS_NEW = "NEW"
STATUS_UNCHANGED = "UNCHANGED"



def sha256_of_file(path):
    """Return the SHA-256 hex digest of a file, reading it chunk by chunk."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def scan_folder(folder, progress=None):
    """Walk the folder recursively and return {relative_path: {hash,size,mtime}}."""
    paths = []
    for root, _dirs, files in os.walk(folder):
        for name in files:
            paths.append(os.path.join(root, name))

    result = {}
    total = len(paths)
    for i, full in enumerate(paths, 1):
        rel = os.path.relpath(full, folder).replace("\\", "/")
        try:
            st = os.stat(full)
            result[rel] = {
                "hash": sha256_of_file(full),
                "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            }
        except (PermissionError, OSError) as e:
            result[rel] = {"hash": "UNREADABLE: " + str(e), "size": -1, "mtime": ""}
        if progress:
            progress(i, total)
    return result


def derive_key(password, salt):
    """Turn the user's password into a 32-byte key using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)


def _canonical(meta, files):
    """Stable text form of the baseline content, used as the data we sign."""
    return json.dumps({"meta": meta, "files": files}, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def sign(meta, files, key):
    """HMAC-SHA256 signature of the baseline content."""
    return hmac.new(key, _canonical(meta, files), hashlib.sha256).hexdigest()


def create_baseline(folder, password, baseline_path, progress=None):
    """Scan the folder, sign the result and save it to baseline_path."""
    files = scan_folder(folder, progress)
    salt = os.urandom(16)
    meta = {
        "folder": os.path.abspath(folder),
        "created": datetime.now().isoformat(timespec="seconds"),
        "algorithm": "SHA-256",
        "salt": salt.hex(),
        "file_count": len(files),
    }
    key = derive_key(password, salt)
    data = {"meta": meta, "files": files, "signature": sign(meta, files, key)}
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return data


def load_and_verify_baseline(baseline_path, password):
    """
    Load the baseline and check its HMAC signature.
    Returns (data, ok). ok is False if the file was edited or the password is wrong.
    """
    with open(baseline_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    meta, files = data["meta"], data["files"]
    key = derive_key(password, bytes.fromhex(meta["salt"]))
    expected = sign(meta, files, key)
    ok = hmac.compare_digest(expected, data.get("signature", ""))  
    return data, ok


def compare(baseline_files, current_files):
    """Compare baseline and current scan. Returns a list of result rows."""
    rows = []
    for path, old in baseline_files.items():
        if path not in current_files:
            rows.append((STATUS_DELETED, path, old["hash"], "-"))
        elif current_files[path]["hash"] != old["hash"]:
            rows.append((STATUS_MODIFIED, path, old["hash"], current_files[path]["hash"]))
        else:
            rows.append((STATUS_UNCHANGED, path, old["hash"], current_files[path]["hash"]))
    for path, new in current_files.items():
        if path not in baseline_files:
            rows.append((STATUS_NEW, path, "-", new["hash"]))
    order = {STATUS_MODIFIED: 0, STATUS_DELETED: 1, STATUS_NEW: 2, STATUS_UNCHANGED: 3}
    rows.sort(key=lambda r: (order[r[0]], r[1]))
    return rows


def write_log(message):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("[%s] %s\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), message))


def export_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Status", "File", "Baseline SHA-256", "Current SHA-256"])
        w.writerows(rows)


def export_html(rows, path, folder, baseline_ok):
    colors = {STATUS_MODIFIED: "#f8d7da", STATUS_DELETED: "#ffe5b4",
              STATUS_NEW: "#d1ecf1", STATUS_UNCHANGED: "#e2f0d9"}
    counts = {s: sum(1 for r in rows if r[0] == s)
              for s in (STATUS_MODIFIED, STATUS_DELETED, STATUS_NEW, STATUS_UNCHANGED)}
    body = "".join(
        "<tr style='background:%s'><td>%s</td><td>%s</td><td><code>%s</code></td>"
        "<td><code>%s</code></td></tr>"
        % (colors[r[0]], r[0], html.escape(r[1]), r[2], r[3]) for r in rows)
    sig = ("<b style='color:green'>VALID</b>" if baseline_ok
           else "<b style='color:red'>INVALID - baseline may be tampered</b>")
    page = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Integrity Report</title>
<style>body{{font-family:Segoe UI,Arial;margin:24px}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:6px;font-size:13px}}th{{background:#333;color:#fff}}</style>
</head><body>
<h2>File Integrity Report</h2>
<p>Folder: {html.escape(folder)}<br>Generated: {datetime.now():%Y-%m-%d %H:%M:%S}<br>
Baseline signature: {sig}</p>
<p>Modified: {counts[STATUS_MODIFIED]} | Deleted: {counts[STATUS_DELETED]} |
New: {counts[STATUS_NEW]} | Unchanged: {counts[STATUS_UNCHANGED]}</p>
<table><tr><th>Status</th><th>File</th><th>Baseline SHA-256</th><th>Current SHA-256</th></tr>
{body}</table></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("File Integrity Checker - SHA-256")
        self.geometry("1000x620")
        self.minsize(820, 480)

        self.folder = tk.StringVar()
        self.baseline_path = tk.StringVar(value=os.path.abspath("baseline.json"))
        self.status_text = tk.StringVar(value="Ready. Choose a folder to begin.")
        self.last_rows = []
        self.last_baseline_ok = True

        self._build_ui()

    
    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Folder to protect:").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.folder).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(top, text="Browse...", command=self.pick_folder).grid(row=0, column=2)

        ttk.Label(top, text="Baseline file:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(top, textvariable=self.baseline_path).grid(row=1, column=1, sticky="ew",
                                                              padx=6, pady=(6, 0))
        ttk.Button(top, text="Browse...", command=self.pick_baseline).grid(row=1, column=2,
                                                                          pady=(6, 0))
        top.columnconfigure(1, weight=1)

        btns = ttk.Frame(self, padding=(10, 0))
        btns.pack(fill="x")
        self.btn_create = ttk.Button(btns, text="1. Create Baseline", command=self.on_create)
        self.btn_verify = ttk.Button(btns, text="2. Verify Integrity", command=self.on_verify)
        self.btn_csv = ttk.Button(btns, text="Export CSV", command=self.on_csv)
        self.btn_html = ttk.Button(btns, text="Export HTML Report", command=self.on_html)
        self.btn_log = ttk.Button(btns, text="View Log", command=self.on_log)
        for b in (self.btn_create, self.btn_verify, self.btn_csv, self.btn_html, self.btn_log):
            b.pack(side="left", padx=(0, 6), pady=8)

        
        self.banner = tk.Label(self, text="", anchor="w", font=("Segoe UI", 10, "bold"),
                               padx=10, pady=6)
        self.banner.pack(fill="x", padx=10)

        
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill="both", expand=True)
        cols = ("status", "file", "old", "new")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings")
        heads = {"status": ("Status", 100), "file": ("File", 330),
                 "old": ("Baseline SHA-256", 230), "new": ("Current SHA-256", 230)}
        for c in cols:
            self.tree.heading(c, text=heads[c][0])
            self.tree.column(c, width=heads[c][1], anchor="w")
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self.tree.tag_configure(STATUS_MODIFIED, background="#f8d7da")
        self.tree.tag_configure(STATUS_DELETED, background="#ffe5b4")
        self.tree.tag_configure(STATUS_NEW, background="#d1ecf1")
        self.tree.tag_configure(STATUS_UNCHANGED, background="#e2f0d9")

        
        bottom = ttk.Frame(self, padding=(10, 0, 10, 10))
        bottom.pack(fill="x")
        self.progress = ttk.Progressbar(bottom, mode="determinate")
        self.progress.pack(fill="x")
        ttk.Label(bottom, textvariable=self.status_text).pack(anchor="w", pady=(4, 0))

    
    def pick_folder(self):
        d = filedialog.askdirectory(title="Select folder to protect")
        if d:
            self.folder.set(d)

    def pick_baseline(self):
        p = filedialog.asksaveasfilename(title="Baseline file", defaultextension=".json",
                                         initialfile="baseline.json",
                                         filetypes=[("JSON", "*.json")],
                                         confirmoverwrite=False)
        if p:
            self.baseline_path.set(p)

    def set_busy(self, busy):
        state = "disabled" if busy else "normal"
        for b in (self.btn_create, self.btn_verify):
            b.config(state=state)

    def update_progress(self, i, total):
        
        self.after(0, lambda: (self.progress.config(maximum=total, value=i),
                               self.status_text.set("Hashing file %d of %d ..." % (i, total))))

    def ask_password(self, confirm=False):
        pw = simpledialog.askstring("Password", "Enter baseline password:", show="*", parent=self)
        if not pw:
            return None
        if confirm:
            pw2 = simpledialog.askstring("Password", "Re-enter password:", show="*", parent=self)
            if pw != pw2:
                messagebox.showerror("Mismatch", "Passwords do not match.")
                return None
        return pw

    def show_banner(self, text, color):
        self.banner.config(text=text, bg=color)

    def fill_table(self, rows):
        self.tree.delete(*self.tree.get_children())
        for status, path, old, new in rows:
            self.tree.insert("", "end", values=(status, path, old, new), tags=(status,))

    
    def on_create(self):
        folder = self.folder.get()
        if not os.path.isdir(folder):
            messagebox.showwarning("Folder", "Please choose a valid folder first.")
            return
        bpath = self.baseline_path.get()
        if os.path.exists(bpath) and not messagebox.askyesno(
                "Overwrite?", "A baseline already exists at this location.\nReplace it?"):
            return
        pw = self.ask_password(confirm=True)
        if not pw:
            return

        self.set_busy(True)

        def work():
            try:
                data = create_baseline(folder, pw, bpath, self.update_progress)
                n = data["meta"]["file_count"]
                write_log("BASELINE created for %s (%d files) -> %s" % (folder, n, bpath))
                self.after(0, lambda: self.finish_create(n))
            except Exception as e:
                self.after(0, lambda: self.fail(str(e)))

        threading.Thread(target=work, daemon=True).start()

    def finish_create(self, n):
        self.set_busy(False)
        self.tree.delete(*self.tree.get_children())
        self.show_banner("Baseline created and signed: %d files recorded." % n, "#d4edda")
        self.status_text.set("Baseline saved. Run 'Verify Integrity' whenever you want to check.")

    def on_verify(self):
        folder = self.folder.get()
        bpath = self.baseline_path.get()
        if not os.path.isdir(folder):
            messagebox.showwarning("Folder", "Please choose a valid folder first.")
            return
        if not os.path.isfile(bpath):
            messagebox.showwarning("Baseline", "Baseline file not found. Create one first.")
            return
        pw = self.ask_password()
        if not pw:
            return

        self.set_busy(True)

        def work():
            try:
                data, ok = load_and_verify_baseline(bpath, pw)
                if not ok:
                    self.after(0, self.baseline_invalid)
                    return
                current = scan_folder(folder, self.update_progress)
                rows = compare(data["files"], current)
                self.after(0, lambda: self.finish_verify(rows, ok))
            except Exception as e:
                self.after(0, lambda: self.fail(str(e)))

        threading.Thread(target=work, daemon=True).start()

    def baseline_invalid(self):
        self.set_busy(False)
        self.last_rows, self.last_baseline_ok = [], False
        self.tree.delete(*self.tree.get_children())
        self.show_banner("WARNING: baseline signature INVALID. The baseline was edited or the "
                         "password is wrong. Results cannot be trusted.", "#f5c6cb")
        self.status_text.set("Verification stopped.")
        write_log("ALERT: baseline signature INVALID (tampered or wrong password)")
        messagebox.showerror("Baseline tampered?",
                             "The baseline's signature does not match.\n\n"
                             "Either the baseline file was modified, or the password is wrong.")

    def finish_verify(self, rows, ok):
        self.set_busy(False)
        self.last_rows, self.last_baseline_ok = rows, ok
        self.fill_table(rows)
        cnt = {s: sum(1 for r in rows if r[0] == s)
               for s in (STATUS_MODIFIED, STATUS_DELETED, STATUS_NEW, STATUS_UNCHANGED)}
        summary = "Modified: %d   Deleted: %d   New: %d   Unchanged: %d" % (
            cnt[STATUS_MODIFIED], cnt[STATUS_DELETED], cnt[STATUS_NEW], cnt[STATUS_UNCHANGED])
        changed = cnt[STATUS_MODIFIED] + cnt[STATUS_DELETED] + cnt[STATUS_NEW]
        if changed:
            self.show_banner("CHANGES DETECTED -  " + summary, "#f8d7da")
        else:
            self.show_banner("All files intact -  " + summary, "#d4edda")
        self.status_text.set("Verification complete.")
        write_log("VERIFY %s -> %s" % (self.folder.get(), summary))

    def fail(self, msg):
        self.set_busy(False)
        self.status_text.set("Error: " + msg)
        write_log("ERROR: " + msg)
        messagebox.showerror("Error", msg)

    def on_csv(self):
        if not self.last_rows:
            messagebox.showinfo("Export", "Run a verification first.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                         initialfile="integrity_report.csv")
        if p:
            export_csv(self.last_rows, p)
            self.status_text.set("CSV saved: " + p)

    def on_html(self):
        if not self.last_rows:
            messagebox.showinfo("Export", "Run a verification first.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")],
                                         initialfile="integrity_report.html")
        if p:
            export_html(self.last_rows, p, self.folder.get(), self.last_baseline_ok)
            self.status_text.set("HTML report saved: " + p)

    def on_log(self):
        win = tk.Toplevel(self)
        win.title("Activity Log")
        win.geometry("700x400")
        txt = tk.Text(win, wrap="none")
        txt.pack(fill="both", expand=True)
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                txt.insert("1.0", f.read())
        except FileNotFoundError:
            txt.insert("1.0", "No log entries yet.")
        txt.config(state="disabled")


if __name__ == "__main__":
    App().mainloop()
