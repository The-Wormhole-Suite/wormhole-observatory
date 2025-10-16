# gui.py – Tkinter GUI for Pi-hole Manager (clean version, no markdown)

import tkinter as tk
from tkinter import ttk, messagebox
import logging, time
from logging_setup import setup_logging
from config import load_options, save_options, LLMProvider, PromptProfile
from workers import get_scanner
from db import init_db
from pihole import client
from llm import classify_domain

log = logging.getLogger(__name__)

# ------------------------------------------------------------
# Tabs
# ------------------------------------------------------------

class QueriesTab(ttk.Frame):
    """Live query view with periodic delta polling."""
    def __init__(self, master):
        super().__init__(master)
        self.last_ts = int(time.time()) - 60
        self.running = True

        toolbar = ttk.Frame(self)
        toolbar.pack(fill=tk.X, padx=8, pady=6)
        ttk.Label(toolbar, text="Live Query View").pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Refresh now", command=self._refresh_once).pack(side=tk.LEFT, padx=8)
        self.status_var = tk.StringVar(value="idle")
        ttk.Label(toolbar, textvariable=self.status_var).pack(side=tk.RIGHT)

        cols = ("ts", "domain", "client", "status", "type")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=20)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=160 if c == "domain" else 100, anchor="w")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        self.after(1000, self._poll_loop)

    def _refresh_once(self):
        self._poll_queries()

    def _poll_loop(self):
        if not self.running:
            return
        try:
            self._poll_queries()
        except Exception as e:
            log.exception("Live poll error: %s", e)
        self.after(1500, self._poll_loop)

    def _poll_queries(self):
        self.status_var.set("polling…")
        queries = client.poll_queries_since(self.last_ts)
        if queries:
            self.last_ts = max(q.get("ts", self.last_ts) for q in queries)
            for q in queries:
                ts, domain, client_ip, status, qtype = (
                    q.get("ts"), q.get("domain"), q.get("client"),
                    q.get("status"), q.get("type")
                )
                self.tree.insert("", "end", values=(ts, domain, client_ip, status, qtype))
        self.status_var.set("idle")

    def destroy(self):
        self.running = False
        super().destroy()


class ListsTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        ttk.Label(self, text="Allow/Deny list mirror (to be implemented)").pack(anchor="w", padx=8, pady=8)


class ClassifyTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        frm = ttk.Frame(self)
        frm.pack(fill=tk.X, padx=8, pady=8)
        ttk.Label(frm, text="Domain:").pack(side=tk.LEFT)
        self.domain_var = tk.StringVar(value="example.com")
        ttk.Entry(frm, textvariable=self.domain_var, width=40).pack(side=tk.LEFT, padx=6)
        ttk.Button(frm, text="Classify", command=self._classify).pack(side=tk.LEFT)
        self.out = tk.Text(self, height=20)
        self.out.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    def _classify(self):
        d = self.domain_var.get().strip()
        if not d:
            return
        res = classify_domain(d)
        self.out.insert("end", f"{d}: {res}\n")
        self.out.see("end")


class LLMSettingsTab(ttk.Frame):
    """Basic editing for first LLM provider and the first prompt profile."""
    def __init__(self, master):
        super().__init__(master)
        self.opts = load_options()

        col = ttk.Frame(self)
        col.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        # Provider
        prov = self.opts.llm_providers[0] if self.opts.llm_providers else LLMProvider()
        lf = ttk.LabelFrame(col, text="LLM Provider (first)")
        lf.pack(fill=tk.X, pady=6)
        self.base_url = tk.StringVar(value=prov.base_url)
        self.api_key = tk.StringVar(value=prov.api_key)
        self.model = tk.StringVar(value=prov.model)
        self.temp = tk.DoubleVar(value=prov.temperature)
        ttk.Label(lf, text="Base URL:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        ttk.Entry(lf, textvariable=self.base_url, width=50).grid(row=0, column=1, sticky="w", padx=6, pady=4)
        ttk.Label(lf, text="API Key:").grid(row=1, column=0, sticky="w", padx=6, pady=4)
        ttk.Entry(lf, textvariable=self.api_key, width=50, show="*").grid(row=1, column=1, sticky="w", padx=6, pady=4)
        ttk.Label(lf, text="Model:").grid(row=2, column=0, sticky="w", padx=6, pady=4)
        ttk.Entry(lf, textvariable=self.model, width=50).grid(row=2, column=1, sticky="w", padx=6, pady=4)
        ttk.Label(lf, text="Temperature:").grid(row=3, column=0, sticky="w", padx=6, pady=4)
        ttk.Entry(lf, textvariable=self.temp, width=10).grid(row=3, column=1, sticky="w", padx=6, pady=4)

        # Profile
        prof = self.opts.prompt_profiles[0] if self.opts.prompt_profiles else PromptProfile()
        lf2 = ttk.LabelFrame(col, text="Prompt Profile (first)")
        lf2.pack(fill=tk.BOTH, expand=True, pady=6)
        self.system = tk.Text(lf2, height=4)
        self.system.insert("1.0", prof.system)
        self.user_template = tk.Text(lf2, height=8)
        self.user_template.insert("1.0", prof.user_template)
        ttk.Label(lf2, text="System:").grid(row=0, column=0, sticky="nw", padx=6, pady=4)
        self.system.grid(row=0, column=1, sticky="nsew", padx=6, pady=4)
        ttk.Label(lf2, text="User Template:").grid(row=1, column=0, sticky="nw", padx=6, pady=4)
        self.user_template.grid(row=1, column=1, sticky="nsew", padx=6, pady=4)
        lf2.columnconfigure(1, weight=1)

        btns = ttk.Frame(col)
        btns.pack(fill=tk.X, pady=8)
        ttk.Button(btns, text="Save", command=self._save).pack(side=tk.RIGHT)

    def _save(self):
        opts = self.opts
        if not opts.llm_providers:
            opts.llm_providers.append(LLMProvider())
        p = opts.llm_providers[0]
        p.base_url = self.base_url.get().strip()
        p.api_key = self.api_key.get().strip()
        p.model = self.model.get().strip()
        try:
            p.temperature = float(self.temp.get())
        except Exception:
            p.temperature = 0.1
        if not opts.prompt_profiles:
            opts.prompt_profiles.append(PromptProfile())
        prof = opts.prompt_profiles[0]
        prof.system = self.system.get("1.0", "end").strip()
        prof.user_template = self.user_template.get("1.0", "end").strip()
        save_options(opts)
        messagebox.showinfo("Saved", "LLM settings saved.")


class PiHoleSettingsTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.opts = load_options()

        col = ttk.Frame(self)
        col.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        # Pi-hole
        lf = ttk.LabelFrame(col, text="Pi-hole")
        lf.pack(fill=tk.X, pady=6)
        self.host_var = tk.StringVar(value=self.opts.pihole.host)
        self.pw_var = tk.StringVar(value=self.opts.pihole.app_password)
        ttk.Label(lf, text="Host URL:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        ttk.Entry(lf, textvariable=self.host_var, width=50).grid(row=0, column=1, sticky="w", padx=6, pady=4)
        ttk.Label(lf, text="App Password:").grid(row=1, column=0, sticky="w", padx=6, pady=4)
        ttk.Entry(lf, textvariable=self.pw_var, width=50, show="*").grid(row=1, column=1, sticky="w", padx=6, pady=4)
        ttk.Button(lf, text="Login (test)", command=self._login).grid(row=0, column=2, rowspan=2, padx=6, pady=4)

        lf2 = ttk.LabelFrame(col, text="Scanner & Logging")
        lf2.pack(fill=tk.X, pady=6)
        self.scan_enabled = tk.BooleanVar(value=self.opts.scans.enabled)
        ttk.Checkbutton(lf2, text="Enable automatic scans", variable=self.scan_enabled, command=self._toggle_scan).grid(row=0, column=0, sticky="w", padx=6, pady=4)
        self.log_enabled = tk.BooleanVar(value=self.opts.logging.enabled)
        ttk.Checkbutton(lf2, text="Enable logging", variable=self.log_enabled, command=self._toggle_logging).grid(row=1, column=0, sticky="w", padx=6, pady=4)
        ttk.Button(col, text="Save", command=self._save).pack(anchor="e", pady=6)

    def _login(self):
        self._apply_form_to_opts()
        client.refresh_options()
        client.login()
        messagebox.showinfo("Login", "Simulated login successful.")

    def _toggle_scan(self):
        self._apply_form_to_opts()
        get_scanner().wake()

    def _toggle_logging(self):
        self._apply_form_to_opts()
        setup_logging(force=True)

    def _apply_form_to_opts(self):
        self.opts.pihole.host = self.host_var.get().strip()
        self.opts.pihole.app_password = self.pw_var.get().strip()

    def _save(self):
        self._apply_form_to_opts()
        self.opts.scans.enabled = self.scan_enabled.get()
        self.opts.logging.enabled = self.log_enabled.get()
        save_options(self.opts)
        messagebox.showinfo("Saved", "Pi-hole & logging settings saved.")


# ------------------------------------------------------------
# App
# ------------------------------------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Pi-hole Manager")
        self.geometry("1100x750")
        setup_logging()
        init_db()

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True)

        self.tab_queries = QueriesTab(nb)
        self.tab_lists = ListsTab(nb)
        self.tab_classify = ClassifyTab(nb)
        self.tab_llm_settings = LLMSettingsTab(nb)
        self.tab_pihole_settings = PiHoleSettingsTab(nb)

        nb.add(self.tab_queries, text="Live Queries")
        nb.add(self.tab_lists, text="Lists")
        nb.add(self.tab_classify, text="Classify Domain")
        nb.add(self.tab_llm_settings, text="LLM Settings")
        nb.add(self.tab_pihole_settings, text="Pi-hole Settings")

        get_scanner()


def run_app():
    app = App()
    app.mainloop()
