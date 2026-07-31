from __future__ import annotations

import os
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import messagebox, ttk

from pihole_manager import __version__
from pihole_manager.config import Options, load_options, save_options
from pihole_manager.updater import (
    InstallPlan,
    UpdateInfo,
    can_install_update,
    check_for_update,
    download_update,
    launch_update_installer,
    prepare_update_install,
)

_CHANNEL_LABELS = {
    "Stable releases": "stable",
    "Prerelease versions": "prerelease",
}
_CHANNEL_NAMES = {value: key for key, value in _CHANNEL_LABELS.items()}


class ApplicationSettingsPage(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, padding=12)
        self.columnconfigure(1, weight=1)
        self.options: Options | None = None
        self._checking_updates = False

        self.logging_enabled = tk.BooleanVar()
        self.logging_level = tk.StringVar()
        self.logging_filename = tk.StringVar()
        self.theme = tk.StringVar()
        self.show_tooltips = tk.BooleanVar()
        self.check_updates_automatically = tk.BooleanVar()
        self.update_channel = tk.StringVar()
        self.update_interval = tk.StringVar()

        ttk.Checkbutton(
            self,
            text="Show tooltips",
            variable=self.show_tooltips,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        ttk.Checkbutton(
            self,
            text="Write rotating log file",
            variable=self.logging_enabled,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=4)
        self._row(
            "Log level",
            self.logging_level,
            2,
            values=("DEBUG", "INFO", "WARNING", "ERROR"),
        )
        self._row("Log filename", self.logging_filename, 3)
        self._row("Theme", self.theme, 4, values=("system", "light", "dark"))

        updates = ttk.LabelFrame(self, text="Application updates", padding=10)
        updates.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(16, 0))
        updates.columnconfigure(1, weight=1)
        ttk.Label(updates, text=f"Installed version: {__version__}").grid(
            row=0,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(0, 6),
        )
        ttk.Checkbutton(
            updates,
            text="Automatically check for updates",
            variable=self.check_updates_automatically,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=3)
        ttk.Label(updates, text="Update channel").grid(
            row=2,
            column=0,
            sticky="w",
            pady=3,
        )
        ttk.Combobox(
            updates,
            textvariable=self.update_channel,
            values=tuple(_CHANNEL_LABELS),
            state="readonly",
            width=32,
        ).grid(row=2, column=1, sticky="w", padx=(10, 0), pady=3)
        ttk.Label(updates, text="Check interval (hours)").grid(
            row=3,
            column=0,
            sticky="w",
            pady=3,
        )
        ttk.Entry(updates, textvariable=self.update_interval, width=10).grid(
            row=3,
            column=1,
            sticky="w",
            padx=(10, 0),
            pady=3,
        )
        self.check_update_button = ttk.Button(
            updates,
            text="Check for updates",
            command=self.check_for_updates,
        )
        self.check_update_button.grid(row=4, column=0, sticky="w", pady=(8, 0))
        self.update_status = ttk.Label(updates, text="", wraplength=720, justify="left")
        self.update_status.grid(
            row=5,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(8, 0),
        )

    def _row(
        self,
        label: str,
        variable: tk.StringVar,
        row: int,
        values: tuple[str, ...] | None = None,
    ) -> None:
        ttk.Label(self, text=label).grid(row=row, column=0, sticky="w", pady=4)
        if values:
            widget = ttk.Combobox(
                self,
                textvariable=variable,
                values=values,
                state="readonly",
            )
        else:
            widget = ttk.Entry(self, textvariable=variable)
        widget.grid(row=row, column=1, sticky="ew", padx=(10, 0), pady=4)

    def load(self, options: Options) -> None:
        self.options = options
        self.logging_enabled.set(options.logging.enabled)
        self.logging_level.set(options.logging.level)
        self.logging_filename.set(options.logging.filename)
        self.theme.set(options.ui.theme)
        self.show_tooltips.set(options.ui.show_tooltips)
        self.check_updates_automatically.set(options.updates.check_automatically)
        self.update_channel.set(_CHANNEL_NAMES.get(options.updates.channel, "Stable releases"))
        self.update_interval.set(str(options.updates.check_interval_hours))

    def store(self, options: Options) -> bool:
        try:
            update_interval = max(1, int(self.update_interval.get()))
        except ValueError:
            messagebox.showerror("Application", "Update interval must be a whole number.")
            return False
        options.logging.enabled = self.logging_enabled.get()
        options.logging.level = self.logging_level.get()
        options.logging.filename = self.logging_filename.get().strip()
        options.ui.theme = self.theme.get()
        options.ui.show_tooltips = self.show_tooltips.get()
        options.updates.check_automatically = self.check_updates_automatically.get()
        options.updates.channel = _CHANNEL_LABELS.get(self.update_channel.get(), "stable")
        options.updates.check_interval_hours = update_interval
        return True

    def check_for_updates(self, *, silent: bool = False) -> None:
        if self._checking_updates:
            return
        channel = _CHANNEL_LABELS.get(self.update_channel.get(), "stable")
        self._checking_updates = True
        self.check_update_button.state(["disabled"])
        self.check_update_button.configure(text="Checking …")
        self.update_status.configure(text="Checking GitHub releases …")
        threading.Thread(
            target=self._check_worker,
            args=(channel, silent),
            name="UpdateCheck",
            daemon=True,
        ).start()

    def _check_worker(self, channel: str, silent: bool) -> None:
        try:
            update = check_for_update(channel=channel)
        except Exception as exc:
            self.after(0, self._check_failed, str(exc), silent)
            return
        self.after(0, self._check_finished, update, silent)

    def _check_failed(self, error: str, silent: bool) -> None:
        self._finish_check_controls()
        self.update_status.configure(text=f"Update check failed: {error}")
        self._record_check_time()
        if not silent:
            messagebox.showerror("Application update", f"Update check failed:\n{error}")

    def _check_finished(self, update: UpdateInfo, silent: bool) -> None:
        self._finish_check_controls()
        self._record_check_time()
        if not update.available:
            channel = _CHANNEL_NAMES.get(update.channel, update.channel)
            self.update_status.configure(text=f"No newer {channel.lower()} build is available.")
            if not silent:
                messagebox.showinfo("Application update", "No update is available.")
            return

        self.update_status.configure(
            text=f"Available: {update.release_name} ({update.channel} channel)"
        )
        if update.asset is None:
            if messagebox.askyesno(
                "Application update",
                "A newer build is available, but the release contains no compatible "
                "Onedir ZIP for this operating system and architecture. Open the release page?",
            ):
                webbrowser.open(update.release_url)
            return

        if messagebox.askyesno(
            "Application update",
            f"{update.release_name} is available. Download it now?",
        ):
            self._download_update(update)

    def _download_update(self, update: UpdateInfo) -> None:
        asset = update.asset
        if asset is None:
            self.update_status.configure(text="No compatible update asset is available.")
            messagebox.showerror(
                "Application update",
                "The release contains no compatible downloadable Onedir ZIP asset.",
            )
            return
        self._checking_updates = True
        self.check_update_button.state(["disabled"])
        self.check_update_button.configure(text="Downloading …")
        self.update_status.configure(text=f"Downloading {asset.name} …")
        threading.Thread(
            target=self._download_worker,
            args=(update,),
            name="UpdateDownload",
            daemon=True,
        ).start()

    def _download_worker(self, update: UpdateInfo) -> None:
        try:
            result = download_update(update)
        except Exception as exc:
            self.after(0, self._download_failed, str(exc))
            return
        self.after(0, self._download_finished, update, result.path, result.verified)

    def _download_failed(self, error: str) -> None:
        self._finish_check_controls()
        self.update_status.configure(text=f"Update download failed: {error}")
        messagebox.showerror("Application update", f"Update download failed:\n{error}")

    def _download_finished(
        self,
        update: UpdateInfo,
        path: Path,
        verified: bool,
    ) -> None:
        self._finish_check_controls()
        verification = "SHA-256 verified" if verified else "no published digest"
        self.update_status.configure(text=f"Downloaded to {path} ({verification}).")
        if can_install_update():
            if messagebox.askyesno(
                "Application update",
                "The update is ready. Install it now and restart Pi-hole Manager?\n\n"
                "The current Onedir version is backed up automatically and restored if "
                "the new version cannot start.",
            ):
                self._prepare_install(update, path)
            return
        if messagebox.askyesno(
            "Application update",
            "The update was downloaded. Automatic installation is available only in a "
            "packaged Onedir build. Open the download folder?",
        ):
            self._open_folder(path.parent)

    def _prepare_install(self, update: UpdateInfo, path: Path) -> None:
        self._checking_updates = True
        self.check_update_button.state(["disabled"])
        self.check_update_button.configure(text="Preparing …")
        self.update_status.configure(text="Validating and preparing the update …")
        threading.Thread(
            target=self._prepare_install_worker,
            args=(update, path),
            name="UpdatePrepare",
            daemon=True,
        ).start()

    def _prepare_install_worker(self, update: UpdateInfo, path: Path) -> None:
        try:
            plan = prepare_update_install(update, path)
        except Exception as exc:
            self.after(0, self._install_failed, str(exc))
            return
        self.after(0, self._install_ready, plan)

    def _install_ready(self, plan: InstallPlan) -> None:
        try:
            launch_update_installer(plan, parent_pid=os.getpid())
        except Exception as exc:
            self._install_failed(str(exc))
            return
        self.update_status.configure(text="Update prepared. Closing for installation …")
        root = self.winfo_toplevel()
        closer = getattr(root, "_on_close", root.destroy)
        self.after(150, closer)

    def _install_failed(self, error: str) -> None:
        self._finish_check_controls()
        self.update_status.configure(text=f"Update installation failed: {error}")
        messagebox.showerror("Application update", f"Could not install the update:\n{error}")

    def _finish_check_controls(self) -> None:
        self._checking_updates = False
        self.check_update_button.state(["!disabled"])
        self.check_update_button.configure(text="Check for updates")

    def _record_check_time(self) -> None:
        options = load_options()
        options.updates.last_check_at = int(time.time())
        save_options(options)
        if self.options is not None:
            self.options.updates.last_check_at = options.updates.last_check_at

    @staticmethod
    def _open_folder(path: Path) -> None:
        if os.name == "nt":
            os.startfile(path)  # type: ignore[attr-defined]
        else:
            webbrowser.open(path.resolve().as_uri())
