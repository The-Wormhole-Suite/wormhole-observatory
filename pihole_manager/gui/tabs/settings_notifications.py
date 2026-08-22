from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, ttk

from pihole_manager.config import Options
from pihole_manager.push_notifications import (
    PushNotificationOptions,
    build_review_link,
    load_push_options,
    save_push_options,
    send_push_notifications,
    unifiedpush_vapid_public_key,
)


class NotificationsSettingsPage(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, padding=12)
        self.columnconfigure(1, weight=1)
        self._options: Options | None = None

        self.enable_desktop = tk.BooleanVar()
        self.enable_sound = tk.BooleanVar()
        self.rate_limit = tk.StringVar()
        self.review_base_url = tk.StringVar()
        self.push_timeout = tk.StringVar()

        self.ntfy_enabled = tk.BooleanVar()
        self.ntfy_base_url = tk.StringVar()
        self.ntfy_topic = tk.StringVar()
        self.ntfy_token = tk.StringVar()

        self.unifiedpush_enabled = tk.BooleanVar()
        self.unifiedpush_endpoint = tk.StringVar()
        self.unifiedpush_p256dh = tk.StringVar()
        self.unifiedpush_auth = tk.StringVar()
        self.unifiedpush_subject = tk.StringVar()
        self.unifiedpush_allow_private = tk.BooleanVar()
        self.vapid_public = tk.StringVar(value="Generated after UnifiedPush is saved.")
        self.test_status = tk.StringVar()

        local = ttk.LabelFrame(self, text="Local notifications", padding=10)
        local.grid(row=0, column=0, columnspan=2, sticky="ew")
        ttk.Checkbutton(
            local,
            text="Enable desktop notifications",
            variable=self.enable_desktop,
        ).grid(row=0, column=0, sticky="w", pady=3)
        ttk.Checkbutton(
            local,
            text="Enable notification sound",
            variable=self.enable_sound,
        ).grid(row=1, column=0, sticky="w", pady=3)
        ttk.Label(local, text="Minimum interval (seconds)").grid(row=2, column=0, sticky="w", pady=3)
        ttk.Entry(local, textvariable=self.rate_limit, width=10).grid(
            row=2, column=1, sticky="w", padx=(10, 0), pady=3
        )

        common = ttk.LabelFrame(self, text="Push deep links", padding=10)
        common.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(14, 0))
        common.columnconfigure(1, weight=1)
        ttk.Label(common, text="Review app base URL").grid(row=0, column=0, sticky="w", pady=3)
        ttk.Entry(common, textvariable=self.review_base_url).grid(
            row=0, column=1, sticky="ew", padx=(10, 0), pady=3
        )
        ttk.Label(common, text="Network timeout (seconds)").grid(
            row=1, column=0, sticky="w", pady=3
        )
        ttk.Entry(common, textvariable=self.push_timeout, width=10).grid(
            row=1, column=1, sticky="w", padx=(10, 0), pady=3
        )
        ttk.Label(
            common,
            text=(
                "Use a URL reachable from the receiving device, for example a future "
                "Tailscale/HTTPS address. Notifications add ?domain=… to this URL."
            ),
            wraplength=720,
            justify="left",
        ).grid(row=2, column=0, columnspan=2, sticky="ew", pady=(4, 0))

        ntfy = ttk.LabelFrame(self, text="ntfy", padding=10)
        ntfy.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(14, 0))
        ntfy.columnconfigure(1, weight=1)
        ttk.Checkbutton(ntfy, text="Enable ntfy", variable=self.ntfy_enabled).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 5)
        )
        self._entry_row(ntfy, 1, "Server URL", self.ntfy_base_url)
        self._entry_row(ntfy, 2, "Topic", self.ntfy_topic)
        self._entry_row(ntfy, 3, "Access token (optional)", self.ntfy_token, secret=True)
        ttk.Label(
            ntfy,
            text="ntfy Click notifications open the domain directly in the review PWA.",
            wraplength=720,
            justify="left",
        ).grid(row=4, column=0, columnspan=2, sticky="ew", pady=(4, 0))

        unified = ttk.LabelFrame(self, text="UnifiedPush / Web Push", padding=10)
        unified.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(14, 0))
        unified.columnconfigure(1, weight=1)
        ttk.Checkbutton(
            unified,
            text="Enable UnifiedPush",
            variable=self.unifiedpush_enabled,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 5))
        self._entry_row(unified, 1, "Push endpoint", self.unifiedpush_endpoint, secret=True)
        self._entry_row(unified, 2, "p256dh public key", self.unifiedpush_p256dh)
        self._entry_row(unified, 3, "Auth secret", self.unifiedpush_auth, secret=True)
        self._entry_row(unified, 4, "VAPID subject", self.unifiedpush_subject)
        ttk.Checkbutton(
            unified,
            text="Allow a private/non-global self-hosted push endpoint",
            variable=self.unifiedpush_allow_private,
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(5, 3))
        ttk.Label(unified, text="VAPID public key").grid(row=6, column=0, sticky="nw", pady=3)
        ttk.Label(
            unified,
            textvariable=self.vapid_public,
            wraplength=620,
            justify="left",
        ).grid(row=6, column=1, sticky="ew", padx=(10, 0), pady=3)
        ttk.Label(
            unified,
            text=(
                "UnifiedPush registration values come from the receiving client/distributor. "
                "Payloads are encrypted with RFC 8291 Web Push; the private VAPID key is "
                "generated automatically and stored in the OS credential store."
            ),
            wraplength=720,
            justify="left",
        ).grid(row=7, column=0, columnspan=2, sticky="ew", pady=(4, 0))

        actions = ttk.Frame(self)
        actions.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(14, 0))
        ttk.Button(actions, text="Send test push", command=self._send_test).pack(side="left")
        ttk.Label(actions, textvariable=self.test_status).pack(side="left", padx=(10, 0))

    @staticmethod
    def _entry_row(
        parent: ttk.Frame,
        row: int,
        label: str,
        variable: tk.StringVar,
        *,
        secret: bool = False,
    ) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
        ttk.Entry(parent, textvariable=variable, show="•" if secret else "").grid(
            row=row,
            column=1,
            sticky="ew",
            padx=(10, 0),
            pady=3,
        )

    def load(self, options: Options) -> None:
        self._options = options
        self.enable_desktop.set(options.notify.enable_desktop)
        self.enable_sound.set(options.notify.enable_sound)
        self.rate_limit.set(str(options.notify.rate_limit_sec))
        push = load_push_options()
        self.review_base_url.set(push.review_base_url)
        self.push_timeout.set(str(push.timeout_sec))
        self.ntfy_enabled.set(push.ntfy_enabled)
        self.ntfy_base_url.set(push.ntfy_base_url)
        self.ntfy_topic.set(push.ntfy_topic)
        self.ntfy_token.set(push.ntfy_token)
        self.unifiedpush_enabled.set(push.unifiedpush_enabled)
        self.unifiedpush_endpoint.set(push.unifiedpush_endpoint)
        self.unifiedpush_p256dh.set(push.unifiedpush_p256dh)
        self.unifiedpush_auth.set(push.unifiedpush_auth)
        self.unifiedpush_subject.set(push.unifiedpush_vapid_subject)
        self.unifiedpush_allow_private.set(push.unifiedpush_allow_private_endpoint)
        self._update_vapid_label(push)

    def _collect_push_options(self) -> PushNotificationOptions:
        timeout = max(1.0, float(self.push_timeout.get()))
        current = load_push_options()
        current.review_base_url = self.review_base_url.get().strip()
        current.timeout_sec = timeout
        current.ntfy_enabled = self.ntfy_enabled.get()
        current.ntfy_base_url = self.ntfy_base_url.get().strip()
        current.ntfy_topic = self.ntfy_topic.get().strip()
        current.ntfy_token = self.ntfy_token.get().strip()
        current.unifiedpush_enabled = self.unifiedpush_enabled.get()
        current.unifiedpush_endpoint = self.unifiedpush_endpoint.get().strip()
        current.unifiedpush_p256dh = self.unifiedpush_p256dh.get().strip()
        current.unifiedpush_auth = self.unifiedpush_auth.get().strip()
        current.unifiedpush_vapid_subject = self.unifiedpush_subject.get().strip()
        current.unifiedpush_allow_private_endpoint = self.unifiedpush_allow_private.get()
        return current

    def store(self, options: Options) -> bool:
        try:
            rate_limit = max(0, int(self.rate_limit.get()))
            push = self._collect_push_options()
            if push.review_base_url:
                build_review_link(push.review_base_url, "example.com")
        except ValueError as exc:
            messagebox.showerror("Notifications", str(exc), parent=self)
            return False
        if (push.ntfy_enabled or push.unifiedpush_enabled) and not push.review_base_url:
            messagebox.showerror(
                "Notifications",
                "Push notifications require a Review app base URL for deep links.",
                parent=self,
            )
            return False
        if push.ntfy_enabled and (not push.ntfy_base_url or not push.ntfy_topic):
            messagebox.showerror(
                "Notifications",
                "ntfy requires a server URL and topic.",
                parent=self,
            )
            return False
        if push.unifiedpush_enabled and (
            not push.unifiedpush_endpoint
            or not push.unifiedpush_p256dh
            or not push.unifiedpush_auth
        ):
            messagebox.showerror(
                "Notifications",
                "UnifiedPush requires endpoint, p256dh, and auth registration values.",
                parent=self,
            )
            return False
        options.notify.enable_desktop = self.enable_desktop.get()
        options.notify.enable_sound = self.enable_sound.get()
        options.notify.rate_limit_sec = rate_limit
        try:
            save_push_options(push)
        except Exception as exc:
            messagebox.showerror("Notifications", f"Could not save push settings: {exc}", parent=self)
            return False
        self._update_vapid_label(push)
        return True

    def _update_vapid_label(self, push: PushNotificationOptions) -> None:
        try:
            public_key = unifiedpush_vapid_public_key(push)
        except Exception:
            public_key = ""
        self.vapid_public.set(public_key or "Generated after UnifiedPush is saved.")

    def _send_test(self) -> None:
        if self._options is None or not self.store(self._options):
            return
        push = load_push_options()
        if not (push.ntfy_enabled or push.unifiedpush_enabled):
            messagebox.showinfo("Notifications", "Enable ntfy or UnifiedPush first.", parent=self)
            return
        self.test_status.set("Sending …")
        threading.Thread(
            target=self._test_worker,
            args=(push,),
            name="PushNotificationTest",
            daemon=True,
        ).start()

    def _test_worker(self, push: PushNotificationOptions) -> None:
        errors = send_push_notifications(
            "Wormhole Observatory",
            "Push notification test for example.com",
            domain="example.com",
            options=push,
        )
        self.after(0, self._test_done, errors)

    def _test_done(self, errors: list[str]) -> None:
        if errors:
            self.test_status.set("Test failed")
            messagebox.showerror("Notifications", "\n".join(errors), parent=self)
        else:
            self.test_status.set("Test sent")
