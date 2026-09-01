from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from dataclasses import asdict
from tkinter import messagebox, ttk

from pihole_manager.config import Options
from pihole_manager.gui.group_assignment_manager import show_group_assignment_manager
from pihole_manager.pihole_instances import (
    PiHoleInstance,
    PiHoleInstanceRegistry,
    load_pihole_instances,
    options_from_instance,
    save_pihole_instances,
)


def _copy_instance(instance: PiHoleInstance) -> PiHoleInstance:
    return PiHoleInstance(**asdict(instance))


class PiHoleSettingsPage(ttk.Frame):
    def __init__(
        self,
        master: tk.Misc,
        save_test_command: Callable[[], None],
    ) -> None:
        super().__init__(master, padding=12)
        self.columnconfigure(1, weight=1)
        self._save_test_command = save_test_command
        self._instances: list[PiHoleInstance] = []
        self._display_to_id: dict[str, str] = {}
        self._current_instance_id = ""
        self._saved_active_id = ""
        self._switching = False

        self.instance = tk.StringVar()
        self.instance_name = tk.StringVar()
        self.base_url = tk.StringVar()
        self.password = tk.StringVar()
        self.ca_bundle_path = tk.StringVar()
        self.timeout = tk.StringVar()
        self.result = tk.StringVar(value="No connection test performed.")
        self.active_note = tk.StringVar()

        instance_box = ttk.LabelFrame(self, text="Pi-hole instances", padding=10)
        instance_box.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 12))
        instance_box.columnconfigure(1, weight=1)
        ttk.Label(instance_box, text="Instance").grid(row=0, column=0, sticky="w")
        self.instance_combo = ttk.Combobox(
            instance_box,
            textvariable=self.instance,
            state="readonly",
        )
        self.instance_combo.grid(row=0, column=1, sticky="ew", padx=(10, 8))
        self.instance_combo.bind("<<ComboboxSelected>>", self._instance_selected)
        ttk.Button(instance_box, text="Add", command=self._add_instance).grid(
            row=0, column=2, padx=(0, 6)
        )
        self.remove_button = ttk.Button(
            instance_box,
            text="Remove",
            command=self._remove_instance,
        )
        self.remove_button.grid(row=0, column=3)
        ttk.Label(
            instance_box,
            textvariable=self.active_note,
            wraplength=760,
            justify="left",
        ).grid(row=1, column=0, columnspan=4, sticky="w", pady=(8, 0))

        ttk.Label(self, text="Instance name").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(self, textvariable=self.instance_name).grid(
            row=1,
            column=1,
            sticky="ew",
            padx=(10, 0),
            pady=4,
        )

        ttk.Label(self, text="Base URL").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(self, textvariable=self.base_url).grid(
            row=2,
            column=1,
            sticky="ew",
            padx=(10, 0),
            pady=4,
        )

        ttk.Label(self, text="Application password").grid(
            row=3,
            column=0,
            sticky="w",
            pady=4,
        )
        ttk.Entry(self, textvariable=self.password, show="•").grid(
            row=3,
            column=1,
            sticky="ew",
            padx=(10, 0),
            pady=4,
        )

        ttk.Label(self, text="Timeout in seconds").grid(
            row=4,
            column=0,
            sticky="w",
            pady=4,
        )
        timeout_row = ttk.Frame(self)
        timeout_row.grid(row=4, column=1, sticky="w", padx=(10, 0), pady=4)
        ttk.Entry(timeout_row, textvariable=self.timeout, width=10).pack(side="left")

        ttk.Label(self, text="Custom CA bundle (optional)").grid(
            row=5, column=0, sticky="w", pady=4
        )
        ttk.Entry(self, textvariable=self.ca_bundle_path).grid(
            row=5,
            column=1,
            sticky="ew",
            padx=(10, 0),
            pady=4,
        )

        self.save_test_button = ttk.Button(
            self,
            text="Save + Set Active + Test",
            command=save_test_command,
        )
        self.save_test_button.grid(
            row=6,
            column=1,
            sticky="w",
            padx=(10, 0),
            pady=(8, 4),
        )
        self.save_test_button._skip_auto_save = True  # type: ignore[attr-defined]

        ttk.Label(self, textvariable=self.result, wraplength=900).grid(
            row=7,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(8, 0),
        )

        groups = ttk.LabelFrame(self, text="Pi-hole groups", padding=10)
        groups.grid(row=7, column=0, columnspan=2, sticky="ew", pady=(16, 0))
        groups.columnconfigure(0, weight=1)
        ttk.Label(
            groups,
            text=(
                "Assign exact domains and subscribed allow/block lists to groups on the "
                "currently saved active Pi-hole instance."
            ),
            wraplength=760,
            justify="left",
        ).grid(row=0, column=0, sticky="w")
        ttk.Button(
            groups,
            text="Manage group assignments…",
            command=self._manage_groups,
        ).grid(row=1, column=0, sticky="w", pady=(8, 0))

    @staticmethod
    def _display(instance: PiHoleInstance) -> str:
        suffix = (
            instance.instance_id[-6:]
            if len(instance.instance_id) > 6
            else instance.instance_id
        )
        return f"{instance.name} · {instance.base_url} · {suffix}"

    def _refresh_selector(self, selected_id: str | None = None) -> None:
        self._display_to_id = {
            self._display(instance): instance.instance_id for instance in self._instances
        }
        values = list(self._display_to_id)
        self.instance_combo.configure(values=values)
        target = selected_id or self._current_instance_id
        for display, instance_id in self._display_to_id.items():
            if instance_id == target:
                self.instance.set(display)
                break
        self.remove_button.state(["disabled"] if len(self._instances) <= 1 else ["!disabled"])
        self._update_active_note()

    def _find(self, instance_id: str) -> PiHoleInstance | None:
        return next(
            (item for item in self._instances if item.instance_id == instance_id),
            None,
        )

    def _load_instance(self, instance_id: str) -> None:
        instance = self._find(instance_id)
        if instance is None:
            return
        self._current_instance_id = instance_id
        self.instance_name.set(instance.name)
        self.base_url.set(instance.base_url)
        self.password.set(instance.password)
        self.ca_bundle_path.set(instance.ca_bundle_path)
        self.timeout.set(str(instance.timeout_sec))
        self._refresh_selector(instance_id)

    def _capture_current(self, *, show_error: bool) -> bool:
        instance = self._find(self._current_instance_id)
        if instance is None:
            return True
        try:
            timeout = float(self.timeout.get())
        except ValueError:
            if show_error:
                messagebox.showerror("Connection", "Timeout must be a number.")
            return False
        if timeout <= 0:
            if show_error:
                messagebox.showerror("Connection", "Timeout must be greater than zero.")
            return False
        name = self.instance_name.get().strip()
        if not name:
            if show_error:
                messagebox.showerror("Connection", "Instance name must not be empty.")
            return False
        base_url = self.base_url.get().strip()
        if not base_url:
            if show_error:
                messagebox.showerror("Connection", "Base URL must not be empty.")
            return False
        instance.name = name
        instance.base_url = base_url
        instance.password = self.password.get()
        instance.ca_bundle_path = self.ca_bundle_path.get().strip()
        instance.timeout_sec = timeout
        return True

    def _instance_selected(self, _event: object = None) -> None:
        if self._switching:
            return
        target_id = self._display_to_id.get(self.instance.get(), "")
        if not target_id or target_id == self._current_instance_id:
            return
        if not self._capture_current(show_error=True):
            self._refresh_selector(self._current_instance_id)
            return
        self._switching = True
        try:
            self._load_instance(target_id)
        finally:
            self._switching = False

    def _add_instance(self) -> None:
        if not self._capture_current(show_error=True):
            return
        existing_names = {item.name for item in self._instances}
        number = len(self._instances) + 1
        name = f"Pi-hole {number}"
        while name in existing_names:
            number += 1
            name = f"Pi-hole {number}"
        instance = PiHoleInstance(name=name)
        self._instances.append(instance)
        self._load_instance(instance.instance_id)
        self.result.set("New instance added. Save to make it active and persist it.")

    def _remove_instance(self) -> None:
        if len(self._instances) <= 1:
            messagebox.showinfo("Pi-hole", "At least one Pi-hole instance is required.")
            return
        current = self._find(self._current_instance_id)
        if current is None:
            return
        if not messagebox.askyesno(
            "Remove Pi-hole instance",
            f"Remove '{current.name}' from the configured instances?",
        ):
            return
        self._instances = [
            item for item in self._instances if item.instance_id != self._current_instance_id
        ]
        replacement = self._instances[0]
        self._load_instance(replacement.instance_id)
        self.result.set("Instance removed. Save to persist this change.")

    def _update_active_note(self) -> None:
        current = self._find(self._current_instance_id)
        saved = self._find(self._saved_active_id)
        if current is None:
            self.active_note.set("")
            return
        if self._current_instance_id == self._saved_active_id:
            self.active_note.set(f"Active instance: {current.name}")
        elif saved is not None:
            self.active_note.set(
                f"Currently active: {saved.name}. Save + Set Active + Test "
                f"switches to {current.name}."
            )
        else:
            self.active_note.set(
                f"Save + Set Active + Test makes {current.name} the active instance."
            )

    def _manage_groups(self) -> None:
        if self._current_instance_id != self._saved_active_id:
            messagebox.showinfo(
                "Pi-hole groups",
                "Save and activate this instance before managing its groups.",
            )
            return
        show_group_assignment_manager(self)

    def load(self, options: Options) -> None:
        registry = load_pihole_instances(options.pihole)
        self._instances = [_copy_instance(item) for item in registry.instances]
        self._saved_active_id = registry.active_instance_id
        selected_id = self._saved_active_id
        if self._find(selected_id) is None:
            selected_id = self._instances[0].instance_id
        self._load_instance(selected_id)

    def _values(self) -> PiHoleInstance | None:
        if not self._capture_current(show_error=True):
            return None
        names = [item.name.casefold() for item in self._instances]
        if len(names) != len(set(names)):
            messagebox.showerror("Connection", "Pi-hole instance names must be unique.")
            return None
        current = self._find(self._current_instance_id)
        return _copy_instance(current) if current is not None else None

    def store(self, options: Options) -> bool:
        values = self._values()
        if values is None:
            return False
        registry = PiHoleInstanceRegistry(
            active_instance_id=values.instance_id,
            instances=[_copy_instance(item) for item in self._instances],
        )
        try:
            save_pihole_instances(registry)
        except Exception as exc:
            messagebox.showerror("Pi-hole", f"Could not save Pi-hole instances: {exc}")
            return False
        options.pihole = options_from_instance(values)
        self._saved_active_id = values.instance_id
        self._refresh_selector(values.instance_id)
        return True

    def mark_saved(self) -> None:
        self._saved_active_id = self._current_instance_id
        self._refresh_selector(self._current_instance_id)

    def active_instance_name(self) -> str:
        current = self._find(self._current_instance_id)
        return current.name if current is not None else "Pi-hole"

    def set_connection_status(self, text: str) -> None:
        self.result.set(text)

    def set_test_running(self, running: bool) -> None:
        self.save_test_button.state(["disabled"] if running else ["!disabled"])
