from __future__ import annotations

import dataclasses
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from typing import TYPE_CHECKING

from pihole_manager.config import LLMProviderOptions, save_options
from pihole_manager.credentials import (
    CredentialBackendError,
    clear_api_key,
    get_api_key,
    set_api_key,
)
from pihole_manager.llm import test_llm_provider
from pihole_manager.provider_api import list_provider_models
from pihole_manager.provider_presets import (
    preset_by_name,
    provider_presets,
)
from pihole_manager.provider_registry import registry_metadata, update_provider_registry
from pihole_manager.quota import reset_provider_quota_state

if TYPE_CHECKING:
    from pihole_manager.gui.tabs.settings import SettingsTab


class ProviderSettingsSection:
    def __init__(self, owner: SettingsTab, parent: ttk.Frame) -> None:
        self.owner = owner
        self.app = owner.app
        self.parent = parent
        self.options = owner.options
        self.llm = self.options.llm
        self._provider_ids: list[str] = []
        self._selected_provider_id = ""
        self._build()

    def _build(self) -> None:
        parent = self.parent
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

        split = ttk.Panedwindow(parent, orient="horizontal")
        split.grid(row=0, column=0, sticky="nsew")

        provider_list = ttk.LabelFrame(split, text="Providers")
        provider_list.columnconfigure(0, weight=1)
        provider_list.rowconfigure(0, weight=1)
        self.provider_tree = ttk.Treeview(
            provider_list,
            columns=("enabled", "model", "limits"),
            show="tree headings",
            selectmode="browse",
            height=18,
        )
        self.provider_tree.heading("#0", text="Provider")
        self.provider_tree.heading("enabled", text="Enabled")
        self.provider_tree.heading("model", text="Model")
        self.provider_tree.heading("limits", text="Limits")
        self.provider_tree.column("#0", width=180, minwidth=120)
        self.provider_tree.column("enabled", width=70, anchor="center", stretch=False)
        self.provider_tree.column("model", width=170, minwidth=100)
        self.provider_tree.column("limits", width=90, anchor="center", stretch=False)
        self.provider_tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll = ttk.Scrollbar(
            provider_list,
            orient="vertical",
            command=self.provider_tree.yview,
        )
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.provider_tree.configure(yscrollcommand=tree_scroll.set)
        self.provider_tree.bind("<<TreeviewSelect>>", self._provider_selected)

        list_buttons = ttk.Frame(provider_list)
        list_buttons.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Button(list_buttons, text="Add", command=self._add_provider).pack(side="left")
        ttk.Button(list_buttons, text="Duplicate", command=self._duplicate_provider).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(list_buttons, text="Remove", command=self._remove_provider).pack(
            side="left", padx=(6, 0)
        )
        split.add(provider_list, weight=2)

        editor = ttk.LabelFrame(split, text="Provider details")
        editor.columnconfigure(1, weight=1)
        split.add(editor, weight=3)

        self.name = tk.StringVar()
        self.enabled = tk.BooleanVar()
        self.api_style = tk.StringVar()
        self.base_url = tk.StringVar()
        self.model = tk.StringVar()
        self.timeout_sec = tk.DoubleVar()
        self.temperature = tk.DoubleVar()
        self.max_output_tokens = tk.IntVar()
        self.max_tokens_parameter = tk.StringVar()
        self.send_temperature = tk.BooleanVar()
        self.structured_output = tk.StringVar()
        self.limit_mode = tk.StringVar()
        self.requests_per_minute = tk.IntVar()
        self.requests_per_day = tk.IntVar()
        self.tokens_per_minute = tk.IntVar()
        self.tokens_per_day = tk.IntVar()
        self.concurrent_requests = tk.IntVar()
        self.safety_margin = tk.DoubleVar()

        self._entry(editor, 0, "Name", self.name)
        enabled_box = ttk.Checkbutton(editor, text="Enabled", variable=self.enabled)
        enabled_box.grid(row=0, column=2, sticky="w", padx=(8, 0))

        style_row = ttk.Frame(editor)
        style_row.columnconfigure(0, weight=1)
        style_row.grid(row=1, column=1, columnspan=2, sticky="ew", pady=3)
        ttk.Label(editor, text="API style").grid(row=1, column=0, sticky="w", pady=3)
        style_box = ttk.Combobox(
            style_row,
            textvariable=self.api_style,
            values=(
                "openai_compatible",
                "openai_responses_web_search",
                "anthropic_messages",
            ),
            state="readonly",
        )
        style_box.grid(row=0, column=0, sticky="ew")
        style_box.bind("<<ComboboxSelected>>", self._api_style_changed)
        self._info_button(
            style_row,
            "API style",
            "OpenAI-compatible providers use chat/completions-style requests. OpenAI Responses "
            "+ Web Search uses the native Responses API and returns web citations. Anthropic uses "
            "its native Messages API. Native API modes use prompt-only structured output here.",
        ).grid(row=0, column=1, padx=(6, 0))
        self._entry(editor, 2, "Base URL", self.base_url)
        self.api_key_label = ttk.Label(editor, text="API key")
        self.api_key_label.grid(row=3, column=0, sticky="w", pady=3)
        key_row = ttk.Frame(editor)
        key_row.columnconfigure(0, weight=1)
        key_row.grid(row=3, column=1, columnspan=2, sticky="ew", pady=3)
        self.api_key = ttk.Entry(key_row, show="*")
        self.api_key.grid(row=0, column=0, sticky="ew")
        ttk.Button(key_row, text="Store", command=self._store_api_key).grid(
            row=0, column=1, padx=(6, 0)
        )
        ttk.Button(key_row, text="Clear", command=self._clear_api_key).grid(
            row=0, column=2, padx=(6, 0)
        )
        self._info_button(
            key_row,
            "API key storage",
            "API keys are stored through the configured credential backend rather than in the "
            "plain-text application settings. The provider entry only keeps a reference ID.",
        ).grid(row=0, column=3, padx=(6, 0))

        model_row = ttk.Frame(editor)
        model_row.columnconfigure(0, weight=1)
        model_row.grid(row=4, column=1, columnspan=2, sticky="ew", pady=3)
        ttk.Label(editor, text="Model").grid(row=4, column=0, sticky="w", pady=3)
        self.model_box = ttk.Combobox(model_row, textvariable=self.model)
        self.model_box.grid(row=0, column=0, sticky="ew")
        ttk.Button(model_row, text="Fetch models", command=self._fetch_models).grid(
            row=0, column=1, padx=(6, 0)
        )
        self._info_button(
            model_row,
            "Model selection",
            "Fetch models asks the provider's models endpoint when available. The field stays "
            "editable because some providers do not expose a compatible model-list endpoint.",
        ).grid(row=0, column=2, padx=(6, 0))

        self._entry(editor, 5, "Timeout (s)", self.timeout_sec)
        self._entry(editor, 6, "Temperature", self.temperature)
        self._entry(editor, 7, "Max output tokens", self.max_output_tokens)
        token_param_row = ttk.Frame(editor)
        token_param_row.columnconfigure(0, weight=1)
        token_param_row.grid(row=8, column=1, columnspan=2, sticky="ew", pady=3)
        ttk.Label(editor, text="Max-token parameter").grid(row=8, column=0, sticky="w", pady=3)
        ttk.Combobox(
            token_param_row,
            textvariable=self.max_tokens_parameter,
            values=("max_tokens", "max_completion_tokens", "none"),
            state="readonly",
        ).grid(row=0, column=0, sticky="ew")
        self._info_button(
            token_param_row,
            "Max-token parameter",
            "OpenAI-compatible APIs disagree on the token-limit field. Use max_tokens for most "
            "providers, max_completion_tokens for current OpenAI reasoning models, or none when "
            "the endpoint rejects both fields.",
        ).grid(row=0, column=1, padx=(6, 0))
        temp_row = ttk.Frame(editor)
        temp_row.grid(row=9, column=1, columnspan=2, sticky="w", pady=3)
        ttk.Checkbutton(
            temp_row,
            text="Send temperature",
            variable=self.send_temperature,
        ).pack(side="left")
        self._info_button(
            temp_row,
            "Temperature compatibility",
            "Disable this for models that only accept their provider default temperature. The "
            "configured numeric value is retained for models that support it.",
        ).pack(side="left", padx=(6, 0))

        structured_row = ttk.Frame(editor)
        structured_row.columnconfigure(0, weight=1)
        structured_row.grid(row=10, column=1, columnspan=2, sticky="ew", pady=3)
        ttk.Label(editor, text="Structured output").grid(row=10, column=0, sticky="w", pady=3)
        self.structured_box = ttk.Combobox(
            structured_row,
            textvariable=self.structured_output,
            values=("auto", "json_schema", "json_object", "prompt_only"),
            state="readonly",
        )
        self.structured_box.grid(row=0, column=0, sticky="ew")
        self._info_button(
            structured_row,
            "Structured output",
            "auto tries the strongest available JSON mode first and falls back when a provider "
            "rejects it. prompt_only relies on the system prompt plus local strict validation.",
        ).grid(row=0, column=1, padx=(6, 0))

        ttk.Separator(editor).grid(row=11, column=0, columnspan=3, sticky="ew", pady=10)
        ttk.Label(editor, text="Limit handling", style="Section.TLabel").grid(
            row=12, column=0, columnspan=3, sticky="w"
        )

        limit_row = ttk.Frame(editor)
        limit_row.columnconfigure(0, weight=1)
        limit_row.grid(row=13, column=1, columnspan=2, sticky="ew", pady=3)
        ttk.Label(editor, text="Mode").grid(row=13, column=0, sticky="w", pady=3)
        ttk.Combobox(
            limit_row,
            textvariable=self.limit_mode,
            values=("auto", "manual"),
            state="readonly",
        ).grid(row=0, column=0, sticky="ew")
        self._info_button(
            limit_row,
            "Limit mode",
            "Auto uses the signed capability registry plus live rate-limit headers. Manual uses "
            "the values below as hard configured limits. Server feedback always remains the "
            "authoritative safety signal during a run.",
        ).grid(row=0, column=1, padx=(6, 0))
        self._entry(editor, 14, "Requests/min", self.requests_per_minute)
        self._entry(editor, 15, "Requests/day", self.requests_per_day)
        self._entry(editor, 16, "Tokens/min", self.tokens_per_minute)
        self._entry(editor, 17, "Tokens/day", self.tokens_per_day)
        self._entry(editor, 18, "Concurrent requests", self.concurrent_requests)
        self._entry(editor, 19, "Safety margin", self.safety_margin)

        action_row = ttk.Frame(editor)
        action_row.grid(row=20, column=0, columnspan=3, sticky="ew", pady=(12, 0))
        ttk.Button(action_row, text="Test provider", command=self._test_provider).pack(side="left")
        ttk.Button(action_row, text="Reset quota state", command=self._reset_quota).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(action_row, text="Save provider", command=self._save_provider).pack(
            side="right"
        )

        registry_frame = ttk.LabelFrame(editor, text="Capability registry")
        registry_frame.grid(row=21, column=0, columnspan=3, sticky="ew", pady=(14, 0))
        registry_frame.columnconfigure(0, weight=1)
        self.registry_status = ttk.Label(registry_frame, wraplength=560, justify="left")
        self.registry_status.grid(row=0, column=0, sticky="w", padx=8, pady=8)
        ttk.Button(
            registry_frame,
            text="Update registry",
            command=self._update_registry,
        ).grid(row=0, column=1, padx=8, pady=8)

        self.mandatory_note = ttk.Label(editor, foreground="#9A6700", wraplength=560)
        self.mandatory_note.grid(row=22, column=0, columnspan=3, sticky="w", pady=(8, 0))

        self._refresh_provider_tree()
        self._refresh_registry_status()
        if self._provider_ids:
            self.provider_tree.selection_set(self._provider_ids[0])
            self.provider_tree.focus(self._provider_ids[0])
            self._load_provider(self._provider_ids[0])

    def _entry(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        variable: tk.Variable,
    ) -> ttk.Entry:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
        entry = ttk.Entry(parent, textvariable=variable)
        entry.grid(row=row, column=1, columnspan=2, sticky="ew", pady=3)
        return entry

    def _info_button(self, parent: ttk.Frame, title: str, text: str) -> ttk.Button:
        return ttk.Button(
            parent,
            text="?",
            width=3,
            command=lambda: messagebox.showinfo(title, text, parent=self.owner),
        )

    def _refresh_provider_tree(self, *, selected_id: str | None = None) -> None:
        for item in self.provider_tree.get_children():
            self.provider_tree.delete(item)
        providers = sorted(self.llm.providers, key=lambda item: item.name.casefold())
        self._provider_ids = [provider.provider_id for provider in providers]
        for provider in providers:
            limits = "Auto" if provider.limits.mode == "auto" else "Manual"
            self.provider_tree.insert(
                "",
                "end",
                iid=provider.provider_id,
                text=provider.name,
                values=("Yes" if provider.enabled else "No", provider.model, limits),
            )
        target = selected_id or self._selected_provider_id
        if target and self.provider_tree.exists(target):
            self.provider_tree.selection_set(target)
            self.provider_tree.focus(target)

    def _provider_selected(self, _event: tk.Event | None = None) -> None:
        selected = self.provider_tree.selection()
        if not selected:
            return
        next_id = selected[0]
        if self._selected_provider_id and self._selected_provider_id != next_id:
            try:
                self._store_current(show_errors=False)
            except (tk.TclError, ValueError):
                pass
        self._load_provider(next_id)

    def _provider(self, provider_id: str) -> LLMProviderOptions | None:
        return next(
            (provider for provider in self.llm.providers if provider.provider_id == provider_id),
            None,
        )

    def _load_provider(self, provider_id: str) -> None:
        provider = self._provider(provider_id)
        if provider is None:
            return
        self._selected_provider_id = provider_id
        self.name.set(provider.name)
        self.enabled.set(provider.enabled)
        self.api_style.set(provider.api_style)
        self.base_url.set(provider.base_url)
        self.model.set(provider.model)
        self.timeout_sec.set(provider.timeout_sec)
        self.temperature.set(provider.temperature)
        self.max_output_tokens.set(provider.max_output_tokens)
        self.max_tokens_parameter.set(provider.max_tokens_parameter)
        self.send_temperature.set(provider.send_temperature)
        self.structured_output.set(provider.structured_output)
        self.limit_mode.set(provider.limits.mode)
        self.requests_per_minute.set(provider.limits.requests_per_minute)
        self.requests_per_day.set(provider.limits.requests_per_day)
        self.tokens_per_minute.set(provider.limits.tokens_per_minute)
        self.tokens_per_day.set(provider.limits.tokens_per_day)
        self.concurrent_requests.set(provider.limits.concurrent_requests)
        self.safety_margin.set(provider.limits.safety_margin)
        self.api_key.delete(0, "end")
        try:
            stored_key = get_api_key(provider)
        except CredentialBackendError:
            stored_key = provider.api_key
        if stored_key:
            self.api_key.insert(0, stored_key)
        self._refresh_api_key_label(provider)
        self.model_box.configure(values=(provider.model,) if provider.model else ())
        self._api_style_changed()

    def _refresh_api_key_label(self, provider: LLMProviderOptions) -> None:
        if provider.api_key_ref:
            suffix = f" ({provider.api_key_ref})"
        elif provider.api_key:
            suffix = " (legacy plain-text value; save to migrate)"
        else:
            suffix = ""
        self.api_key_label.configure(text=f"API key{suffix}")

    def _store_current(self, *, show_errors: bool = True) -> LLMProviderOptions | None:
        provider = self._provider(self._selected_provider_id)
        if provider is None:
            return None
        try:
            provider.name = self.name.get().strip() or provider.name
            provider.enabled = self.enabled.get()
            provider.api_style = self.api_style.get().strip() or "openai_compatible"
            provider.base_url = self.base_url.get().strip()
            provider.model = self.model.get().strip()
            provider.timeout_sec = max(1.0, float(self.timeout_sec.get()))
            provider.temperature = float(self.temperature.get())
            provider.max_output_tokens = max(1, int(self.max_output_tokens.get()))
            provider.max_tokens_parameter = self.max_tokens_parameter.get()
            provider.send_temperature = self.send_temperature.get()
            provider.structured_output = self.structured_output.get()
            if provider.api_style in {"anthropic_messages", "openai_responses_web_search"}:
                provider.structured_output = "prompt_only"
                self.structured_output.set("prompt_only")
            provider.limits.mode = self.limit_mode.get().strip() or "auto"
            provider.limits.requests_per_minute = max(0, int(self.requests_per_minute.get()))
            provider.limits.requests_per_day = max(0, int(self.requests_per_day.get()))
            provider.limits.tokens_per_minute = max(0, int(self.tokens_per_minute.get()))
            provider.limits.tokens_per_day = max(0, int(self.tokens_per_day.get()))
            provider.limits.concurrent_requests = max(1, int(self.concurrent_requests.get()))
            provider.limits.safety_margin = min(1.0, max(0.1, float(self.safety_margin.get())))
            entered_key = self.api_key.get().strip()
            if entered_key:
                set_api_key(provider, entered_key)
            elif provider.api_key and not provider.api_key_ref:
                set_api_key(provider, provider.api_key)
            return provider
        except (tk.TclError, ValueError, CredentialBackendError) as exc:
            if show_errors:
                messagebox.showerror("Provider", str(exc), parent=self.owner)
            raise

    def _save_provider(self) -> None:
        try:
            provider = self._store_current()
        except (tk.TclError, ValueError, CredentialBackendError):
            return
        if provider is None:
            return
        save_options(self.options)
        self._refresh_provider_tree(selected_id=provider.provider_id)
        self._refresh_api_key_label(provider)
        self.owner.set_status(f"Saved provider: {provider.name}")

    def _store_api_key(self) -> None:
        provider = self._provider(self._selected_provider_id)
        if provider is None:
            return
        value = self.api_key.get().strip()
        if not value:
            messagebox.showwarning("API key", "Enter an API key first.", parent=self.owner)
            return
        try:
            set_api_key(provider, value)
            save_options(self.options)
        except (CredentialBackendError, OSError) as exc:
            messagebox.showerror("API key", str(exc), parent=self.owner)
            return
        self._refresh_api_key_label(provider)
        self.owner.set_status("API key stored securely.")

    def _clear_api_key(self) -> None:
        provider = self._provider(self._selected_provider_id)
        if provider is None:
            return
        try:
            clear_api_key(provider)
            save_options(self.options)
        except (CredentialBackendError, OSError) as exc:
            messagebox.showerror("API key", str(exc), parent=self.owner)
            return
        self.api_key.delete(0, "end")
        self._refresh_api_key_label(provider)
        self.owner.set_status("API key cleared.")

    def _api_style_changed(self, _event: tk.Event | None = None) -> None:
        prompt_only = self.api_style.get() in {
            "anthropic_messages",
            "openai_responses_web_search",
        }
        if prompt_only:
            self.structured_output.set("prompt_only")
            self.structured_box.state(["disabled"])
        else:
            self.structured_box.state(["!disabled"])

    def _add_provider(self) -> None:
        presets = provider_presets()
        names = [preset.name for preset in presets]
        dialog = tk.Toplevel(self.owner)
        dialog.title("Add provider")
        dialog.transient(self.owner)
        dialog.grab_set()
        ttk.Label(dialog, text="Preset").grid(row=0, column=0, sticky="w", padx=10, pady=10)
        preset_name = tk.StringVar(value=names[0] if names else "")
        box = ttk.Combobox(dialog, textvariable=preset_name, values=names, state="readonly", width=42)
        box.grid(row=0, column=1, sticky="ew", padx=(0, 10), pady=10)
        result: dict[str, bool] = {"ok": False}

        def accept() -> None:
            result["ok"] = True
            dialog.destroy()

        button_row = ttk.Frame(dialog)
        button_row.grid(row=1, column=0, columnspan=2, sticky="e", padx=10, pady=(0, 10))
        ttk.Button(button_row, text="Cancel", command=dialog.destroy).pack(side="right")
        ttk.Button(button_row, text="Add", command=accept).pack(side="right", padx=(0, 6))
        dialog.wait_window()
        if not result["ok"]:
            return
        preset = preset_by_name(preset_name.get())
        if preset is None:
            return
        provider_id = self._next_provider_id(preset.preset_id)
        provider = LLMProviderOptions(
            provider_id=provider_id,
            name=preset.name,
            enabled=True,
            api_style=preset.api_style,
            base_url=preset.base_url,
            model=preset.default_model,
            structured_output=preset.structured_output,
            max_tokens_parameter=preset.max_tokens_parameter,
            send_temperature=preset.send_temperature,
        )
        if preset.recommended_min_request_interval_sec is not None:
            self.llm.min_request_interval_sec = max(
                self.llm.min_request_interval_sec,
                preset.recommended_min_request_interval_sec,
            )
        if preset.recommended_max_retries is not None:
            self.llm.max_retries = max(self.llm.max_retries, preset.recommended_max_retries)
        self.llm.providers.append(provider)
        self._refresh_provider_tree(selected_id=provider_id)
        self._load_provider(provider_id)
        if preset.notes:
            messagebox.showinfo("Provider preset", preset.notes, parent=self.owner)

    def _duplicate_provider(self) -> None:
        provider = self._provider(self._selected_provider_id)
        if provider is None:
            return
        clone = dataclasses.replace(
            provider,
            provider_id=self._next_provider_id(f"{provider.provider_id}_copy"),
            name=f"{provider.name} Copy",
            api_key="",
            api_key_ref="",
            limits=dataclasses.replace(provider.limits),
        )
        self.llm.providers.append(clone)
        self._refresh_provider_tree(selected_id=clone.provider_id)
        self._load_provider(clone.provider_id)

    def _remove_provider(self) -> None:
        provider = self._provider(self._selected_provider_id)
        if provider is None:
            return
        if not messagebox.askyesno(
            "Remove provider",
            f"Remove '{provider.name}'?",
            parent=self.owner,
        ):
            return
        clear_api_key(provider)
        self.llm.providers = [
            item for item in self.llm.providers if item.provider_id != provider.provider_id
        ]
        self._selected_provider_id = ""
        self._refresh_provider_tree()
        if self._provider_ids:
            self.provider_tree.selection_set(self._provider_ids[0])
            self._load_provider(self._provider_ids[0])

    def _next_provider_id(self, base: str) -> str:
        clean = "".join(ch if ch.isalnum() else "_" for ch in base.casefold()).strip("_") or "provider"
        existing = {provider.provider_id for provider in self.llm.providers}
        if clean not in existing:
            return clean
        index = 2
        while f"{clean}_{index}" in existing:
            index += 1
        return f"{clean}_{index}"

    def _fetch_models(self) -> None:
        try:
            provider = self._store_current()
            if provider is None:
                return
            models = list_provider_models(provider)
        except Exception as exc:
            messagebox.showerror("Fetch models", str(exc), parent=self.owner)
            return
        self.model_box.configure(values=models)
        if provider.model not in models and models:
            self.model.set(models[0])
        self.owner.set_status(f"Loaded {len(models)} models from {provider.name}.")

    def _test_provider(self) -> None:
        try:
            provider = self._store_current()
            if provider is None:
                return
            result = test_llm_provider(provider)
        except Exception as exc:
            messagebox.showerror("Test provider", str(exc), parent=self.owner)
            return
        messagebox.showinfo("Test provider", result, parent=self.owner)

    def _reset_quota(self) -> None:
        provider = self._provider(self._selected_provider_id)
        if provider is None:
            return
        reset_provider_quota_state(provider)
        self.owner.set_status(f"Reset quota state for {provider.name}.")

    def _update_registry(self) -> None:
        try:
            result = update_provider_registry(self.llm)
        except Exception as exc:
            messagebox.showerror("Capability registry", str(exc), parent=self.owner)
            return
        self._refresh_registry_status()
        self.owner.set_status(result)

    def _refresh_registry_status(self) -> None:
        meta = registry_metadata(self.llm)
        if meta is None:
            text = "Using bundled capability registry. Remote updates are disabled or unavailable."
        else:
            text = (
                f"Registry v{meta.version} · updated {meta.updated_at or 'unknown'} · "
                f"source {meta.source or 'bundled'}"
            )
        self.registry_status.configure(text=text)

    def _mandatory_state(self, provider: LLMProviderOptions) -> tuple[bool, str]:
        preset = next(
            (
                item
                for item in provider_presets()
                if item.api_style == provider.api_style
                and item.base_url.rstrip("/") == provider.base_url.rstrip("/")
            ),
            None,
        )
        requires_key = True if preset is None else preset.api_key_required
        if provider.base_url.startswith("http://localhost") or provider.base_url.startswith(
            "http://127.0.0.1"
        ):
            requires_key = False
        if requires_key:
            return True, "This provider preset normally requires an API key."
        return False, ""

    def _refresh_mandatory_note(self) -> None:
        provider = self._provider(self._selected_provider_id)
        if provider is None:
            self.mandatory_note.grid_remove()
            return
        mandatory, text = self._mandatory_state(provider)
        if mandatory:
            self.mandatory_note.configure(text=text)
            self.mandatory_note.grid()
        else:
            self.mandatory_note.grid_remove()

    def _api_style_changed(self, _event: tk.Event | None = None) -> None:
        prompt_only = self.api_style.get() in {
            "anthropic_messages",
            "openai_responses_web_search",
        }
        if prompt_only:
            self.structured_output.set("prompt_only")
            self.structured_box.state(["disabled"])
        else:
            self.structured_box.state(["!disabled"])

    def _apply_provider_preset(self, preset_name: str) -> None:
        preset = preset_by_name(preset_name)
        if preset is None:
            return
        provider = self._provider(self._selected_provider_id)
        if provider is None:
            return
        provider.name = preset.name
        provider.api_style = preset.api_style
        provider.base_url = preset.base_url
        provider.model = preset.default_model
        provider.structured_output = preset.structured_output
        provider.max_tokens_parameter = preset.max_tokens_parameter
        provider.send_temperature = preset.send_temperature
        self._load_provider(provider.provider_id)

    def _add_preset_provider(self, preset_name: str) -> None:
        preset = preset_by_name(preset_name)
        if preset is None:
            return
        provider_id = self._next_provider_id(preset.preset_id)
        provider = LLMProviderOptions(
            provider_id=provider_id,
            name=preset.name,
            enabled=True,
            api_style=preset.api_style,
            base_url=preset.base_url,
            model=preset.default_model,
            structured_output=preset.structured_output,
            max_tokens_parameter=preset.max_tokens_parameter,
            send_temperature=preset.send_temperature,
        )
        self.llm.providers.append(provider)
        self._refresh_provider_tree(selected_id=provider_id)
        self._load_provider(provider_id)

    def save(self) -> None:
        self._store_current(show_errors=False)

