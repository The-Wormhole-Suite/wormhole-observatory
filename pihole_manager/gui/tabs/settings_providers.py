from __future__ import annotations

import copy
import threading
import tkinter as tk
from collections.abc import Callable
from tkinter import messagebox, simpledialog, ttk

from pihole_manager.config import LLMProviderOptions, Options
from pihole_manager.gui.tooltips import TooltipSupport
from pihole_manager.local_discovery import (
    DiscoveredLocalProvider,
    discover_local_providers,
)
from pihole_manager.provider_api import list_provider_models
from pihole_manager.provider_presets import (
    preset_by_id,
    preset_by_name,
    provider_presets,
)


class ProvidersSettingsPage(TooltipSupport, ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        ttk.Frame.__init__(self, master, padding=10)
        self._init_tooltips()
        self._change_callback: Callable[[], None] | None = None
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self.options: Options | None = None
        self.index = 0

        left = ttk.Frame(self)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 10))
        self.listbox = tk.Listbox(left, width=31, exportselection=False, activestyle="none")
        self.listbox.pack(fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self._selected)

        buttons = ttk.Frame(left)
        buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(buttons, text="Custom", command=self._add_custom).pack(side="left")
        ttk.Button(buttons, text="Duplicate", command=self._duplicate).pack(side="left", padx=4)
        ttk.Button(buttons, text="Remove", command=self._remove).pack(side="left")

        preset_box = ttk.LabelFrame(left, text="Add configured provider", padding=6)
        preset_box.pack(fill="x", pady=(10, 0))
        self.preset_name = tk.StringVar(value=provider_presets()[0].name)
        ttk.Combobox(
            preset_box,
            textvariable=self.preset_name,
            values=tuple(item.name for item in provider_presets()),
            state="readonly",
            width=27,
        ).pack(fill="x")
        ttk.Button(preset_box, text="Add preset", command=self._add_preset).pack(
            fill="x", pady=(6, 0)
        )
        self.discover_button = ttk.Button(
            preset_box,
            text="Discover local servers",
            command=self._discover_local,
        )
        self.discover_button.pack(fill="x", pady=(6, 0))

        editor = ttk.LabelFrame(self, text="LLM provider", padding=10)
        editor.grid(row=0, column=1, sticky="nsew")
        editor.columnconfigure(1, weight=1)
        self.name = tk.StringVar()
        self.api_style = tk.StringVar()
        self.base_url = tk.StringVar()
        self.api_key = tk.StringVar()
        self.model = tk.StringVar()
        self.temperature = tk.StringVar()
        self.timeout = tk.StringVar()
        self.max_output_tokens = tk.StringVar()
        self.max_tokens_parameter = tk.StringVar()
        self.send_temperature = tk.BooleanVar()
        self.structured_output = tk.StringVar()

        self._entry(editor, 0, "Name", self.name)
        ttk.Label(editor, text="API style").grid(row=1, column=0, sticky="w", pady=4)
        style_row = ttk.Frame(editor)
        style_row.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=4)
        style_row.columnconfigure(0, weight=1)
        style_box = ttk.Combobox(
            style_row,
            textvariable=self.api_style,
            values=("openai_compatible", "anthropic_messages"),
            state="readonly",
        )
        style_box.grid(row=0, column=0, sticky="ew")
        style_box.bind("<<ComboboxSelected>>", self._api_style_changed)
        self._info_button(
            style_row,
            "API style",
            "OpenAI-compatible providers use chat/completions-style requests. Anthropic uses "
            "its native Messages API and therefore has different authentication and structured "
            "output behavior.",
        ).grid(row=0, column=1, padx=(6, 0))
        self._entry(editor, 2, "Base URL", self.base_url)
        self.api_key_label = ttk.Label(editor, text="API key")
        self.api_key_label.grid(row=3, column=0, sticky="w", pady=4)
        api_key_row = ttk.Frame(editor)
        api_key_row.grid(row=3, column=1, sticky="ew", padx=(10, 0), pady=4)
        api_key_row.columnconfigure(0, weight=1)
        ttk.Entry(
            api_key_row,
            textvariable=self.api_key,
            show="•",
        ).grid(row=0, column=0, sticky="ew")

        ttk.Label(editor, text="Model").grid(row=4, column=0, sticky="w", pady=4)
        model_row = ttk.Frame(editor)
        model_row.grid(row=4, column=1, sticky="ew", padx=(10, 0), pady=4)
        model_row.columnconfigure(0, weight=1)
        self.model_box = ttk.Combobox(model_row, textvariable=self.model, state="normal")
        self.model_box.grid(row=0, column=0, sticky="ew")
        self.fetch_models_button = ttk.Button(
            model_row,
            text="Fetch models",
            command=self._fetch_models,
        )
        self.fetch_models_button.grid(row=0, column=1, padx=(6, 0))

        self._entry(
            editor,
            5,
            "Temperature",
            self.temperature,
            help_text="Lower values make classifications more deterministic. Some reasoning "
            "models reject this parameter; disable Send temperature for those models.",
        )
        send_row = ttk.Frame(editor)
        send_row.grid(row=6, column=1, sticky="ew", padx=(10, 0), pady=4)
        ttk.Checkbutton(
            send_row,
            text="Send temperature",
            variable=self.send_temperature,
        ).grid(row=0, column=0, sticky="w")
        self._info_button(
            send_row,
            "Send temperature",
            "Disable this when a provider or model rejects the temperature parameter.",
        ).grid(row=0, column=1, padx=(6, 0))
        self._entry(editor, 7, "Timeout (seconds)", self.timeout)
        self._entry(
            editor,
            8,
            "Max output tokens",
            self.max_output_tokens,
            help_text="Upper limit for the model response. Large domain batches and detailed "
            "evidence require a larger response budget.",
        )

        ttk.Label(editor, text="Output token parameter").grid(row=9, column=0, sticky="w", pady=4)
        token_row = ttk.Frame(editor)
        token_row.grid(row=9, column=1, sticky="ew", padx=(10, 0), pady=4)
        token_row.columnconfigure(0, weight=1)
        ttk.Combobox(
            token_row,
            textvariable=self.max_tokens_parameter,
            values=("max_tokens", "max_completion_tokens", "none"),
            state="readonly",
        ).grid(row=0, column=0, sticky="ew")
        self._info_button(
            token_row,
            "Output token parameter",
            "Different APIs use different field names for the response limit. Provider presets "
            "select the expected value automatically.",
        ).grid(row=0, column=1, padx=(6, 0))

        ttk.Label(editor, text="Structured output").grid(row=10, column=0, sticky="w", pady=4)
        structured_row = ttk.Frame(editor)
        structured_row.grid(row=10, column=1, sticky="ew", padx=(10, 0), pady=4)
        structured_row.columnconfigure(0, weight=1)
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
            "JSON schema is the strictest API-level format. Auto tries supported structured "
            "modes and falls back when necessary. Every response is still validated locally.",
        ).grid(row=0, column=1, padx=(6, 0))

        self.provider_note = ttk.Label(
            editor,
            justify="left",
            wraplength=720,
            text=(
                "Provider presets configure the API base and transport. Fetch models queries "
                "the provider instead of relying on a static model list."
            ),
        )
        self.provider_note.grid(row=11, column=0, columnspan=2, sticky="ew", pady=(14, 0))
        self.mandatory_note = ttk.Label(editor, text="* mandatory field")
        self.mandatory_note.grid(
            row=12,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(8, 0),
        )

    def _entry(
        self,
        parent: ttk.LabelFrame,
        row: int,
        label: str,
        variable: tk.StringVar,
        *,
        secret: bool = False,
        help_text: str = "",
    ) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
        value_row = ttk.Frame(parent)
        value_row.grid(row=row, column=1, sticky="ew", padx=(10, 0), pady=4)
        value_row.columnconfigure(0, weight=1)
        ttk.Entry(
            value_row,
            textvariable=variable,
            show="•" if secret else "",
        ).grid(row=0, column=0, sticky="ew")
        if help_text:
            self._info_button(value_row, label, help_text).grid(row=0, column=1, padx=(6, 0))

    def set_change_callback(self, callback: Callable[[], None]) -> None:
        self._change_callback = callback

    def _changed(self) -> None:
        if self._change_callback is not None:
            self._change_callback()

    def load(self, options: Options) -> None:
        self.options = options
        self._reload(options.llm.active_provider_index)

    def store(self, options: Options) -> bool:
        if self.options is not options:
            self.options = options
        if not self._store_current():
            return False
        options.llm.active_provider_index = self.index
        return True

    def _reload(self, selected: int) -> None:
        assert self.options is not None
        providers = self.options.llm_providers
        selected = min(max(0, selected), len(providers) - 1)
        active = min(
            max(0, int(self.options.llm.active_provider_index)),
            len(providers) - 1,
        )
        selected_provider = providers[selected]
        active_provider = providers[active]
        providers.sort(key=lambda item: (item.name or "Unnamed provider").casefold())
        self.options.llm.active_provider_index = _identity_index(providers, active_provider)
        self.index = _identity_index(providers, selected_provider)

        self.listbox.delete(0, "end")
        for index, provider in enumerate(providers):
            marker = "● " if index == self.options.llm.active_provider_index else ""
            self.listbox.insert("end", marker + (provider.name or "Unnamed provider"))
        self._select_index(self.index)
        self._load_current()

    def _load_current(self) -> None:
        assert self.options is not None
        provider = self.options.llm_providers[self.index]
        self.name.set(provider.name)
        self.api_style.set(provider.api_style)
        self.base_url.set(provider.base_url)
        self.api_key.set(provider.api_key)
        self.model.set(provider.model)
        self.temperature.set(str(provider.temperature))
        self.timeout.set(str(provider.timeout_sec))
        self.max_output_tokens.set(str(provider.max_output_tokens))
        self.max_tokens_parameter.set(provider.max_tokens_parameter)
        self.send_temperature.set(provider.send_temperature)
        self.structured_output.set(provider.structured_output)
        self.model_box.configure(values=())
        preset = preset_by_id(provider.preset_id)
        note = preset.notes if preset and preset.notes else "Custom provider configuration."
        self.provider_note.configure(
            text=(
                f"{note}\nFetch models reads the provider's live /models endpoint. "
                "Changes are saved automatically."
            )
        )
        self._api_style_changed()
        self._update_api_key_requirement(provider)

    def _store_current(self) -> bool:
        assert self.options is not None
        try:
            temperature = float(self.temperature.get())
            timeout = max(1.0, float(self.timeout.get()))
            max_output_tokens = max(1, int(self.max_output_tokens.get()))
        except ValueError:
            messagebox.showerror(
                "Provider",
                "Temperature, timeout, and max output tokens must be numbers.",
            )
            return False
        provider = self.options.llm_providers[self.index]
        provider.name = self.name.get().strip() or "Unnamed provider"
        provider.api_style = self.api_style.get().strip() or "openai_compatible"
        provider.base_url = self.base_url.get().strip().rstrip("/")
        provider.api_key = self.api_key.get().strip()
        provider.model = self.model.get().strip()
        provider.temperature = temperature
        provider.timeout_sec = timeout
        provider.max_output_tokens = max_output_tokens
        provider.max_tokens_parameter = self.max_tokens_parameter.get()
        provider.send_temperature = self.send_temperature.get()
        provider.structured_output = self.structured_output.get()
        if provider.api_style == "anthropic_messages":
            provider.structured_output = "prompt_only"
            self.structured_output.set("prompt_only")
        self.listbox.delete(self.index)
        marker = "● " if self.index == self.options.llm.active_provider_index else ""
        self.listbox.insert(self.index, marker + provider.name)
        self._select_index(self.index)
        return True

    def _selected(self, _event: tk.Event | None = None) -> None:
        if self.options is None:
            return
        selection = self.listbox.curselection()
        if not selection or int(selection[0]) == self.index:
            return
        selected = int(selection[0])
        if not self._store_current():
            self._select_index(self.index)
            return
        self.options.llm.active_provider_index = selected
        self._reload(selected)
        self._changed()

    def _select_index(self, index: int) -> None:
        self.listbox.selection_clear(0, "end")
        self.listbox.selection_set(index)
        self.listbox.activate(index)
        self.listbox.see(index)

    def _update_api_key_requirement(self, provider: LLMProviderOptions) -> None:
        preset = preset_by_id(provider.preset_id)
        if preset is not None:
            required = preset.api_key_required
        else:
            base_url = provider.base_url.strip().lower()
            required = bool(base_url) and not any(
                marker in base_url for marker in ("localhost", "127.0.0.1", "[::1]")
            )
        self.api_key_label.configure(text="API key *" if required else "API key")
        if required:
            self.mandatory_note.grid()
        else:
            self.mandatory_note.grid_remove()

    def _api_style_changed(self, _event: tk.Event | None = None) -> None:
        anthropic = self.api_style.get() == "anthropic_messages"
        if anthropic:
            self.structured_output.set("prompt_only")
            self.structured_box.state(["disabled"])
        else:
            self.structured_box.state(["!disabled", "readonly"])

    def _add_custom(self) -> None:
        assert self.options is not None
        name = simpledialog.askstring("Provider", "Provider name:", parent=self)
        if not name or not self._store_current():
            return
        self.options.llm_providers.append(LLMProviderOptions(name=name.strip()))
        self._reload(len(self.options.llm_providers) - 1)
        self._changed()

    def _add_preset(self) -> None:
        assert self.options is not None
        if not self._store_current():
            return
        preset = preset_by_name(self.preset_name.get())
        if preset is None:
            messagebox.showerror("Provider", "The selected provider preset was not found.")
            return
        self.options.llm_providers.append(
            LLMProviderOptions(
                name=preset.name,
                preset_id=preset.preset_id,
                api_style=preset.api_style,
                base_url=preset.base_url,
                model=preset.default_model,
                structured_output=preset.structured_output,
                max_tokens_parameter=preset.max_tokens_parameter,
                send_temperature=preset.send_temperature,
            )
        )
        if preset.recommended_worker_batch_size is not None:
            self.options.llm.worker_batch_size = preset.recommended_worker_batch_size
        if preset.recommended_domains_per_request is not None:
            self.options.llm.domains_per_request = preset.recommended_domains_per_request
        if preset.recommended_min_request_interval_sec is not None:
            self.options.llm.min_request_interval_sec = preset.recommended_min_request_interval_sec
        if preset.recommended_max_retries is not None:
            self.options.llm.max_retries = preset.recommended_max_retries
        self._reload(len(self.options.llm_providers) - 1)
        self._changed()

    def _duplicate(self) -> None:
        assert self.options is not None
        if not self._store_current():
            return
        duplicate = copy.deepcopy(self.options.llm_providers[self.index])
        duplicate.name = f"{duplicate.name} (copy)"
        duplicate.preset_id = "custom"
        self.options.llm_providers.insert(self.index + 1, duplicate)
        self._reload(self.index + 1)
        self._changed()

    def _remove(self) -> None:
        assert self.options is not None
        if len(self.options.llm_providers) <= 1:
            messagebox.showwarning("Provider", "At least one provider must remain.")
            return
        del self.options.llm_providers[self.index]
        self._reload(min(self.index, len(self.options.llm_providers) - 1))
        self._changed()

    def _discover_local(self) -> None:
        assert self.options is not None
        if not self._store_current():
            return
        self.discover_button.state(["disabled"])
        self.discover_button.configure(text="Scanning …")
        threading.Thread(
            target=self._discover_local_worker,
            name="LocalLLMDiscovery",
            daemon=True,
        ).start()

    def _discover_local_worker(self) -> None:
        try:
            providers = discover_local_providers()
        except Exception as exc:
            self.after(0, self._discovery_failed, str(exc))
            return
        self.after(0, self._discovery_finished, providers)

    def _discovery_finished(
        self,
        discovered: list[DiscoveredLocalProvider],
    ) -> None:
        self.discover_button.state(["!disabled"])
        self.discover_button.configure(text="Discover local servers")
        if not discovered:
            messagebox.showinfo(
                "Local LLM discovery",
                "No supported local LLM server was found on this computer.\n\n"
                "Start Ollama, LM Studio, LocalAI, llama.cpp, vLLM, or LiteLLM "
                "and run the scan again.",
            )
            return

        summary = "\n".join(f"• {item.name}: {len(item.models)} model(s)" for item in discovered)
        if not messagebox.askyesno(
            "Local LLM discovery",
            f"Found the following local services:\n\n{summary}\n\n"
            "Add or update these provider configurations?",
        ):
            return

        assert self.options is not None
        added = 0
        updated = 0
        selected_index: int | None = None
        for item in discovered:
            existing_index = self._find_existing_provider(item)
            if existing_index is not None:
                provider = self.options.llm_providers[existing_index]
                if not provider.model and item.models:
                    provider.model = item.models[0]
                    updated += 1
                if selected_index is None:
                    selected_index = existing_index
                continue

            preset = preset_by_id(item.preset_id)
            provider = LLMProviderOptions(
                name=item.name,
                preset_id=item.preset_id,
                api_style=preset.api_style if preset else "openai_compatible",
                base_url=item.base_url,
                model=item.models[0] if item.models else "",
                structured_output=preset.structured_output if preset else "auto",
                max_tokens_parameter=(preset.max_tokens_parameter if preset else "max_tokens"),
                send_temperature=preset.send_temperature if preset else True,
            )
            self.options.llm_providers.append(provider)
            added += 1
            if selected_index is None:
                selected_index = len(self.options.llm_providers) - 1

        self._reload(selected_index if selected_index is not None else self.index)
        self._changed()
        messagebox.showinfo(
            "Local LLM discovery",
            f"Added {added} provider(s) and updated {updated} existing provider(s).\n"
            "The changes were saved automatically.",
        )

    def _find_existing_provider(
        self,
        discovered: DiscoveredLocalProvider,
    ) -> int | None:
        assert self.options is not None
        target_url = self._normalized_local_url(discovered.base_url)
        for index, provider in enumerate(self.options.llm_providers):
            if self._normalized_local_url(provider.base_url) == target_url:
                return index
        return None

    @staticmethod
    def _normalized_local_url(value: str) -> str:
        return value.strip().lower().rstrip("/").replace("localhost", "127.0.0.1")

    def _discovery_failed(self, error: str) -> None:
        self.discover_button.state(["!disabled"])
        self.discover_button.configure(text="Discover local servers")
        messagebox.showerror("Local LLM discovery", f"Discovery failed:\n{error}")

    def _fetch_models(self) -> None:
        assert self.options is not None
        if not self._store_current():
            return
        provider_index = self.index
        provider = copy.deepcopy(self.options.llm_providers[provider_index])
        if not provider.base_url:
            messagebox.showerror("Provider", "Configure a base URL first.")
            return
        self.fetch_models_button.state(["disabled"])
        self.fetch_models_button.configure(text="Loading …")
        threading.Thread(
            target=self._fetch_models_worker,
            args=(provider_index, provider),
            name="LLMModelFetch",
            daemon=True,
        ).start()

    def _fetch_models_worker(
        self,
        provider_index: int,
        provider: LLMProviderOptions,
    ) -> None:
        try:
            models = list_provider_models(provider)
        except Exception as exc:
            self.after(0, self._models_failed, provider_index, str(exc))
            return
        self.after(0, self._models_loaded, provider_index, models)

    def _models_loaded(self, provider_index: int, models: list[str]) -> None:
        self.fetch_models_button.state(["!disabled"])
        self.fetch_models_button.configure(text="Fetch models")
        if provider_index == self.index:
            self.model_box.configure(values=models)
            if not self.model.get().strip() and models:
                self.model.set(models[0])
                self._changed()
        messagebox.showinfo("Provider", f"Loaded {len(models)} available model(s).")

    def _models_failed(self, provider_index: int, error: str) -> None:
        self.fetch_models_button.state(["!disabled"])
        self.fetch_models_button.configure(text="Fetch models")
        messagebox.showerror("Provider", f"Could not load models:\n{error}")


def _identity_index(values: list[LLMProviderOptions], target: LLMProviderOptions) -> int:
    for index, value in enumerate(values):
        if value is target:
            return index
    return 0
