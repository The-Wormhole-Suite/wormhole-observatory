from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProviderPreset:
    preset_id: str
    name: str
    api_style: str
    base_url: str
    default_model: str = ""
    structured_output: str = "auto"
    api_key_required: bool = True
    max_tokens_parameter: str = "max_tokens"
    send_temperature: bool = True
    notes: str = ""
    recommended_worker_batch_size: int | None = None
    recommended_domains_per_request: int | None = None
    recommended_min_request_interval_sec: float | None = None
    recommended_max_retries: int | None = None


_PRESETS = (
    ProviderPreset(
        "openai",
        "OpenAI",
        "openai_compatible",
        "https://api.openai.com/v1",
        structured_output="json_schema",
        max_tokens_parameter="max_completion_tokens",
        send_temperature=False,
        notes="Official OpenAI API. Use Fetch models to select an available model.",
    ),
    ProviderPreset(
        "anthropic",
        "Anthropic Claude",
        "anthropic_messages",
        "https://api.anthropic.com/v1",
        structured_output="prompt_only",
        notes="Uses Anthropic's native Messages API and local strict response validation.",
    ),
    ProviderPreset(
        "google_gemini",
        "Google Gemini",
        "openai_compatible",
        "https://generativelanguage.googleapis.com/v1beta/openai",
        structured_output="json_schema",
    ),
    ProviderPreset(
        "xai",
        "xAI Grok",
        "openai_compatible",
        "https://api.x.ai/v1",
        structured_output="json_schema",
    ),
    ProviderPreset(
        "deepseek",
        "DeepSeek",
        "openai_compatible",
        "https://api.deepseek.com",
        "deepseek-chat",
        structured_output="auto",
    ),
    ProviderPreset(
        "mistral",
        "Mistral AI",
        "openai_compatible",
        "https://api.mistral.ai/v1",
        "mistral-small-latest",
        "auto",
    ),
    ProviderPreset(
        "groq",
        "GroqCloud",
        "openai_compatible",
        "https://api.groq.com/openai/v1",
        structured_output="auto",
    ),
    ProviderPreset(
        "groq_free_gpt_oss",
        "Groq Free (GPT OSS 120B)",
        "openai_compatible",
        "https://api.groq.com/openai/v1",
        "openai/gpt-oss-120b",
        structured_output="prompt_only",
        notes=(
            "Conservative settings for Groq's free tier. Current limits remain provider- and "
            "model-specific; server retry headers take precedence."
        ),
        recommended_worker_batch_size=12,
        recommended_domains_per_request=4,
        recommended_min_request_interval_sec=2.1,
        recommended_max_retries=2,
    ),
    ProviderPreset(
        "openrouter",
        "OpenRouter",
        "openai_compatible",
        "https://openrouter.ai/api/v1",
        structured_output="auto",
        notes="Structured-output support depends on the selected routed model.",
    ),
    ProviderPreset(
        "openrouter_free",
        "OpenRouter Free Router",
        "openai_compatible",
        "https://openrouter.ai/api/v1",
        "openrouter/free",
        structured_output="prompt_only",
        notes=(
            "Uses OpenRouter's free-model router. Model availability and daily quotas can change; "
            "server retry headers take precedence."
        ),
        recommended_worker_batch_size=20,
        recommended_domains_per_request=10,
        recommended_min_request_interval_sec=5.0,
        recommended_max_retries=2,
    ),
    ProviderPreset(
        "perplexity",
        "Perplexity Sonar",
        "openai_compatible",
        "https://api.perplexity.ai",
        "sonar",
        structured_output="auto",
    ),
    ProviderPreset(
        "together",
        "Together AI",
        "openai_compatible",
        "https://api.together.ai/v1",
        structured_output="auto",
    ),
    ProviderPreset(
        "fireworks",
        "Fireworks AI",
        "openai_compatible",
        "https://api.fireworks.ai/inference/v1",
        structured_output="auto",
    ),
    ProviderPreset(
        "cohere",
        "Cohere",
        "openai_compatible",
        "https://api.cohere.ai/compatibility/v1",
        structured_output="json_schema",
    ),
    ProviderPreset(
        "cerebras",
        "Cerebras Inference",
        "openai_compatible",
        "https://api.cerebras.ai/v1",
        structured_output="auto",
    ),
    ProviderPreset(
        "cerebras_free_gpt_oss",
        "Cerebras Free (GPT OSS 120B)",
        "openai_compatible",
        "https://api.cerebras.ai/v1",
        "gpt-oss-120b",
        structured_output="prompt_only",
        notes=(
            "Conservative settings for the Cerebras free trial. Current account limits and server "
            "retry headers take precedence."
        ),
        recommended_worker_batch_size=20,
        recommended_domains_per_request=10,
        recommended_min_request_interval_sec=13.0,
        recommended_max_retries=2,
    ),
    ProviderPreset(
        "sambanova",
        "SambaNova Cloud",
        "openai_compatible",
        "https://api.sambanova.ai/v1",
        structured_output="auto",
    ),
    ProviderPreset(
        "huggingface",
        "Hugging Face Inference Providers",
        "openai_compatible",
        "https://router.huggingface.co/v1",
        structured_output="auto",
    ),
    ProviderPreset(
        "ollama",
        "Ollama (local)",
        "openai_compatible",
        "http://localhost:11434/v1",
        structured_output="auto",
        api_key_required=False,
    ),
    ProviderPreset(
        "lm_studio",
        "LM Studio (local)",
        "openai_compatible",
        "http://localhost:1234/v1",
        structured_output="auto",
        api_key_required=False,
    ),
    ProviderPreset(
        "llama_cpp",
        "llama.cpp server (local)",
        "openai_compatible",
        "http://localhost:8080/v1",
        structured_output="auto",
        api_key_required=False,
    ),
    ProviderPreset(
        "localai",
        "LocalAI (local)",
        "openai_compatible",
        "http://localhost:8080/v1",
        structured_output="auto",
        api_key_required=False,
    ),
    ProviderPreset(
        "vllm",
        "vLLM (local/server)",
        "openai_compatible",
        "http://localhost:8000/v1",
        structured_output="auto",
        api_key_required=False,
    ),
    ProviderPreset(
        "litellm",
        "LiteLLM Proxy",
        "openai_compatible",
        "http://localhost:4000/v1",
        structured_output="auto",
        api_key_required=False,
        notes="A configured proxy key can still be entered when authentication is enabled.",
    ),
)


def provider_presets() -> tuple[ProviderPreset, ...]:
    return tuple(sorted(_PRESETS, key=lambda item: item.name.casefold()))


def preset_by_id(preset_id: str) -> ProviderPreset | None:
    normalized = preset_id.strip().lower()
    return next((item for item in _PRESETS if item.preset_id == normalized), None)


def preset_by_name(name: str) -> ProviderPreset | None:
    return next((item for item in _PRESETS if item.name == name), None)
