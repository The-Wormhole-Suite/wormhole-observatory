
import json, logging
from typing import Dict, Any
from config import load_options, PromptProfile
log = logging.getLogger(__name__)

def _select_profile(name: str) -> PromptProfile:
    opts = load_options()
    for p in opts.prompt_profiles:
        if p.name == name:
            return p
    return opts.prompt_profiles[0]

def classify_domain(domain: str, profile_name: str = "balanced") -> Dict[str, Any]:
    """Call an OpenAI-compatible LLM and return a normalized dict.
    This is a stub that returns a safe default; integrate your API next.
    """
    prof = _select_profile(profile_name)
    # TODO: Real HTTP call using providers list (round-robin / failover)
    # For now return a deterministic placeholder
    result = {
        "category": "unknown",
        "policy": "manual_review",
        "short": f"No data for {domain}",
        "details": "Stub classifier result. Configure LLM providers to enable real classification.",
        "provider": "stub"
    }
    log.debug("LLM classify %s -> %s", domain, result)
    return result
