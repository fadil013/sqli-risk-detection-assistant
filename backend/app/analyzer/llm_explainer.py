"""Human-readable security reasoning for one field's classification +
risk score, and (Stage 5) RAG-grounded remediation for OWASP findings.

Template-based by default. Two opt-in local LLM backends exist —
LLM_EXPLAINER_BACKEND=ollama (Qwen3 via Ollama) or =lmstudio
(WhiteRabbitNeo via LM Studio's OpenAI-compatible local server) —
because a live call takes seconds-to-tens-of-seconds: running that per
field by default would make a multi-field scan slow and would make
the test suite depend on a local model server being up. The template
is always the fallback if neither is reachable or errors out, so
`explain()`/`explain_owasp_finding()` never raise and never return an
empty string.
"""
from __future__ import annotations

import os

import httpx

from app.analyzer.remediation_kb import retrieve

_OLLAMA_URL = "http://localhost:11434/api/generate"
_OLLAMA_MODEL = "qwen3:8b"

_LMSTUDIO_URL = "http://localhost:1234/v1/chat/completions"
_LMSTUDIO_MODEL = "whiterabbitneo_whiterabbitneo-v3-7b"
_LMSTUDIO_SYSTEM_PROMPT = (
    "You are WhiteRabbitNeo, a cybersecurity-expert AI. You write concise, "
    "practical remediation guidance for a defensive security report. This is "
    "a passive, discovery-stage finding — no exploit has been attempted or "
    "confirmed, so do not claim the target IS compromised, only that this "
    "specific evidence warrants a fix. Output only the finished answer, no "
    "preamble, no reasoning steps, no repetition."
)

_CATEGORY_OPENERS = {
    "authentication": "This field is used for user authentication or credential verification.",
    "security_token": "This field carries a session or security token used to authorize requests.",
    "payment": "This field carries payment or financial information.",
    "file_upload": "This field accepts an uploaded file.",
    "transaction_parameter": "This field represents a transaction, order, or quantity value.",
    "database_identifier": "This parameter appears to identify a specific database record.",
    "user_profile": "This field represents user profile or personal information.",
    "search_parameter": "This field is used to filter or search records.",
    "unknown": "This field's purpose could not be confidently determined from its name or context.",
}


def _call_ollama(prompt: str) -> str | None:
    """Returns Qwen3's response text, or None on any failure (Ollama
    not running, model not pulled, timeout, ...) so the caller can
    fall back to the template without ever raising.
    """
    try:
        response = httpx.post(
            _OLLAMA_URL,
            json={"model": _OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=90.0,
        )
        response.raise_for_status()
        text = response.json().get("response", "").strip()
        return text or None
    except (httpx.HTTPError, KeyError, ValueError):
        return None


def _call_lmstudio(user_prompt: str, system_prompt: str = _LMSTUDIO_SYSTEM_PROMPT) -> str | None:
    """Returns WhiteRabbitNeo's response text via LM Studio's local,
    OpenAI-compatible server, or None on any failure (server not
    running, model not loaded, timeout, ...) so the caller can fall
    back to the template/KB text without ever raising.
    """
    try:
        response = httpx.post(
            _LMSTUDIO_URL,
            json={
                "model": _LMSTUDIO_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.3,
            },
            timeout=90.0,
        )
        response.raise_for_status()
        text = response.json()["choices"][0]["message"]["content"].strip()
        return text or None
    except (httpx.HTTPError, KeyError, IndexError, ValueError):
        return None


def _template_explanation(
    field_name: str | None,
    category: str,
    confidence: float,
    risk_score: int,
    severity: str,
    reasons: list[str],
) -> str:
    opener = _CATEGORY_OPENERS.get(category, _CATEGORY_OPENERS["unknown"])
    sentences = [opener]

    if category == "database_identifier":
        sentences.append(
            "Identifiers like this are commonly used directly in backend database lookups."
        )
    elif category == "authentication":
        sentences.append(
            "Authentication fields are a common target because they interact with credential "
            "storage and lookup logic."
        )

    sentences.append(
        f"Because its value is user-controlled and the field was classified as '{category}' "
        f"with {confidence:.0%} confidence, it was scored {risk_score}/100 ({severity})."
    )
    if reasons:
        sentences.append("Contributing factors: " + "; ".join(reasons) + ".")
    sentences.append(
        "This is a reconnaissance-stage assessment, not a confirmed vulnerability — it flags "
        "the field for manual security review, not an exploit finding."
    )

    return " ".join(sentences)


def _build_prompt(
    field_name: str | None,
    page_url: str,
    category: str,
    confidence: float,
    risk_score: int,
    severity: str,
    reasons: list[str],
) -> str:
    return (
        "You are a security analyst writing one short paragraph for a reconnaissance "
        "report. This is a passive, discovery-stage finding — no exploit has been "
        "attempted or confirmed, so do not claim the field IS vulnerable, only that it "
        "warrants review. Do not include any preamble, headers, or reasoning steps — "
        "output only the finished paragraph.\n\n"
        f"Field name: {field_name!r}\n"
        f"Found on page: {page_url}\n"
        f"Classified category: {category}\n"
        f"Classification confidence: {confidence:.0%}\n"
        f"Risk score: {risk_score}/100 ({severity})\n"
        f"Contributing factors: {'; '.join(reasons) if reasons else 'none listed'}\n"
    )


def explain(
    field_name: str | None,
    page_url: str,
    category: str,
    confidence: float,
    risk_score: int,
    severity: str,
    reasons: list[str],
) -> str:
    """Returns a short paragraph a security analyst can read directly
    in a report — no JSON, no jargon dump, just the reasoning.

    Uses a local model when LLM_EXPLAINER_BACKEND=ollama (Qwen3) or
    =lmstudio (WhiteRabbitNeo) is set; otherwise (the default) uses
    the fast, deterministic template. Falls back to the template if
    the configured backend is unreachable or errors.
    """
    template_text = _template_explanation(
        field_name, category, confidence, risk_score, severity, reasons
    )

    backend = os.environ.get("LLM_EXPLAINER_BACKEND")
    if backend in ("ollama", "lmstudio"):
        prompt = _build_prompt(
            field_name, page_url, category, confidence, risk_score, severity, reasons
        )
        llm_text = _call_ollama(prompt) if backend == "ollama" else _call_lmstudio(prompt)
        if llm_text:
            return llm_text

    return template_text


def _owasp_template_remediation(category: str, evidence: str, kb_chunks: list[str]) -> str:
    if kb_chunks:
        return kb_chunks[0]
    return f"Review and remediate: {evidence}"


def explain_owasp_finding(category: str, evidence: str, description: str, severity: str) -> str:
    """RAG-grounded remediation for one OwaspFinding: retrieves the
    most relevant local knowledge-base chunk(s) for this finding, then
    (if LLM_EXPLAINER_BACKEND=lmstudio) asks WhiteRabbitNeo to turn
    that retrieved context + the specific evidence into a concrete,
    on-topic fix. Falls back to the raw retrieved chunk if the local
    model isn't reachable, so this never returns an empty string.
    """
    kb_chunks = retrieve(f"{category} {evidence} {description}", k=2)
    template_text = _owasp_template_remediation(category, evidence, kb_chunks)

    if os.environ.get("LLM_EXPLAINER_BACKEND") == "lmstudio":
        context = "\n\n".join(kb_chunks) if kb_chunks else "No specific reference material retrieved."
        prompt = (
            f"OWASP category: {category}\n"
            f"Severity: {severity}\n"
            f"Evidence observed: {evidence}\n"
            f"Description: {description}\n\n"
            f"Reference remediation guidance (retrieved from local knowledge base):\n{context}\n\n"
            "Using the evidence and reference guidance above, write a short, specific, "
            "actionable fix (2-4 sentences) for this exact finding."
        )
        llm_text = _call_lmstudio(prompt)
        if llm_text:
            return llm_text

    return template_text
