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
        return " ".join(kb_chunks[:2])
    return f"Review and remediate: {evidence}"


_FOLLOWUP_SYSTEM_PROMPT = (
    "You are WhiteRabbitNeo, a cybersecurity-expert AI planning a knowledge-base lookup. "
    "You will be shown one finding and one already-retrieved reference chunk. Reply with "
    "ONLY a short search phrase (3-6 words) naming the ONE additional security concept "
    "that would most sharpen the fix for THIS specific finding — no punctuation, no "
    "explanation, no preamble, just the phrase itself on a single line."
)


def _agentic_followup_query(category: str, evidence: str, first_chunk: str) -> str | None:
    """The 'agentic' step: instead of a fixed k=2 retrieval, the model
    itself inspects what was already retrieved and names what's still
    missing — so the second retrieval is driven by the model's own
    assessment of the gap, not a hardcoded second query.
    """
    prompt = (
        f"Finding category: {category}\n"
        f"Evidence: {evidence}\n"
        f"Already retrieved reference:\n{first_chunk}\n\n"
        "What ONE additional concept should be looked up next?"
    )
    return _call_lmstudio(prompt, system_prompt=_FOLLOWUP_SYSTEM_PROMPT)


def explain_owasp_finding(category: str, evidence: str, description: str, severity: str) -> str:
    """Agentic RAG remediation for one OwaspFinding:

    1. Retrieve — pull the best-matching local KB chunk for the finding.
    2. Reason — (if LLM_EXPLAINER_BACKEND=lmstudio) ask WhiteRabbitNeo
       what additional concept it needs to sharpen the fix, given what
       was already retrieved. This is the agentic step: the *model*
       decides the follow-up query, it isn't hardcoded.
    3. Retrieve again — look up that model-chosen follow-up query
       against the same local KB.
    4. Generate — ask WhiteRabbitNeo for the final fix, grounded in
       both retrieved chunks plus the specific evidence.

    Falls back to the raw retrieved chunk(s) at any step where the
    local model isn't reachable, so this never returns an empty string
    and never raises.
    """
    first_chunks = retrieve(f"{category} {evidence} {description}", k=1)
    all_chunks = list(first_chunks)

    use_lmstudio = os.environ.get("LLM_EXPLAINER_BACKEND") == "lmstudio"
    if use_lmstudio and first_chunks:
        followup_query = _agentic_followup_query(category, evidence, first_chunks[0])
        if followup_query:
            second_chunks = retrieve(followup_query, k=1)
            all_chunks.extend(c for c in second_chunks if c not in all_chunks)

    template_text = _owasp_template_remediation(category, evidence, all_chunks)

    if use_lmstudio:
        context = "\n\n".join(all_chunks) if all_chunks else "No specific reference material retrieved."
        prompt = (
            f"OWASP category: {category}\n"
            f"Severity: {severity}\n"
            f"Evidence observed: {evidence}\n"
            f"Description: {description}\n\n"
            f"Reference remediation guidance (retrieved from local knowledge base, "
            f"including a self-directed follow-up lookup):\n{context}\n\n"
            "Using the evidence and reference guidance above, write a short, specific, "
            "actionable fix (2-4 sentences) for this exact finding."
        )
        llm_text = _call_lmstudio(prompt)
        if llm_text:
            return llm_text

    return template_text
