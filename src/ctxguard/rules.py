"""Data-driven regex rules for text-pattern prompt-injection detection.

Each :class:`Rule` is a compiled pattern plus metadata. Detectors in
:mod:`ctxguard.detectors` also contribute findings that are not expressible as a
single regex (invisible Unicode, HTML smuggling, JSON structure walks).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern

from ctxguard.finding import Severity

_OWASP = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
_CSA_README = (
    "https://labs.cloudsecurityalliance.org/research/"
    "csa-research-note-readme-instruction-injection-ai-coding-agents/"
)
_TROJAN_SOURCE = "https://trojansource.codes/"
_MCP_POISON = "https://www.cve.org/CVERecord?id=CVE-2025-54136"


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    base_severity: Severity
    confidence: str
    pattern: Pattern[str]
    message: str
    reference: str = ""


def _rx(pattern: str) -> Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


# Terms that make a sentence look addressed to an AI assistant rather than a human.
_ASSISTANT = (
    r"(?:ai|a\.i\.|assistant|agent|model|llm|chatbot|copilot|cursor|claude|"
    r"chatgpt|gpt|gemini|codex|language\s+model|coding\s+(?:agent|assistant))"
)
# Verbs that describe an action an attacker wants the agent to take.
_ACTION = (
    r"(?:run|execute|eval|exfiltrate|send|post|upload|curl|wget|fetch|download|"
    r"install|delete|remove|rm\s|drop|push|commit|open|read|print|reveal|"
    r"disclose|leak|email|transmit|copy|encode|base64)"
)

RULES: List[Rule] = [
    # -- Direct instruction / role overrides -------------------------------
    Rule(
        id="CG101",
        category="instruction-override",
        base_severity=Severity.HIGH,
        confidence="high",
        pattern=_rx(
            r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}"
            r"\b(?:all\s+)?(?:previous|prior|above|earlier|system|initial|"
            r"the\s+following)\b[^.\n]{0,20}"
            r"\b(?:instruction|instructions|prompt|prompts|context|rules?|"
            r"directions?|guidance)\b"
        ),
        message="Classic instruction-override phrasing ('ignore previous instructions').",
        reference=_OWASP,
    ),
    Rule(
        id="CG102",
        category="instruction-override",
        base_severity=Severity.HIGH,
        confidence="medium",
        pattern=_rx(
            r"\byou\s+are\s+now\b|\bfrom\s+now\s+on\s+you\b|"
            r"\bnew\s+(?:instructions?|rules?|system\s+prompt|directive)\s*[:\-]|"
            r"\bupdated\s+(?:instructions?|system\s+prompt)\s*[:\-]"
        ),
        message="Persona / instruction reset directed at the model.",
        reference=_OWASP,
    ),
    Rule(
        id="CG103",
        category="instruction-override",
        base_severity=Severity.HIGH,
        confidence="high",
        pattern=re.compile(
            r"<\s*/?\s*(?:system|assistant|user|developer|tool)\s*>|"
            r"<\|(?:im_start|im_end|system|assistant|user|endoftext)\|>|"
            r"\[/?INST\]|\[/?SYS\]|###\s*(?:System|Instruction|Assistant)\b|"
            r"^\s*(?:System|Assistant|Developer)\s*:",
            re.IGNORECASE | re.MULTILINE,
        ),
        message="Chat-template / role-delimiter tokens embedded in prose.",
        reference=_OWASP,
    ),
    Rule(
        id="CG104",
        category="instruction-override",
        base_severity=Severity.MEDIUM,
        confidence="medium",
        pattern=_rx(
            r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention\s+to|reveal\s+to|"
            r"warn|alert|notify)\s+(?:the\s+)?(?:user|human|developer|operator)\b"
        ),
        message="Instruction to hide activity from the user.",
        reference=_MCP_POISON,
    ),
    Rule(
        id="CG105",
        category="instruction-override",
        base_severity=Severity.MEDIUM,
        confidence="medium",
        pattern=_rx(
            r"<\s*IMPORTANT\s*>|<\s*SECRET\s*>|"
            r"\bbefore\s+(?:using|calling|invoking)\s+(?:any\s+)?(?:other\s+)?tool"
        ),
        message="Hidden-priority marker of the kind used in MCP tool-poisoning payloads.",
        reference=_MCP_POISON,
    ),
    # -- Instruction aimed at an assistant, coupled with an action --------
    Rule(
        id="CG201",
        category="agent-directed-instruction",
        base_severity=Severity.MEDIUM,
        confidence="medium",
        pattern=_rx(
            r"(?:(?:^|[.!?\n]\s*)|\b(?:as|dear|hey|attention|ok|okay|now)\b[ ,]{0,3})"
            + _ASSISTANT
            + r"\b[ ,:]{0,3}[^.\n]{0,60}\b"
            + _ACTION
            + r"\b"
        ),
        message="Sentence addressed to an AI assistant that also names an action to take.",
        reference=_CSA_README,
    ),
    Rule(
        id="CG202",
        category="agent-directed-instruction",
        base_severity=Severity.MEDIUM,
        confidence="low",
        pattern=_rx(
            r"\byour\s+(?:real\s+)?(?:task|job|goal|instruction|objective)\s+is\b|"
            r"\byou\s+(?:must|should|need\s+to|have\s+to|are\s+required\s+to)\s+"
            + _ACTION
        ),
        message="Imperative framing ('your task is', 'you must run…').",
        reference=_CSA_README,
    ),
    # -- Data exfiltration primitives -----------------------------------
    Rule(
        id="CG301",
        category="exfiltration",
        base_severity=Severity.HIGH,
        confidence="medium",
        pattern=_rx(
            r"\b(?:send|upload|exfiltrate|transmit|forward|leak|e-?mail)\b[^.\n]{0,40}"
            r"(?:\b(?:secrets?|tokens?|api[_\s-]?keys?|access[_\s-]?keys?|credentials?|"
            r"passwords?|private\s+keys?|ssh\s+keys?|dotenv)\b|\.env\b)"
        ),
        message="Instruction to send secrets somewhere.",
        reference=_OWASP,
    ),
    Rule(
        id="CG302",
        category="exfiltration",
        base_severity=Severity.HIGH,
        confidence="high",
        pattern=_rx(
            r"https?://(?:[a-z0-9-]+\.)*(?:webhook\.site|pipedream\.net|"
            r"requestbin\.\w+|requestcatcher\.com|oast\.\w+|burpcollaborator\.net|"
            r"interact\.sh|ngrok\.(?:io|app|dev)|beeceptor\.com|mockbin\.\w+|"
            r"canarytokens\.\w+)"
        ),
        message="URL points at a request-capture / callback service used for exfiltration.",
        reference=_OWASP,
    ),
    Rule(
        id="CG303",
        category="exfiltration",
        base_severity=Severity.MEDIUM,
        confidence="medium",
        pattern=re.compile(
            r"!\[[^\]]*\]\(\s*https?://"
            r"(?!(?:[a-z0-9-]+\.)*(?:shields\.io|badgen\.net|github\.com|"
            r"githubusercontent\.com|forthebadge\.com|codecov\.io|coveralls\.io|"
            r"circleci\.com|travis-ci\.(?:org|com)|codacy\.com|snyk\.io|"
            r"readthedocs\.org|opencollective\.com|gitpod\.io|herokuapp\.com))"
            r"[^)\s]*[?&#][^)\s]*\)",
            re.IGNORECASE,
        ),
        message="Markdown image with a query string: can auto-exfiltrate on render.",
        reference=_OWASP,
    ),
    Rule(
        id="CG304",
        category="exfiltration",
        base_severity=Severity.HIGH,
        confidence="high",
        pattern=_rx(
            r"\bcurl\b[^\n|]{0,120}\|\s*(?:sudo\s+)?(?:ba)?sh\b|"
            r"\bwget\b[^\n|]{0,120}\|\s*(?:sudo\s+)?(?:ba)?sh\b|"
            r"\b(?:iwr|invoke-webrequest)\b[^\n|]{0,120}\|\s*iex\b"
        ),
        message="Pipe-to-shell one-liner (remote code execution primitive).",
        reference=_OWASP,
    ),
    # -- Obfuscation / smuggling (regex-expressible parts) ---------------
    Rule(
        id="CG401",
        category="obfuscation",
        base_severity=Severity.MEDIUM,
        confidence="low",
        pattern=re.compile(
            r"<!--[^>]*?\b(?:ignore|instruction|system|assistant|you\s+must|"
            r"do\s+not\s+tell|exfiltrate|api[_\s-]?key|token|prompt)\b[^>]*?-->",
            re.IGNORECASE | re.DOTALL,
        ),
        message="HTML comment carrying instruction-like text (hidden on render).",
        reference=_CSA_README,
    ),
    Rule(
        id="CG402",
        category="obfuscation",
        base_severity=Severity.MEDIUM,
        confidence="medium",
        pattern=_rx(
            r"style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|"
            r"font-size\s*:\s*0|color\s*:\s*(?:#fff(?:fff)?|white|transparent|rgba\(0,\s*0,\s*0,\s*0\)))"
        ),
        message="Inline style hides text visually while leaving it in the token stream.",
        reference=_CSA_README,
    ),
    Rule(
        id="CG403",
        category="obfuscation",
        base_severity=Severity.LOW,
        confidence="low",
        pattern=re.compile(
            r"(?:[A-Za-z0-9+/]{80,}={0,2})",
        ),
        message="Long base64-looking blob; decode and inspect for hidden instructions.",
        reference=_OWASP,
    ),
]


def rules_by_id() -> dict:
    return {r.id: r for r in RULES}
