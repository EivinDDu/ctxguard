"""Data-driven regex rules for text-pattern prompt-injection detection.

Each :class:`Rule` is a compiled pattern plus metadata. Detectors in
:mod:`ctxsentry.detectors` also contribute findings that are not expressible as a
single regex (invisible Unicode, HTML smuggling, JSON structure walks).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern

from ctxsentry.finding import Severity

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
            r"\bnew\s+(?:instructions?|rules?|system\s+prompt|directive)\s*[:\-]|"
            r"\bupdated\s+(?:instructions?|system\s+prompt)\s*[:\-]|"
            r"\byou\s+are\s+now\s+(?:a\s+different|an?\s+\w+\s+(?:model|assistant|ai|bot|persona|"
            r"character)\b|(?:in\s+)?\w+\s+mode\b|unrestricted\b|jailbroken\b|DAN\b|"
            r"free\s+(?:from|of)\b|operating\s+without\b|allowed\s+to\s+ignore\b|no\s+longer\s+bound)|"
            r"\bfrom\s+now\s+on[, ]+you\s+(?:will|must|should|shall|are\s+to)\s+"
            r"(?:ignore|disregard|forget|only|no\s+longer|act\s+as|pretend|behave|respond\s+only)\b"
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
            r"<\s*/?\s*(?:system|assistant)\s*>|"
            r"<\|(?:im_start|im_end|system|assistant|user|endoftext)\|>|"
            r"\[/?INST\]|\[/?SYS\]|"
            r"###\s*(?:System\s+prompt|Instruction)\s*(?::|$)|"
            r"^\s*(?:System|Assistant)\s*:\s+(?:you\b|ignore\b|from\s+now|your\s+(?:new|real)\b)",
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
    Rule(
        id="CG106",
        category="instruction-override",
        base_severity=Severity.MEDIUM,
        confidence="medium",
        pattern=_rx(
            r"\bdo\s+anything\s+now\b|\bDAN\s+mode\b|"
            r"\bdeveloper\s+mode\s+(?:enabled|on|output)\b|\bjailbreak\b|"
            r"\bwithout\s+any\s+(?:restrictions|filters|guidelines|guardrails)\b|"
            r"\byou\s+are\s+not\s+bound\s+by\b|"
            r"\bignore\s+your\s+(?:guidelines|guardrails|safety|training|programming)\b|"
            r"\bpretend\s+(?:you\s+have\s+no|there\s+are\s+no)\s+(?:restrictions|rules)\b"
        ),
        message="Jailbreak / guardrail-removal phrasing.",
        reference=_OWASP,
    ),
    Rule(
        id="CG107",
        category="instruction-override",
        base_severity=Severity.HIGH,
        confidence="medium",
        pattern=_rx(
            r"\b(?:repeat|print|output|reveal|show|display|summar(?:ize|ise))\b"
            r"[^.\n]{0,40}\b(?:the\s+)?(?:words?|text|everything|content|instructions?|"
            r"prompt)\b[^.\n]{0,20}\b(?:above|before|preceding|so\s+far|verbatim)\b|"
            r"\bwhat\s+(?:is|are|was)\b[^.\n]{0,20}\byour\s+(?:system\s+prompt|"
            r"initial\s+instructions?|original\s+instructions?)\b"
        ),
        message="Attempt to make the model disclose its own prompt / prior context.",
        reference=_OWASP,
    ),
    # -- Instruction aimed at an assistant, coupled with an action --------
    Rule(
        id="CG201",
        category="agent-directed-instruction",
        base_severity=Severity.MEDIUM,
        confidence="medium",
        pattern=_rx(
            # Vocative: "Claude, run …" / "Hey AI assistant: exfiltrate …"
            r"(?:^|[.!?\n]\s*|\b(?:hey|ok|okay|dear|listen|attention)\s+)"
            r"(?:ai\s+)?(?:assistant|agent|copilot|cursor|claude|chatgpt|gpt|gemini|"
            r"language\s+model|llm)\s*[,:]\s+(?:please\s+)?" + _ACTION + r"\b"
            # "As the/an AI assistant, (please) <verb> …"
            r"|\bas\s+(?:the|an?|my)\s+(?:ai\s+)?(?:assistant|agent|language\s+model|llm|"
            r"coding\s+(?:agent|assistant))\b[^.\n]{0,40},\s*(?:please\s+|you\s+(?:must|should)\s+)?"
            + _ACTION + r"\b"
        ),
        message="Instruction addressed directly to an AI assistant (vocative or 'as the assistant, …').",
        reference=_CSA_README,
    ),
    Rule(
        id="CG202",
        category="agent-directed-instruction",
        base_severity=Severity.MEDIUM,
        confidence="low",
        pattern=_rx(
            r"\byour\s+(?:real|actual|true|only|sole|new|primary|hidden|secret)\s+"
            r"(?:task|job|goal|instruction|objective|purpose|mission)\s+is\b|"
            r"\byour\s+(?:task|job|goal|objective)\s+is\s+to\s+"
            r"(?:exfiltrat|send|leak|reveal|disclose|ignore|delete|curl|run\b|execute|"
            r"forward|upload|print\s+the|email)|"
            r"\byou\s+(?:must|should|need\s+to|have\s+to|are\s+required\s+to)\s+"
            r"(?:immediately\s+|now\s+|first\s+)?"
            r"(?:exfiltrat|curl|run\s+the\s+following|ignore\s+(?:all\s+)?previous|"
            r"delete\s+all|reveal\s+the|print\s+the\s+system|send\s+(?:me|the\s+contents))"
        ),
        message="Imperative framing ('your real task is…', 'you must exfiltrate…').",
        reference=_CSA_README,
    ),
    Rule(
        id="CG203",
        category="agent-directed-instruction",
        base_severity=Severity.MEDIUM,
        confidence="medium",
        pattern=_rx(
            r"(?:^|\n)\s*(?:-{3,}|={3,}|\*{3,}|#{1,6})?\s*"
            r"(?:end\s+of\s+(?:document|file|context|content|input)|"
            r"begin\s+new\s+(?:instructions?|task|prompt)|"
            r"actual\s+(?:instructions?|task)\s+(?:start|follow)|"
            r"system\s+(?:override|message|note)|"
            r"\[\s*(?:system|admin|important)\s*\])\b[^.\n]{0,10}[:\-]?"
        ),
        message="Fake context boundary / 'system' banner used to inject a new task "
        "into retrieved content.",
        reference=_CSA_README,
    ),
    # -- Data exfiltration primitives -----------------------------------
    Rule(
        id="CG301",
        category="exfiltration",
        base_severity=Severity.HIGH,
        confidence="medium",
        pattern=_rx(
            r"(?<!\bnot\s)(?<!n't\s)(?<!\bnever\s)(?<!\bwithout\s)"
            r"\b(?:send|upload|exfiltrate|transmit|forward|e-?mail|post|paste|leak)\b"
            r"[^.\n]{0,45}?(?:\.env\b|\bdotenv\b|\bsecrets?\b|\bapi[_\s-]?keys?\b|"
            r"\baccess[_\s-]?keys?\b|\bcredentials?\b|\bprivate\s+keys?\b|\bssh\s+keys?\b|"
            r"\bid_rsa\b|~/\.(?:aws|ssh|config)\b)"
            r"[^.\n]{0,60}?(?:\bto\s+(?:me\b|us\b|my\b|the\s+(?:following|attacker|server|"
            r"endpoint|address|url))|\bhttps?://|[\w.+-]+@[\w.-]+\.[a-z]{2,})"
        ),
        message="Instruction to send secrets to an external destination.",
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
            r"interact\.sh|ngrok(?:-free)?\.(?:io|app|dev)|beeceptor\.com|mockbin\.\w+|"
            r"canarytokens\.\w+|smee\.io|hookb\.in|webhookrelay\.com|"
            r"trycloudflare\.com|loca\.lt|localtunnel\.me|serveo\.net|lhr\.life|"
            r"dnslog\.cn|\w+\.free\.beeceptor\.com)"
        ),
        message="URL points at a request-capture / callback / tunnel service used for exfiltration.",
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
    Rule(
        id="CG306",
        category="code-execution",
        base_severity=Severity.HIGH,
        confidence="high",
        pattern=re.compile(
            r"bash\s+-i\s*>&?\s*/dev/tcp/|"
            r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+|"
            r"\bnc\s+(?:-\w*e\w*|-\w*c\w*)\b[^\n]{0,50}\b\d{1,5}\b|"
            r"\bpython[0-9.]*\s+-c\s+['\"][^'\"]{0,200}"
            r"(?:socket|pty)\.[^'\"]{0,200}(?:/bin/(?:ba)?sh|exec)",
            re.IGNORECASE | re.DOTALL,
        ),
        message="Reverse-shell command pattern.",
        reference=_OWASP,
    ),
    Rule(
        id="CG307",
        category="exfiltration",
        base_severity=Severity.HIGH,
        confidence="medium",
        pattern=_rx(
            r"\b(?:dig|nslookup|host)\b[^\n]{0,40}\$\((?:cat|base64|whoami|env)\b|"
            r"\b(?:dig|nslookup)\b\s+\+?\w*\s+[\w.$(){}-]+\.(?:oast\.\w+|"
            r"dnslog\.\w+|interact\.sh|burpcollaborator\.net|nip\.io)\b"
        ),
        message="DNS-based exfiltration (encode data into a DNS lookup).",
        reference=_OWASP,
    ),
    Rule(
        id="CG308",
        category="exfiltration",
        base_severity=Severity.HIGH,
        confidence="medium",
        pattern=_rx(
            r"\bgit\s+remote\s+add\b[^\n]{0,60}https?://|"
            r"\bgit\s+push\b[^\n]{0,60}https?://(?![^\s]*github\.com/)|"
            r"\b(?:add|create)\b[^.\n]{0,30}\bpostinstall\b[^.\n]{0,30}\bscript\b|"
            r"\"postinstall\"\s*:\s*\"[^\"]*(?:curl|wget|nc|http)"
        ),
        message="Exfiltration / persistence via version control or package hooks.",
        reference=_OWASP,
    ),
    # -- Obfuscation / smuggling (regex-expressible parts) ---------------
    Rule(
        id="CG401",
        category="obfuscation",
        base_severity=Severity.MEDIUM,
        confidence="low",
        pattern=re.compile(
            r"<!--(?:(?!-->).)*?(?:"
            r"\bignore\s+(?:(?!-->)[^\n]){0,30}?\b(?:instructions?|prompts?|rules?|context)\b|"
            r"\bdisregard\s+(?:the\s+)?(?:above|previous)\b|"
            r"\bdo\s+not\s+(?:tell|mention|inform)\b|\byou\s+must\s+\w+|"
            r"\bexfiltrat|\bsystem\s+prompt\b|<\s*important\s*>|"
            r"\bcurl\b(?:(?!-->).){0,50}\|\s*(?:ba)?sh|\bnew\s+instructions?\s*:"
            r")(?:(?!-->).)*?-->",
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
        pattern=re.compile(
            r"(?:style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|"
            r"font-size\s*:\s*0(?:px|pt|em)?\b|"
            r"(?:color|opacity)\s*:\s*(?:#fff(?:fff)?|white|transparent|0(?:\.0+)?|"
            r"rgba?\(\s*0[\s,]+0[\s,]+0[\s,/]+0"
            r"))[^\"']*[\"']|aria-hidden\s*=\s*[\"']true[\"'])"
            r"[^<>]{0,60}>\s*(?:(?!</).){0,600}?\b(?:"
            r"ignore\s+(?:all\s+)?(?:previous|prior|the\s+above)|system\s+prompt|"
            r"you\s+must\s+\w+|do\s+not\s+(?:tell|mention)|exfiltrat|"
            r"<\s*important\s*>|new\s+instructions?\s*:)",
            re.IGNORECASE | re.DOTALL,
        ),
        message="Element hidden from view but still in the token stream carries instruction-like text.",
        reference=_CSA_README,
    ),
    # CG403 / CG404 (encoded-payload detection) live in ctxsentry.detectors:
    # they decode base64 / hex blobs and rescan the plaintext.
]


def rules_by_id() -> dict:
    return {r.id: r for r in RULES}
