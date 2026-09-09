from __future__ import annotations

import re


_SUSPICIOUS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("instruction_override", re.compile(r"\b(ignore|disregard|override)\b.{0,80}\b(previous|earlier|system|developer|instructions?)\b", re.IGNORECASE | re.DOTALL)),
    ("role_impersonation", re.compile(r"\b(you are|act as|pretend to be)\b.{0,60}\b(system|developer|assistant|chatgpt|llm|model)\b", re.IGNORECASE | re.DOTALL)),
    ("instruction_block", re.compile(r"\b(system message|developer message|new instructions?|follow these instructions?)\b", re.IGNORECASE)),
    ("secret_exfiltration", re.compile(r"\b(reveal|output|print|exfiltrate|share)\b.{0,80}\b(secrets?|tokens?|api keys?|credentials?|prompts?)\b", re.IGNORECASE | re.DOTALL)),
    ("tool_manipulation", re.compile(r"\b(run|execute|call)\b.{0,80}\b(shell|terminal|command|tool)\b.{0,80}\b(ignore|without approval|secret|credential)\b", re.IGNORECASE | re.DOTALL)),
)


def inspect_pr_content(title: str = "", body: str = "", diff_text: str = "") -> tuple[bool, list[str]]:
    """Detect likely LLM-directed instructions in untrusted PR content.

    Return pattern labels only. Never persist matched text because it may contain
    secrets or attacker-controlled prompt content.
    """
    content = "\n".join((title, body, diff_text))
    labels = [label for label, pattern in _SUSPICIOUS_PATTERNS if pattern.search(content)]
    return bool(labels), labels