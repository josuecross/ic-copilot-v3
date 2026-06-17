from __future__ import annotations

from ic_copilot.schemas import ICDecision


def _command_text(value) -> str | None:
    if not value:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("command_text") or value.get("command") or value.get("text")
    return getattr(value, "command_text", None) or getattr(value, "command", None) or str(value)


def render_ic_whisper(decision: ICDecision) -> str:
    sections: list[tuple[str, str | None]] = [
        ("SAY THIS", decision.output.get("say_this")),
        ("NEXT LINE", decision.output.get("next_line")),
        ("COMMAND", _command_text(decision.output.get("command"))),
    ]
    rendered: list[str] = []
    for label, value in sections:
        if value:
            rendered.append(f"{label}:\n{value}")
    return "\n\n".join(rendered)
