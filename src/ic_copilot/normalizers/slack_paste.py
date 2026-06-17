from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from ic_copilot.schemas import IncidentEvent

URL_RE = re.compile(r"https?://[^\s>)\]]+")
MENTION_RE = re.compile(r"<@([A-Z0-9]+)>|@([A-Za-z][\w.-]*)")
NUMBER_RE = re.compile(r"(?<![\w.-])\d+(?:\.\d+)?(?![\w.-])")
SLASH_COMMAND_RE = re.compile(r"(?<!\w)/[A-Za-z][\w.-]*(?:\s+[^\n\r]+)?")
BOT_COMMAND_RE = re.compile(
    r"(?<!\w)@(?:zsrebot|zsrebotstg)\s+"
    r"(?:oncall|page|incident\s+priority|jira\s+create|daco)\b(?:\s+[^\n\r]+)?",
    re.IGNORECASE,
)

BRACKET_TIMESTAMP = r"(?:\d{1,2}:\d{2}(?:\s?[AP]M)?|[A-Z][a-z]{2,8}\s+\d{1,2}(?:,?\s+\d{4})?(?:\s+\d{1,2}:\d{2}(?:\s?[AP]M)?)?|Today|Yesterday)"

TIMESTAMP_AUTHOR_PATTERNS = [
    re.compile(rf"^\[(?P<ts>{BRACKET_TIMESTAMP})\]\s+(?P<author>[^:]{{1,80}}):\s+(?P<message>.*)$"),
    re.compile(rf"^\[(?P<ts>{BRACKET_TIMESTAMP})\]\s+(?P<message>.*)$"),
    re.compile(
        r"^(?P<author>[^:\[][^:\[]{0,79}?)\s+(?:APP\s+)?"
        r"\[(?P<ts>\d{1,2}:\d{2}\s?[AP]M)\]\s*(?P<message>.*)$",
        re.IGNORECASE,
    ),
    re.compile(r"^(?P<ts>\d{1,2}:\d{2}(?:\s?[AP]M)?)\s+(?P<author>[^:]{1,80}):\s+(?P<message>.*)$"),
    re.compile(r"^(?P<author>[^:]{1,80}):\s+(?P<message>.*)$"),
]
COMPACT_AUTHOR_LINE_RE = re.compile(
    r"^(?P<author>[^:\[][^:\[]{0,79}?)\s+(?:APP\s+)?"
    r"\[(?P<ts>\d{1,2}:\d{2}\s?[AP]M)\]\s*(?P<message>.*)$",
    re.IGNORECASE,
)
COMPACT_TIMESTAMP = r"\d{1,2}:\d{2}\s?[AP]M"
GLUED_CARD_AUTHOR_RE = re.compile(
    rf"(?P<prefix>\b(?:PagerDutyOpen|PagerDuty|JiraCloudOpen|Jira Cloud|ZoomOpen|Open|Refresh|Status|Priority|Assignee|Call))"
    rf"(?P<author>[A-Z][A-Za-z0-9_.-]{{2,}}(?:\s+[A-Z][A-Za-z0-9_.-]{{1,}}){{0,4}})"
    rf"\s+\[(?P<ts>{COMPACT_TIMESTAMP})\]",
)
GLUED_CAMEL_AUTHOR_RE = re.compile(
    rf"(?P<prev>[a-z0-9.!?)])"
    rf"(?P<author>[A-Z][A-Za-z0-9_.-]{{2,}}(?:\s+[A-Z][A-Za-z0-9_.-]{{1,}}){{0,4}})"
    rf"\s+\[(?P<ts>{COMPACT_TIMESTAMP})\]",
)
SLACK_HEADER_PATTERN = re.compile(
    r"^(?P<author>[^:]{1,80}?)\s+(?:APP\s+)?(?P<ts>\d{1,2}:\d{2}\s?[AP]M)$",
    re.IGNORECASE,
)
TIME_ONLY_PATTERN = re.compile(r"^(?P<ts>\d{1,2}:\d{2}\s?[AP]M)$", re.IGNORECASE)

SYSTEM_PHRASES = (
    "created this channel",
    "joined the channel",
    "left the channel",
    "set the channel",
    "renamed the channel",
    "archived the channel",
)
BOT_AUTHOR_NAMES = {
    "anantha app",
    "app",
    "daco-bot",
    "database-agent",
    "default_agent",
    "grafana alert",
    "im-agent",
    "incident-trust-post-notification",
    "slackbot",
    "zsrebot",
    "zsrebotstg",
}
TICKET_CONTEXT_WORDS = (
    "ecra",
    "incident #",
    "jira",
    "l3",
    "pagerduty",
    "pd incident",
    "proactive outreach ticket",
    "ticket",
    "zd",
    "zendesk",
)
TENANT_CONTEXT_WORDS = (
    "account",
    "account id",
    "customer account",
    "entity id",
    "org id",
    "tenant",
    "tenant id",
)
METRIC_CONTEXT_WORDS = (
    "count",
    "error code",
    "hours",
    "lag",
    "line",
    "ora-",
    "status code",
    "total",
    "version",
)
NON_AUTHOR_LABELS = {
    "actions taken",
    "action items",
    "average",
    "assignee",
    "audit logs",
    "awaiting sre",
    "call",
    "command",
    "checkpoint",
    "current status",
    "current update",
    "cpu_usage",
    "customer id",
    "customer name",
    "active",
    "batchcount",
    "comment",
    "createdon",
    "dedicatedcluster",
    "dedicatedtopic",
    "dedicatedtopiccount",
    "diagnosis",
    "environment",
    "envirovmentvariables",
    "error",
    "expiry",
    "findings",
    "fix vulnerability",
    "heavy database load",
    "impact",
    "impact summary",
    "issue",
    "just to confirm",
    "issue priority",
    "issue start time",
    "issue status",
    "jira cloud",
    "key observations",
    "meeting id",
    "monitoring plan",
    "next actions",
    "next action",
    "number of pending messages",
    "owners",
    "pagerduty",
    "pid",
    "potential risk",
    "priority",
    "processlist_db",
    "processlist_id",
    "processlist_user",
    "queue name",
    "reasoning for escalation",
    "reference links",
    "recommended actions",
    "recordfromcache",
    "recordfromdb",
    "rediskeys",
    "related incidents",
    "re-evaluate severity",
    "refresh",
    "roles",
    "root cause",
    "rotate credentials",
    "severity",
    "shard detail",
    "services impacted",
    "status",
    "teams involved",
    "tenants impacted",
    "tenant running the queries",
    "tenantid",
    "the disclosed secrets include",
    "thread_id",
    "tid",
    "topicname",
    "topicnumber",
    "total error call",
    "total queries running",
    "total zdp queries running",
    "urgency",
    "updatedby",
    "updatedon",
    "what caused the previous incident",
    "what fix/mitigation worked",
}
NON_AUTHOR_PREFIXES = (":alert_red:", ":check-img:", ":robot:", "🚀", "🔴", "🟡")
TABLE_OR_SEPARATOR_RE = re.compile(r"^\s*(?:\|[^|]*|[+=-]{3,}|\+[-+]+\+)\s*")
WORK_ITEM_LABEL_RE = re.compile(
    r"^\s*(?:[-*•]\s*)?"
    r"(?P<label>[A-Z][A-Za-z0-9 /&_.-]{2,72}?):\s*"
    r"(?P<body>.+?)\s*$"
)
WORK_ITEM_ACTIVE_VERB_RE = re.compile(
    r"\b(?:is|are|will|was|were|has|have)\s+"
    r"(?:contacting|checking|monitoring|validating|investigating|reviewing|coordinating|working|owning|driving)\b",
    re.IGNORECASE,
)
WORK_ITEM_LEADING_GROUP_RE = re.compile(
    r"^[A-Z][A-Za-z0-9 /&_.-]{1,72}?"
    r"(?:\s+(?:team|Team|engineering|Engineering|SRE|Ops|Support)|Workflow|Security)\s+"
    r"(?:is|are|will|was|were|has|have|checking|monitoring|validating|investigating)\b"
)
WORK_ITEM_LABEL_TERMS = (
    "audit",
    "check",
    "credential",
    "fix",
    "investigation",
    "monitor",
    "next action",
    "next step",
    "recovery",
    "rotate",
    "validation",
)
JSON_DIAGNOSTIC_KEY_RE = re.compile(
    r"""^\s*
    ["']?
    (?P<key>[A-Za-z_][A-Za-z0-9_.-]{1,64})
    ["']?
    \s*:
    (?P<value>.*?)
    \s*,?\s*$""",
    re.VERBOSE | re.IGNORECASE,
)
JSON_FRAGMENT_RE = re.compile(r"^\s*(?:[{}\[\]],?|\"?\{?\\?\"[A-Za-z_][A-Za-z0-9_.-]+\\?\"\s*:)")
DIAGNOSTIC_KEY_NAMES = {
    "active",
    "batchcount",
    "comment",
    "createdon",
    "dedicatedcluster",
    "dedicatedtopic",
    "dedicatedtopiccount",
    "envirovmentvariables",
    "expiry",
    "key",
    "latency_count_topic",
    "locked",
    "recordfromcache",
    "recordfromdb",
    "rediskeys",
    "ttl",
    "tenantid",
    "topicname",
    "topicnumber",
    "updatedby",
    "updatedon",
}


def _label_key(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().strip(":").replace("_", " ").lower())


def _is_table_or_separator_line(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped and TABLE_OR_SEPARATOR_RE.match(stripped))


def _looks_like_non_author_label(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    normalized = re.sub(r"^\s*(?:[-*•]|\d+\.)\s*", "", stripped).strip()
    lowered = _label_key(normalized)
    if lowered in NON_AUTHOR_LABELS:
        return True
    if _looks_like_json_diagnostic_line(normalized):
        return True
    if any(lowered.startswith(prefix) for prefix in ("processlist ", "total ", "customer ")):
        return True
    if any(normalized.startswith(prefix) for prefix in NON_AUTHOR_PREFIXES):
        return True
    work_item = WORK_ITEM_LABEL_RE.match(normalized)
    if work_item:
        label = _label_key(work_item.group("label"))
        body = work_item.group("body")
        if (
            any(term in label for term in WORK_ITEM_LABEL_TERMS)
            and (
                body.strip().startswith("(Owner:")
                or (body.strip().startswith("@") and WORK_ITEM_ACTIVE_VERB_RE.search(body))
                or WORK_ITEM_LEADING_GROUP_RE.search(body)
            )
        ):
            return True
    return False


def _looks_like_json_diagnostic_line(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    if JSON_FRAGMENT_RE.match(stripped):
        return True
    match = JSON_DIAGNOSTIC_KEY_RE.match(stripped)
    if not match:
        return False
    key = _label_key(match.group("key"))
    if key in DIAGNOSTIC_KEY_NAMES:
        return True
    value = match.group("value").strip()
    # In pasted diagnostic objects, camelCase/snake_case keys followed by a
    # scalar or nested object are log structure, not Slack display names.
    return (
        bool(re.search(r"[A-Z_]", match.group("key")))
        and len(key.split()) == 1
        and bool(re.match(r"^(?:[{\[\"']|true\b|false\b|null\b|-?\d)", value, re.IGNORECASE))
    )


def _suspicious_author_reason(author: str | None, message: str = "") -> str | None:
    if not author:
        return None
    stripped = author.strip()
    normalized = _label_key(stripped)
    if normalized in BOT_AUTHOR_NAMES:
        return None
    if normalized.startswith("just to confirm"):
        return "question_prefix_not_author"
    if re.match(r"^\d+\s+files?\b", normalized):
        return "file_label_not_author"
    if normalized.startswith("phase update"):
        return "phase_update_label_not_author"
    if normalized.startswith("set the channel topic"):
        return "slack_lifecycle_label"
    if "response we would see this" in normalized:
        return "generated_summary_fragment_not_author"
    if re.match(r"^@?[a-z][\w .-]{1,80}\s+as reported here\b", normalized):
        return "quoted_mention_prefix_not_author"
    if re.match(r"^srebot[a-z0-9_.-]+$", normalized):
        return "fused_bot_author_not_human"
    if "#" in stripped or URL_RE.search(stripped):
        return "channel_or_url_fragment"
    if any(normalized.startswith(phrase.removesuffix(" the channel")) for phrase in SYSTEM_PHRASES):
        return "slack_lifecycle_label"
    if _is_table_or_separator_line(stripped):
        return "table_or_separator_line"
    if _looks_like_non_author_label(stripped):
        return "diagnostic_or_key_value_label"
    if _looks_like_json_diagnostic_line(stripped):
        return "json_or_log_diagnostic_key"
    if stripped.startswith(NON_AUTHOR_PREFIXES):
        return "emoji_or_generated_header"
    if re.fullmatch(r"[\w.-]+", stripped) and normalized in {"tid", "pid", "command", "average"}:
        return "diagnostic_label"
    if len(stripped.split()) > 8:
        return "too_many_words_for_author"
    if normalized in {"here", "@here", "channel", "@channel"}:
        return "broadcast_mention_not_author"
    if re.fullmatch(r"(?:ap\s+)?(?:prod|production|sandbox|csbx|qa|stage|stg|dev)\s*\d*", normalized):
        return "environment_label"
    if re.fullmatch(r"(?:prod|csbx|sandbox|stage|stg|dev)\d{1,5}", normalized):
        return "environment_label"
    if message and _looks_like_non_author_label(f"{stripped}:"):
        return "diagnostic_or_key_value_label"
    if message and "(owner:" in message.lower() and normalized in NON_AUTHOR_LABELS:
        return "owner_action_label"
    if message and _looks_like_non_author_label(f"{stripped}: {message}"):
        return "work_item_continuation_line"
    return None


def _parse_line(line: str) -> tuple[str | None, str | None, str]:
    for pattern in TIMESTAMP_AUTHOR_PATTERNS:
        match = pattern.match(line)
        if match:
            return match.groupdict().get("ts"), match.groupdict().get("author"), match.group("message")
    return None, None, line


def _split_compact_author_markers(raw_text: str) -> str:
    """Recover compact Slack export markers that were pasted without line breaks."""

    def split_card(match: re.Match[str]) -> str:
        return f"{match.group('prefix')}\n{match.group('author')} [{match.group('ts')}]"

    def split_camel(match: re.Match[str]) -> str:
        return f"{match.group('prev')}\n{match.group('author')} [{match.group('ts')}]"

    text = GLUED_CARD_AUTHOR_RE.sub(split_card, raw_text)
    return GLUED_CAMEL_AUTHOR_RE.sub(split_camel, text)


def _is_compact_author_line(line: str) -> bool:
    return bool(COMPACT_AUTHOR_LINE_RE.match(line.strip()))


def _parse_header_line(line: str) -> tuple[str, str] | None:
    match = SLACK_HEADER_PATTERN.match(line)
    if not match:
        return None
    author = match.group("author").strip()
    if _suspicious_author_reason(author):
        return None
    if len(author.split()) > 8:
        return None
    return match.group("ts"), author


def _looks_like_author_only_header(line: str) -> bool:
    stripped = line.strip()
    if not stripped or ":" in stripped or URL_RE.search(stripped):
        return False
    if _is_table_or_separator_line(stripped) or _suspicious_author_reason(stripped):
        return False
    lowered = stripped.lower()
    if any(phrase in lowered for phrase in SYSTEM_PHRASES):
        return False
    if len(stripped) > 80 or len(stripped.split()) > 8:
        return False
    return bool(re.search(r"[A-Za-z]", stripped))


def _is_system_or_bot(author: str | None, message: str) -> tuple[bool, bool]:
    author_l = (author or "").lower()
    message_l = message.lower()
    is_bot = "bot" in author_l or author_l in BOT_AUTHOR_NAMES
    is_system = any(phrase in message_l for phrase in SYSTEM_PHRASES)
    return is_system, is_bot


def classify_numeric_evidence(value: str, context: str) -> str:
    """Type a numeric token by nearby text without inferring incident facts."""
    context_norm = _label_key(context)
    before, _, _after = context_norm.partition(value.lower())
    value_in_url_path = bool(
        re.search(rf"https?://\S*/(?:[^/\s]+/)*{re.escape(value)}(?:/|\b)", context, re.I)
    )
    ticket_before = any(word in before for word in TICKET_CONTEXT_WORDS)
    tenant_before = any(word in before for word in TENANT_CONTEXT_WORDS)
    ticket_near = any(word in context_norm for word in TICKET_CONTEXT_WORDS)
    tenant_near = any(word in context_norm for word in TENANT_CONTEXT_WORDS)
    if ticket_before and not tenant_before:
        return "ticket_id"
    if tenant_before or (tenant_near and not ticket_before):
        return "tenant_id"
    if ticket_near:
        return "ticket_id"
    if value_in_url_path or any(word in context_norm for word in ("doc", "docs", "wiki", "url")):
        return "url_path_number"
    if any(word in context_norm for word in METRIC_CONTEXT_WORDS):
        return "metric_count_version"
    return "untyped_numeric_id"


def _number_tokens(message: str) -> list[dict[str, str]]:
    tokens: list[dict[str, str]] = []
    for match in NUMBER_RE.finditer(message):
        start = max(0, match.start() - 24)
        end = min(len(message), match.end() + 24)
        context = message[start:end].strip()
        tokens.append(
            {
                "value": match.group(0),
                "context": context,
                "numeric_evidence_kind": classify_numeric_evidence(match.group(0), context),
                "targetable": "false",
            }
        )
    return tokens


def _command_candidates(message: str, is_system: bool) -> list[str]:
    if is_system:
        return []
    candidates: list[str] = []
    url_spans = [match.span() for match in URL_RE.finditer(message)]
    for pattern in (SLASH_COMMAND_RE, BOT_COMMAND_RE):
        for match in pattern.finditer(message):
            if any(start <= match.start() < end for start, end in url_spans):
                continue
            command = " ".join(match.group(0).strip().split())
            if "created this channel" in command.lower():
                continue
            candidates.append(command)
    return list(dict.fromkeys(candidates))


def _tokens(message: str, is_system: bool, is_bot: bool) -> dict[str, Any]:
    urls = URL_RE.findall(message)
    mentions = [group for match in MENTION_RE.findall(message) for group in match if group]
    return {
        "urls": urls,
        "slack_mentions": mentions,
        "command_candidates": _command_candidates(message, is_system),
        "numbers": _number_tokens(message),
        "is_system": is_system,
        "is_bot": is_bot,
    }


def extract_slack_like_tokens(
    message: str,
    author: str | None = None,
    urls: list[str] | None = None,
    mentions: list[str] | None = None,
    command_candidates: list[str] | None = None,
) -> dict[str, Any]:
    """Tokenize Slack-like text without doing semantic incident inference."""
    is_system, is_bot = _is_system_or_bot(author, message)
    tokens = _tokens(message, is_system, is_bot)
    if urls:
        tokens["urls"] = sorted({*tokens["urls"], *urls})
    if mentions:
        tokens["slack_mentions"] = sorted({*tokens["slack_mentions"], *mentions})
    if command_candidates and not is_system:
        safe_commands = [command for command in command_candidates if "created this channel" not in command.lower()]
        tokens["command_candidates"] = sorted({*tokens["command_candidates"], *safe_commands})
    return tokens


def normalize_slack_paste(raw_text: str, incident_id: str | None = None) -> list[IncidentEvent]:
    incident_id = incident_id or "incident-local"
    events: list[IncidentEvent] = []
    pending_header: tuple[str | None, str] | None = None
    pending_author_only: str | None = None
    lines = _split_compact_author_markers(raw_text).splitlines()

    for index, raw_line in enumerate(lines):
        line = raw_line.rstrip()
        if not line.strip():
            continue
        continuation_reason = None
        if _is_table_or_separator_line(line) or _looks_like_non_author_label(line):
            continuation_reason = "non_author_continuation_line"
        header = _parse_header_line(line.strip())
        if header:
            pending_header = header
            pending_author_only = None
            continue
        time_only = TIME_ONLY_PATTERN.match(line.strip())
        if time_only and pending_author_only:
            pending_header = (time_only.group("ts"), pending_author_only)
            pending_author_only = None
            continue
        next_line = lines[index + 1].strip() if index + 1 < len(lines) else ""
        if _looks_like_author_only_header(line) and TIME_ONLY_PATTERN.match(next_line):
            pending_author_only = line.strip()
            continue
        if pending_header:
            ts, author = pending_header
            message = line
            pending_header = None
        else:
            ts, author, message = _parse_line(line)
            if (author is not None or ts is not None) and continuation_reason == "non_author_continuation_line":
                continuation_reason = None
        compact_author_recovered = bool(author and ts and _is_compact_author_line(line))
        suspicious_reason = _suspicious_author_reason(author, message)
        if suspicious_reason:
            continuation_reason = suspicious_reason
            ts = None
            author = None
            message = line
            compact_author_recovered = False
        if events and author is None and ts is None:
            previous = events[-1]
            combined_message = f"{previous.message}\n{line}"
            is_system, is_bot = _is_system_or_bot(previous.author, combined_message)
            stable = f"{incident_id}|{previous.sequence}|{previous.author or ''}|{combined_message}"
            metadata = dict(previous.raw_metadata)
            metadata.setdefault("continuations", []).append(line)
            if continuation_reason:
                metadata.setdefault("parser_warnings", []).append(continuation_reason)
                metadata["non_author_continuation_lines"] = int(metadata.get("non_author_continuation_lines", 0)) + 1
            events[-1] = previous.model_copy(
                update={
                    "message": combined_message,
                    "extracted_tokens": _tokens(combined_message, is_system, is_bot),
                    "raw_metadata": metadata,
                    "hash": hashlib.sha256(stable.encode("utf-8")).hexdigest(),
                }
            )
            continue
        is_system, is_bot = _is_system_or_bot(author, message)
        sequence = len(events) + 1
        event_id = f"m{sequence:03d}"
        stable = f"{incident_id}|{sequence}|{author or ''}|{message}"
        event_hash = hashlib.sha256(stable.encode("utf-8")).hexdigest()
        events.append(
            IncidentEvent(
                event_id=event_id,
                incident_id=incident_id,
                ts=ts,
                sequence=sequence,
                source="slack_system" if is_system else "slack_paste",
                author=author.strip() if author else None,
                message=message,
                extracted_tokens=_tokens(message, is_system, is_bot),
                raw_metadata={
                    "raw_line": line,
                    **({"compact_author_recovered": True} if compact_author_recovered else {}),
                    **(
                        {
                            "parser_warnings": [continuation_reason],
                            "non_author_continuation_lines": 1,
                        }
                        if continuation_reason
                        else {}
                    ),
                },
                hash=event_hash,
            )
        )
    return events


def normalize_slack_text(raw_text: str, incident_id: str | None = None) -> list[IncidentEvent]:
    return normalize_slack_paste(raw_text, incident_id=incident_id)


def normalize_slack_paste_file(path: str | Path, incident_id: str | None = None) -> list[IncidentEvent]:
    return normalize_slack_paste(Path(path).read_text(), incident_id=incident_id)
