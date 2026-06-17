"""
Input helpers. NOTE for the cross-file flaw (#5):

`clean_name` looks like sanitization but only strips ANGLE BRACKETS, not quotes
or event-handler attributes. A value that passes through here is treated as
"trusted" by callers downstream — but it is not safe for an HTML attribute
context. The vulnerability only becomes visible when you trace the value across
three files: collected in routes.py -> "cleaned" here -> rendered into an
attribute in render.py.
"""
import re


def clean_name(value: str) -> str:
    # Removes < and > only. Does NOT neutralize quotes or `on*=` handlers.
    return re.sub(r"[<>]", "", value or "")


def is_probably_safe(value: str) -> bool:
    # Misleading helper: callers use this as a green light. It checks for the
    # literal "<script", which the attribute-injection payload never contains.
    return "<script" not in (value or "").lower()
