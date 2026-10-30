"""A small prompt-injection filter the demo apps can apply at each boundary."""

import re

_INJECTION = re.compile(
    r"(?i)\bignore\s+(all\s+|the\s+)?(previous\s+|prior\s+|above\s+)?(instructions|guidelines|rules)\b"
)
_TAG_CHARACTERS = range(0xE0000, 0xE0080)  # invisible "ASCII smuggling"


def flagged(text: str) -> bool:
    """Whether ``text`` looks like an injection attempt."""
    return bool(_INJECTION.search(text)) or any(ord(c) in _TAG_CHARACTERS for c in text)
