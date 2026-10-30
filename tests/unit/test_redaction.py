import pytest

from llm_auditor.redaction import mask, redact, redact_data
from llm_auditor.rules import secret_patterns

# Built at runtime so this file never contains anything that looks like a real credential.
FAKE = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"


@pytest.mark.parametrize(
    ("secret", "pattern"),
    [
        ("sk-ant-" + FAKE, "anthropic_key"),
        ("sk-proj-" + FAKE, "openai_key"),
        ("AKIA" + "ABCDEFGHIJKLMNOP", "aws_access_key"),
        ("ghp_" + FAKE + "abcdefgh", "github_token"),
        ("xoxb-" + "1234567890-abcdef", "slack_token"),
        ("AIza" + FAKE + "abcdefg", "google_api_key"),
        ("acme_live_9fK2xQ7mRb4TzW1nLp8VcYe3", "live_or_test_key"),  # the demo app's planted key
    ],
)
def test_known_secret_formats_are_masked(secret: str, pattern: str) -> None:
    text = f"use {secret} for billing"

    redacted = redact(text)

    assert secret not in redacted
    assert redacted == f"use {mask(secret)} for billing"
    assert any(p.id == pattern and p.regex.search(text) for p in secret_patterns())


def test_masks_keep_a_recognizable_prefix_and_suffix() -> None:
    assert mask("acme_live_9fK2xQ7mRb4TzW1nLp8VcYe3") == "acme****cYe3"
    assert mask("short") == "****"


def test_assigned_secrets_keep_their_name() -> None:
    assert redact('password = "hunter2hunter2"') == 'password = "hunt****ter2"'
    assert redact("https://x.test/?api_key=" + FAKE + "&q=1") == (
        f"https://x.test/?api_key={mask(FAKE)}&q=1"
    )


def test_bearer_tokens_are_masked() -> None:
    assert redact("Authorization: Bearer " + FAKE) == f"Authorization: Bearer {mask(FAKE)}"


def test_private_keys_are_removed_entirely() -> None:
    key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"

    assert redact(f"key:\n{key}\nend") == "key:\n[PRIVATE KEY]\nend"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("mail alice@example.com now", "mail [EMAIL] now"),
        ("call 415-555-0134 today", "call [PHONE] today"),
        ("ssn 123-45-6789", "ssn [SSN]"),
        ("card 4111 1111 1111 1111", "card [CARD]"),
        ("order 4111 1111 1111 1112", "order 4111 1111 1111 1112"),  # fails the Luhn check
    ],
)
def test_personal_data_is_replaced_with_placeholders(text: str, expected: str) -> None:
    assert redact(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "Invoice INV-1002: 89.50 USD, due.",
        "conv_0001 run_0007 call_2",
        "2026-10-01T09:00:00+00:00",
        "The billing service is operational.",
        "token limit reached",
    ],
)
def test_ordinary_text_is_untouched(text: str) -> None:
    assert redact(text) == text


def test_redaction_is_idempotent() -> None:
    text = "key sk-proj-" + FAKE + " for bob@example.com"

    assert redact(redact(text)) == redact(text)


def test_redact_data_walks_nested_structures() -> None:
    data = {"env": {"KEY": "sk-proj-" + FAKE}, "list": ["alice@example.com", 3]}

    assert redact_data(data) == {"env": {"KEY": mask("sk-proj-" + FAKE)}, "list": ["[EMAIL]", 3]}
