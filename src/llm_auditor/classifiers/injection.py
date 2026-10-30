"""Prompt-injection classifiers: built-in rules, or a local Hugging Face model.

Every classifier scores text from 0 to 1 for one of two channels:

- ``user``: what the app's own user typed. Asking the agent to use a tool is normal
  here; overriding its instructions or extracting its prompt is not.
- ``content``: third-party text the model reads (tool results, web pages, emails,
  documents). Any instruction aimed at the model is suspect here.
"""

import importlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from llm_auditor.models import InjectionClassifierSettings, Oracle

Channel = Literal["user", "content"]
BOTH: frozenset[Channel] = frozenset({"user", "content"})
CONTENT: frozenset[Channel] = frozenset({"content"})
MAX_CHARS = 2000  # the model sees at most this much text at a time


@dataclass(frozen=True)
class Verdict:
    score: float  # 0 to 1: how likely the text is an injection attempt
    signals: tuple[str, ...]  # what matched, or the model's label


class InjectionClassifier(Protocol):
    name: str
    oracle: Oracle
    threshold: float

    def classify(self, text: str, channel: Channel) -> Verdict: ...


@dataclass(frozen=True)
class Signal:
    name: str
    weight: float
    pattern: re.Pattern[str]
    channels: frozenset[Channel] = BOTH


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


_TARGETS = r"(instructions?|prompts?|rules|guidelines|directives|constraints|guardrails|context)"
SIGNALS = (
    Signal(
        "overrides its instructions",
        0.9,
        _rx(
            r"\b(ignore|disregard|forget|override|bypass|skip|abandon)\b[^.\n]{0,40}"
            r"\b(previous|prior|above|earlier|preceding|all|any|your|system|initial|original)"
            rf"\b[^.\n]{{0,30}}\b{_TARGETS}\b"
        ),
    ),
    Signal(
        "asks for the system prompt",
        0.8,
        _rx(
            r"\b(reveal|print|show|repeat|output|display|tell me|give me|leak|dump|recite"
            r"|reproduce|spell out|what (is|are|were))\b[^.\n]{0,40}\b(your|the)\s+"
            r"(system\s+prompt|initial\s+prompt|original\s+(instructions|prompt)"
            r"|(hidden|secret|internal)\s+(instructions|prompt|rules)|instructions"
            r"|(text|words|everything)\s+above|developer\s+message)"
        ),
    ),
    Signal(
        "imitates chat-format markup",
        0.7,
        _rx(
            r"<\|(im_start|im_end|system|assistant|user)\|>|\[/?INST\]|<<SYS>>"
            r"|<\s*/?\s*(system|instructions?)\s*>|\[(system|admin)( message)?\]"
            r"|^\s*#{1,3}\s*(system|new instructions?)\s*:?\s*$"
        ),
    ),
    Signal(
        "jailbreak persona",
        0.6,
        _rx(
            r"\bDAN\b|\bdo anything now\b|\bdeveloper mode\b|\bjailbr(eak|oken)"
            r"|\b(without|no) (any )?(restrictions|limitations|filters|censorship)\b"
            r"|\byou are (now )?(free|unrestricted|uncensored|unfiltered)\b"
            r"|\bact as (an? )?(unrestricted|uncensored|unfiltered|evil|rogue)\b"
        ),
    ),
    Signal(
        "announces new instructions",
        0.6,
        _rx(
            r"\b(new|updated|real|actual|revised|additional|important) (system )?"
            r"(instructions?|rules|directives)(\s+(for|to)\s+(the\s+|any\s+)?(AI|assistant|model"
            r"|agent|LLM|bot)s?)?\s*[:!]|\byour new (task|role|goal|instructions?)"
            r" (is|are)\b|\bfrom now on,? (you|always|never)\b"
        ),
    ),
    Signal(
        "addresses the AI reading it",
        # Context, not an attack on its own: transcripts say "Agent:" and "Assistant:" too.
        0.4,
        _rx(
            r"(^|[.!?]\s+)(dear |attention,? |note to (the )?|hey |hi |hello )?(AI|assistant"
            r"|AI assistant|chatbot"
            r"|language model|LLM|agent|AI agent)s?\s*[,:!]"
            r"|\b(if you are|as) an? (AI|assistant|language model|LLM)\b"
            r"|\b(instructions?|message|note) (to|for) (the |any )?(AI|assistant|model|agent|LLM"
            r"|bot)s?\b"
        ),
        CONTENT,
    ),
    Signal(
        "tells the model to call a tool",
        0.6,
        _rx(
            r"\b(call|invoke|use|run|execute|trigger)\s+(the\s+)?`?[a-z]+(_[a-z0-9]+)+`?"
            r"(\s+(tool|function)|\s+with\b)|\bcall\s+`?\w+`?\s+with\s*\{"
        ),
        CONTENT,
    ),
    Signal(
        "tells the model to hide something from the user",
        0.6,
        _rx(
            r"\b(do not|don't|never) (tell|inform|mention|reveal|show|alert|notify|let)\b"
            r"(\s+(this|it|that|these)(\s+\w+)?)?\s+(to\s+)?(the\s+)?(user|customer|human"
            r"|operator)s?\b|\bwithout (telling|informing"
            r"|notifying|alerting) (the )?(user|customer)\b|\b(secretly|silently|quietly)"
            r" (send|forward|email|call|add|include|delete|copy)\b"
        ),
        CONTENT,
    ),
    Signal(
        "tells the model to send data out",
        0.6,
        _rx(
            r"!\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]*="
            # Not a report of what already happened: "Email 'Invoice' sent to x@y"
            r"|\b(send|forward|email|post|upload|exfiltrate|copy|leak)\b"
            r"((?!\b(sent|forwarded|emailed|delivered|was|were)\b)[^.\n]){0,80}\bto\b"
            r"[^.\n]{0,20}[\w.+-]+@[\w-]+(\.[\w-]+)+"
        ),
        CONTENT,
    ),
    Signal(
        "dictates the model's reply",
        0.5,
        _rx(
            r"(^|[.!?,;:]\s+)(say|reply with|respond with|answer with)\s+[\"“]"
            r"|\b(you must|always) (say|reply|respond|answer)\b"
        ),
        CONTENT,
    ),
)


class RuleClassifier:
    """Weighted signal rules. Deterministic, no download; misses novel phrasings."""

    name = "rules"
    oracle = Oracle.RULE

    def __init__(self, threshold: float = 0.5) -> None:
        self.threshold = threshold

    def classify(self, text: str, channel: Channel) -> Verdict:
        matched = [s for s in SIGNALS if channel in s.channels and s.pattern.search(text)]
        remaining = 1.0
        for signal in matched:
            remaining *= 1 - signal.weight
        return Verdict(score=round(1 - remaining, 3), signals=tuple(s.name for s in matched))


class ClassifierUnavailable(Exception):
    """The configured classifier can't be loaded (e.g. its library isn't installed)."""


class HuggingFaceClassifier:
    """A local text-classification model, such as ProtectAI's DeBERTa prompt-injection model
    or Meta's Prompt Guard. Needs the ``classifier`` extra; weights download on first use."""

    oracle = Oracle.CLASSIFIER

    def __init__(self, settings: InjectionClassifierSettings, pipeline: Any = None) -> None:
        self.name = settings.model
        self.threshold = settings.threshold
        self._labels = {label.upper() for label in settings.injection_labels}
        self._pipeline = pipeline or _load_pipeline(settings.model)

    def classify(self, text: str, channel: Channel) -> Verdict:
        chunks = [text[i : i + MAX_CHARS] for i in range(0, max(len(text), 1), MAX_CHARS)]
        best, label = 0.0, "no text"
        for result in self._pipeline(chunks, truncation=True):
            flagged = str(result["label"]).upper() in self._labels
            score = float(result["score"]) if flagged else 1 - float(result["score"])
            if score >= best:
                best, label = score, str(result["label"])
        return Verdict(score=round(best, 3), signals=(f"{self.name}: {label}",))


def _load_pipeline(model: str) -> Any:
    try:
        transformers = importlib.import_module("transformers")
    except ImportError as error:
        raise ClassifierUnavailable(
            "the huggingface classifier needs transformers and torch: "
            "install them with `uv pip install transformers torch`, or use `backend: rules`"
        ) from error
    try:
        return transformers.pipeline("text-classification", model=model)
    except Exception as error:  # download, auth, and model errors all mean "can't classify"
        raise ClassifierUnavailable(f"could not load the model {model}: {error}") from error


def build_classifier(settings: InjectionClassifierSettings) -> InjectionClassifier:
    if settings.backend == "huggingface":
        return HuggingFaceClassifier(settings)
    return RuleClassifier(settings.threshold)


def flagged(classifier: InjectionClassifier, texts: Sequence[str], channel: Channel) -> Verdict:
    """The highest-scoring verdict over several texts (e.g. visible and hidden parts)."""
    verdicts = [classifier.classify(text, channel) for text in texts if text.strip()]
    return max(verdicts, key=lambda v: v.score, default=Verdict(0.0, ()))
