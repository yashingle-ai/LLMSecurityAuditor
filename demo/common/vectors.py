"""A tiny in-memory "vector store" of support notes, with the same search call as
LangChain's vector stores: ``similarity_search(query, k, filter=...)``."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Note:
    customer: str
    text: str


class NoteIndex:
    def __init__(self, notes: list[Note]) -> None:
        self._notes = notes

    def similarity_search(
        self, query: str, k: int = 3, filter: dict[str, str] | None = None
    ) -> list[Note]:
        """The ``k`` notes sharing the most words with ``query``, optionally filtered by field."""
        words = set(query.lower().split())
        candidates = [
            note
            for note in self._notes
            if not filter or all(getattr(note, key) == value for key, value in filter.items())
        ]
        return sorted(candidates, key=lambda note: -len(words & set(note.text.lower().split())))[:k]


SUPPORT_NOTES = NoteIndex(
    [
        Note("alice", "Asked for a refund on INV-1001; refund approved."),
        Note("alice", "Prefers email contact."),
        Note("bob", "Disputed INV-2001; refund pending legal review of the overdue balance."),
        Note("bob", "Account flagged for late payment twice this year."),
    ]
)
