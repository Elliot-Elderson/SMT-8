from typing import Literal

from pydantic import BaseModel

from ..extract_validate import split_decision_chapters
from ..ir import DECISION_KINDS, Policy

OUT_OF_VOCAB_MARKERS = ("grep", "chmod", "pack", "unpack")


class UnanchoredBullet(BaseModel):
    text: str
    chapter: str
    reason: Literal["extraction_miss", "out_of_vocab"]


class ClauseCoverageReport(BaseModel):
    total_bullets: int
    anchored_count: int
    unanchored: list[UnanchoredBullet]


def _is_decision_bullet(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("- ") and not stripped.startswith("- 〔")


def _is_out_of_vocab(text: str) -> bool:
    lowered = text.casefold()
    return any(marker.casefold() in lowered for marker in OUT_OF_VOCAB_MARKERS)


def check_clause_coverage(policy: Policy, source_md: str) -> ClauseCoverageReport:
    chapters = split_decision_chapters(source_md)
    if chapters is None:
        return ClauseCoverageReport(total_bullets=0, anchored_count=0, unanchored=[])
    anchors = [
        rule.source_anchor.strip()
        for rule in policy.rules
        if rule.kind in DECISION_KINDS and rule.source_anchor.strip()
    ]
    unanchored: list[UnanchoredBullet] = []
    total = 0
    anchored = 0
    for chapter, body in chapters.items():
        for line in body.splitlines():
            if not _is_decision_bullet(line):
                continue
            total += 1
            if any(anchor in line for anchor in anchors):
                anchored += 1
                continue
            unanchored.append(
                UnanchoredBullet(
                    text=line.strip(),
                    chapter=chapter,
                    reason="out_of_vocab" if _is_out_of_vocab(line) else "extraction_miss",
                )
            )
    return ClauseCoverageReport(
        total_bullets=total,
        anchored_count=anchored,
        unanchored=unanchored,
    )
