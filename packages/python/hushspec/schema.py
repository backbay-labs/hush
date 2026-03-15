"""Top-level HushSpec schema types."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from hushspec.extensions import Extensions
from hushspec.rules import Rules


class MergeStrategy(str, Enum):
    """Strategy for merging policies when using ``extends``."""

    REPLACE = "replace"
    MERGE = "merge"
    DEEP_MERGE = "deep_merge"


@dataclass
class HushSpec:
    """A parsed HushSpec document.

    This is the top-level type representing a portable security policy.
    """

    hushspec: str
    name: Optional[str] = None
    description: Optional[str] = None
    extends: Optional[str] = None
    merge_strategy: Optional[MergeStrategy] = None
    rules: Optional[Rules] = None
    extensions: Optional[Extensions] = None

    @classmethod
    def from_dict(cls, data: dict) -> HushSpec:
        merge_strategy = None
        if "merge_strategy" in data:
            merge_strategy = MergeStrategy(data["merge_strategy"])
        return cls(
            hushspec=data["hushspec"],
            name=data.get("name"),
            description=data.get("description"),
            extends=data.get("extends"),
            merge_strategy=merge_strategy,
            rules=(
                Rules.from_dict(data["rules"]) if "rules" in data else None
            ),
            extensions=(
                Extensions.from_dict(data["extensions"])
                if "extensions" in data
                else None
            ),
        )

    def to_dict(self) -> dict:
        d: dict = {"hushspec": self.hushspec}
        if self.name is not None:
            d["name"] = self.name
        if self.description is not None:
            d["description"] = self.description
        if self.extends is not None:
            d["extends"] = self.extends
        if self.merge_strategy is not None:
            d["merge_strategy"] = self.merge_strategy.value
        if self.rules is not None:
            d["rules"] = self.rules.to_dict()
        if self.extensions is not None:
            d["extensions"] = self.extensions.to_dict()
        return d
