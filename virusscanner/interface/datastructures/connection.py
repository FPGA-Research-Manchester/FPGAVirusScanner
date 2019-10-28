from typing import Set

from virusscanner.interface.datastructures.port import Port
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Connection:
    begin: Port
    end: Port
    attributes: Set[str] = field(default_factory=set, compare=False)

    def __str__(self) -> str:
        return "{} -> {}".format(self.begin, self.end)
