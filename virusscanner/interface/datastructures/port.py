from virusscanner.interface.datastructures.tile import Tile
from dataclasses import dataclass


@dataclass(frozen=True)
class Port:
    tile: Tile
    name: str

    def __str__(self) -> str:
        return "{} {}".format(str(self.tile), self.name)
