from virusscanner.interface.datastructures.tile import Tile
from dataclasses import dataclass


@dataclass(frozen=True)
class Port:
    tile: Tile
    name: str

    # TODO: Use Tile __str__ method
    def __str__(self) -> str:
        return "{}_X{}Y{} {}".format(self.tile.name, self.tile.x, self.tile.y, self.name)
