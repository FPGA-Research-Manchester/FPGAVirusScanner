from dataclasses import dataclass


@dataclass(frozen=True)
class Tile:
    name: str
    x: int
    y: int
