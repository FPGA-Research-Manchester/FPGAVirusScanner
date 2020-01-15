import re
from dataclasses import dataclass
from typing import Pattern, ClassVar


@dataclass(frozen=True)
class Tile:
    __tile_format: ClassVar[Pattern] = re.compile(
        r"(?P<tile_name>.*)_X(?P<tile_x>\d+)Y(?P<tile_y>\d+)")

    name: str
    x: int
    y: int

    def __str__(self) -> str:
        return "{}_X{}Y{}".format(self.name, self.x, self.y)

    @classmethod
    def make_tile_from_string(cls, str_input: str):
        given_tile = cls.__tile_format.search(str_input)
        if given_tile:
            return Tile(given_tile["tile_name"], int(given_tile["tile_x"]), int(given_tile["tile_y"]))
        else:
            ValueError("Incorrect tile string value given: " + str_input)
