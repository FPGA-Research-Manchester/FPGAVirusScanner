from unittest import TestCase

from virusscanner.interface.datastructures.tile import Tile


class TestTile(TestCase):
    def test_tile_str_is_correct(self):
        tile_x = 2
        tile_y = 1
        tile_name = "fake_port"
        tile_under_test = Tile(tile_name, tile_x, tile_y)
        self.assertEqual(str(tile_under_test), tile_name + "_X" + str(tile_x) + "Y" + str(tile_y))

    def test_make_tile_from_string_makes_correct_string(self):
        tile_x = 2
        tile_y = 1
        tile_name = "fake_port"
        tile_under_test = Tile.make_tile_from_string(tile_name + "_X" + str(tile_x) + "Y" + str(tile_y))
        self.assertEqual(tile_under_test.name, tile_name)
        self.assertEqual(tile_under_test.x, tile_x)
        self.assertEqual(tile_under_test.y, tile_y)
