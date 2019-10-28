import re
from unittest import TestCase, mock

from virusscanner.interface.datastructures.implementation_graph import Graph

from virusscanner.interface.datastructures.connection import Connection

from virusscanner.interface.datastructures.port import Port
from virusscanner.interface.datastructures.tile import Tile
from virusscanner.parsing.util.attributes_adder import AttributesAdder


class TestAttributesAdder(TestCase):
    @mock.patch("virusscanner.parsing.util.attributes_adder.CSVInput")
    def test_add_attributes_to_connections_adds_one_attribute(self, mock_csv_reader):
        any_match = re.compile(r".*")
        expected_match_string = "B"
        unexpected_match = re.compile(r"A")
        expected_attribute = "C"
        unexpected_attribute = "D"
        unexpected_connection_entry = "E"
        existing_attribute = "F"

        mock_csv_reader.return_value.get_regexps_list_from_file.return_value = [
            {"begin_tile_type": any_match, "begin_tile_x": any_match, "begin_tile_y": any_match,
             "begin_port": any_match, "end_tile_type": any_match, "end_tile_x": any_match,
             "end_tile_y": any_match, "end_port": re.compile(r"{}".format(expected_match_string)),
             "attribute_name": expected_attribute},
            {"begin_tile_type": unexpected_match, "begin_tile_x": any_match, "begin_tile_y": any_match,
             "begin_port": any_match, "end_tile_type": any_match, "end_tile_x": any_match,
             "end_tile_y": any_match, "end_port": any_match,
             "attribute_name": unexpected_attribute}
        ]

        any_int = 0

        matching_connection = Connection(Port(Tile(expected_match_string, any_int, any_int), expected_match_string),
                                         Port(Tile(expected_match_string, any_int, any_int), expected_match_string))
        other_connection = Connection(Port(Tile(expected_match_string, any_int, any_int), expected_match_string),
                                      Port(Tile(expected_match_string, any_int, any_int), unexpected_connection_entry),
                                      attributes=set(existing_attribute))

        input_connections = [matching_connection, other_connection]

        AttributesAdder().add_attributes_to_connections("fake_file", Graph(connections=input_connections))

        self.assertEqual(matching_connection.attributes, set(expected_attribute))
        self.assertEqual(other_connection.attributes, set(existing_attribute))
