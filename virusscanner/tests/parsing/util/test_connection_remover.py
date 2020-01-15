from unittest import TestCase, mock

from virusscanner.interface.datastructures.connection import Connection
from virusscanner.interface.datastructures.implementation_graph import Graph
from virusscanner.interface.datastructures.port import Port
from virusscanner.interface.datastructures.tile import Tile
from virusscanner.parsing.util.connections_remover import ConnectionRemover


class TestConnectionRemover(TestCase):
    def test_remove_connections(self):
        first_port = Port(Tile("fake1", 1, 1), "fake1")
        second_port = Port(Tile("fake2", 1, 1), "fake2")
        third_port = Port(Tile("fake3", 1, 1), "fake3")

        first_connection = Connection(first_port, second_port)
        second_connection = Connection(first_port, third_port, {"fake_attribute"})
        third_connection = Connection(second_port, third_port)
        fourth_connection = Connection(second_port, first_port)

        input_graph = Graph(connections=[first_connection, second_connection, third_connection, fourth_connection])
        input_data = str(first_connection) + "\nfake_string\n\n    " + str(second_connection)
        with mock.patch("virusscanner.parsing.util.connections_remover.open", mock.mock_open(read_data=input_data)):
            ConnectionRemover.remove_connections("fake_file", input_graph)
            self.assertEqual(input_graph.connections, [third_connection, fourth_connection])
