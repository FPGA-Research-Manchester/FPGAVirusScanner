from unittest import TestCase, mock

from virusscanner.interface.datastructures.implementation_graph import Graph

from virusscanner.interface.datastructures.connection import Connection
from virusscanner.interface.datastructures.dataclassesjson import DataClassesJSONEncoder
from virusscanner.interface.datastructures.port import Port
from virusscanner.interface.datastructures.tile import Tile
from virusscanner.interface.json_graph_parser import GraphCreator


class TestGraphCreator(TestCase):

    @mock.patch("virusscanner.interface.json_graph_parser.open", new_callable=mock.mock_open())
    @mock.patch("virusscanner.interface.json_graph_parser.json")
    def test_get_connections_from_json_returns_correct_data(self, mock_json, mock_open):
        expected_attributes = ["FAKE_ATTRIBUTE1", "FAKE_ATTRIBUTE2"]

        input_connections = [
            dict(begin=dict(tile=dict(name="INT", x=1, y=0), name="FAKE_PORT"),
                 end=dict(tile=dict(name="INT", x=0, y=0), name="FAKE_PORT1")),
            dict(begin=dict(tile=dict(name="CLEM", x=2, y=50), name="FAKE_PORT2"),
                 end=dict(tile=dict(name="INT", x=3, y=3), name="FAKE_PORT3"), attributes=expected_attributes)]
        expected_connections = [
            Connection(Port(Tile("INT", 1, 0), "FAKE_PORT"), Port(Tile("INT", 0, 0), "FAKE_PORT1")),
            Connection(Port(Tile("CLEM", 2, 50), "FAKE_PORT2"), Port(Tile("INT", 3, 3), "FAKE_PORT3"),
                       set(expected_attributes))]

        mock_json.load.return_value = dict(CONNECTIONS=input_connections)
        self.assertEqual(GraphCreator().get_connections_from_json("some_file"), Graph(connections=expected_connections))
        mock_open.return_value.__enter__.assert_called_once()

    @mock.patch("virusscanner.interface.json_graph_parser.open", new_callable=mock.mock_open())
    @mock.patch("virusscanner.interface.json_graph_parser.json")
    def test_output_graph_outputs_json(self, mock_json, mock_open):
        expected_graph = [mock.Mock()]
        GraphCreator().output_graph(Graph(connections=expected_graph), "some_file")
        mock_json.dump.assert_called_once_with(expected_graph, mock_open.return_value.__enter__.return_value,
                                               cls=DataClassesJSONEncoder)
