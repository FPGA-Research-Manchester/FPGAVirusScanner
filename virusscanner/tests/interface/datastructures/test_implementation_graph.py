from unittest import TestCase, mock

from virusscanner.interface.datastructures.connection import Connection
from virusscanner.interface.datastructures.implementation_graph import Graph
from virusscanner.interface.datastructures.port import Port
from virusscanner.interface.datastructures.tile import Tile


class TestGraph(TestCase):
    def setUp(self) -> None:
        self.first_port = Port(Tile("fake_tile", 0, 1), "fake_name")
        self.second_port = Port(Tile("another_tile", 1, 0), "another_name")
        self.initial_connection = Connection(self.first_port, self.second_port, {"FAKE_ATTRIBUTE"})
        self.initial_lut_values = {"fake_tile": {"fake_lut": "11"}}
        self.graph_under_test = Graph(connections=[self.initial_connection], lut_values=self.initial_lut_values)

    def test_add_connection_adds_connection(self):
        new_connection = mock.Mock()
        self.graph_under_test.add_connection(new_connection)
        self.assertEqual(self.graph_under_test.connections, [self.initial_connection, new_connection])

    def test_remove_connection_removes_connection(self):
        self.graph_under_test.remove_connection(self.initial_connection)
        self.assertEqual(self.graph_under_test.connections, [])

    def test_add_connection_update_visible_in_adjacency_list(self):
        initial_adjacency_list = self.graph_under_test.get_adjacency_list()
        initial_reverse_adjacency_list = self.graph_under_test.get_adjacency_list(True)

        third_port = mock.Mock()
        new_connection = Connection(self.first_port, third_port)

        expected_adjacency_list = {self.first_port: (self.second_port, third_port)}
        expected_reverse_adjacency_list = {self.second_port: (self.first_port,), third_port: (self.first_port,)}

        self.graph_under_test.add_connection(new_connection)

        self.assertEqual(self.graph_under_test.get_adjacency_list(), expected_adjacency_list)
        self.assertEqual(self.graph_under_test.get_adjacency_list(True), expected_reverse_adjacency_list)
        self.assertNotEqual(self.graph_under_test.get_adjacency_list(), initial_adjacency_list)
        self.assertNotEqual(self.graph_under_test.get_adjacency_list(True), initial_reverse_adjacency_list)

    def test_remove_connection_update_visible_in_adjacency_list(self):
        initial_adjacency_list = self.graph_under_test.get_adjacency_list()
        initial_reverse_adjacency_list = self.graph_under_test.get_adjacency_list(True)

        third_port = mock.Mock()
        new_connection = Connection(self.first_port, third_port)

        expected_adjacency_list = {self.first_port: (third_port, )}
        expected_reverse_adjacency_list = {third_port: (self.first_port,)}

        self.graph_under_test.add_connection(new_connection)
        self.graph_under_test.remove_connection(self.initial_connection)

        self.assertEqual(self.graph_under_test.get_adjacency_list(), expected_adjacency_list)
        self.assertEqual(self.graph_under_test.get_adjacency_list(True), expected_reverse_adjacency_list)
        self.assertNotEqual(self.graph_under_test.get_adjacency_list(), initial_adjacency_list)
        self.assertNotEqual(self.graph_under_test.get_adjacency_list(True), initial_reverse_adjacency_list)
