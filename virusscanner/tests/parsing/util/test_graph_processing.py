import re
from unittest import TestCase, mock

from virusscanner.interface.datastructures.connection import Connection
from virusscanner.interface.datastructures.port import Port
from virusscanner.interface.datastructures.tile import Tile
from virusscanner.parsing.util.graph_processing import GraphProcessor


class TestGraphProcessor(TestCase):
    def setUp(self) -> None:
        fake_tile = Tile("fake_tile", 0, 0)

        self.first_port = Port(fake_tile, "A")
        self.second_port = Port(fake_tile, "B")
        self.third_port = Port(fake_tile, "C")

    def test_make_adjacency_list_from_graph_returns_adjacency_list_with_begin_ports(self):
        input_graph = [Connection(self.first_port, self.second_port),
                       Connection(self.first_port, self.third_port),
                       Connection(self.second_port, self.third_port)]

        expected_list = {self.first_port: (self.second_port, self.third_port), self.second_port: (self.third_port,)}

        self.assertEqual(GraphProcessor().make_adjacency_list_from_connections_list(input_graph, "begin", "end"),
                         expected_list)

    def test_make_adjacency_list_from_graph_returns_adjacency_list_with_end_ports(self):
        input_graph = [Connection(self.first_port, self.second_port),
                       Connection(self.first_port, self.third_port),
                       Connection(self.second_port, self.third_port)]

        expected_list = {self.second_port: (self.first_port,), self.third_port: (self.first_port, self.second_port)}

        self.assertEqual(GraphProcessor().make_adjacency_list_from_connections_list(input_graph, "end", "begin"),
                         expected_list)

    def test_find_matching_ports_finds_two_matches(self):
        input_regexps = [dict(tile_type=re.compile(r"expected_tile"), tile_x=re.compile(r"1"), tile_y=re.compile(r"2"),
                              port=re.compile(r"expected_port")),
                         dict(tile_type=re.compile(r"another.*"), tile_x=re.compile(r"[0-5]"),
                              tile_y=re.compile(r"[6-9]"), port=re.compile(r"another.*"))]

        first_port = Port(Tile("expected_tile", 1, 2), "expected_port")
        second_port = Port(Tile("another_expected_tile", 3, 7), "another_expected_port")
        third_port = Port(Tile("unexpected_tile", 1, 2), "another_unexpected_port")

        input_graph = [Connection(first_port, second_port),
                       Connection(first_port, third_port),
                       Connection(second_port, third_port)]

        expected_set = {first_port, second_port}

        self.assertEqual(GraphProcessor().find_matching_ports(input_regexps, input_graph, ["end", "begin"]),
                         expected_set)

    def test_find_matching_ports_returns_nothing(self):
        input_regexps = [dict(tile_type=re.compile(r"expected_tile"), tile_x=re.compile(r"1"), tile_y=re.compile(r"2"),
                              port=re.compile(r"expected_port")),
                         dict(tile_type=re.compile(r"another.*"), tile_x=re.compile(r"[0-5]"),
                              tile_y=re.compile(r"[6-9]"), port=re.compile(r"another.*"))]

        first_port = Port(Tile("expected_tile", 1, 2), "expected_port")
        second_port = Port(Tile("another_expected_tile", 3, 7), "another_expected_port")
        third_port = Port(Tile("unexpected_tile", 1, 2), "another_unexpected_port")

        input_graph = [Connection(first_port, third_port),
                       Connection(second_port, third_port)]

        expected_set = set()

        self.assertEqual(GraphProcessor().find_matching_ports(input_regexps, input_graph, ["end"]),
                         expected_set)

    def test_find_all_paths_finds_two_paths_from_same_start(self):
        input_list = {self.first_port: (self.second_port, self.third_port),
                      self.second_port: (self.first_port, self.third_port,)}

        begin_ports = {self.first_port, self.third_port}
        end_ports = {self.second_port, self.third_port, self.first_port}

        expected_paths = [[self.first_port, self.second_port], [self.first_port, self.third_port]]

        self.assertCountEqual(GraphProcessor().find_all_paths(input_list, begin_ports, end_ports), expected_paths)

    def test_find_all_paths_finds_two_paths_from_different_starts(self):
        input_list = {self.first_port: (self.third_port,), self.second_port: (self.third_port,)}

        begin_ports = {self.first_port, self.second_port}
        end_ports = {self.second_port, self.third_port}

        expected_paths = [[self.first_port, self.third_port], [self.second_port, self.third_port]]

        self.assertCountEqual(GraphProcessor().find_all_paths(input_list, begin_ports, end_ports), expected_paths)

    def test_find_all_paths_finds_no_paths(self):
        input_list = {self.first_port: (self.third_port,), self.second_port: (self.third_port,)}

        begin_ports = {self.third_port}
        end_ports = {self.first_port, self.second_port, self.third_port}

        expected_paths = []

        self.assertEqual(GraphProcessor().find_all_paths(input_list, begin_ports, end_ports), expected_paths)

    def test_find_all_paths_calls_depth_first_search_with_routing(self):
        input_list = {self.first_port: (self.third_port,), self.second_port: (self.third_port,)}

        begin_ports = {self.third_port}
        end_ports = {self.first_port, self.second_port, self.third_port}
        routing_ports = {self.first_port, self.second_port}

        with mock.patch.object(GraphProcessor, "depth_first_invalid_path_search_with_routing") as mocked_search:
            GraphProcessor().find_all_paths(input_list, begin_ports, end_ports, routing_ports)
            mocked_search.assert_called_once_with(self.third_port, end_ports, routing_ports, input_list, [], set())

    def test_depth_first_invalid_path_search_with_routing_finds_invalid_path(self):
        resulting_list = []
        input_list = {self.first_port: (self.second_port,), self.second_port: (self.first_port, self.third_port,)}

        end_ports = {self.second_port}
        routing_ports = {self.second_port}

        expected_paths = [[self.first_port, self.second_port, self.third_port]]

        GraphProcessor().depth_first_invalid_path_search_with_routing(self.first_port, end_ports, routing_ports,
                                                                      input_list, resulting_list, set())
        self.assertCountEqual(resulting_list, expected_paths)

    def test_depth_first_invalid_path_search_with_routing_finds_nothing_with_antenna(self):
        resulting_list = []
        input_list = {self.first_port: (self.second_port,), self.second_port: (self.first_port, self.third_port,)}

        end_ports = set()
        routing_ports = {self.second_port, self.third_port}

        expected_paths = []

        GraphProcessor().depth_first_invalid_path_search_with_routing(self.first_port, end_ports, routing_ports,
                                                                      input_list, resulting_list, set())
        self.assertCountEqual(resulting_list, expected_paths)

    def test_depth_first_invalid_path_search_with_routing_skips_visited_ports(self):
        # TODO: finish writing this test!
        self.fail()

    def test_depth_first_search_adds_two_paths_to_results(self):
        mock_port = mock.Mock()

        input_list = {self.first_port: (self.second_port, self.third_port),
                      self.second_port: (self.first_port, self.third_port,)}

        expected_paths = [[mock_port], [self.first_port, self.third_port],
                          [self.first_port, self.second_port, self.third_port]]

        found_paths = [[mock_port]]
        GraphProcessor().depth_first_search(self.first_port, {self.third_port}, input_list, found_paths)

        self.assertCountEqual(found_paths, expected_paths)

    def test_depth_first_search_finds_nothing(self):
        mock_port = mock.Mock()

        input_list = {self.first_port: (self.second_port,), self.second_port: (self.first_port, self.third_port,)}

        expected_paths = [[mock_port]]

        found_paths = [[mock_port]]
        GraphProcessor().depth_first_search(self.third_port, {self.first_port}, input_list, found_paths)

        self.assertEqual(found_paths, expected_paths)

    @mock.patch("virusscanner.parsing.util.graph_processing.print")
    def test_print_paths_prints_message_with_paths(self, mock_print):
        message_string = "fake_message"

        GraphProcessor().print_paths(message_string, [[self.first_port, self.second_port], [self.third_port], []])

        expected_call_list = [mock.call(message_string),
                              mock.call('  ', end=''),
                              mock.call(self.first_port, end=' -> '),
                              mock.call(self.second_port),
                              mock.call('  ', end=''),
                              mock.call(self.third_port)]

        self.assertEqual(mock_print.mock_calls, expected_call_list)

    @mock.patch("virusscanner.parsing.util.graph_processing.print")
    def test_print_paths_does_nothing_with_empty_list(self, mock_print):
        GraphProcessor().print_paths("fake_message", [])

        self.assertEqual(mock_print.mock_calls, [])

    @mock.patch("virusscanner.parsing.util.graph_processing.print")
    def test_print_ports_prints_message_with_ports(self, mock_print):
        message_string = "fake_message"

        GraphProcessor().print_ports(message_string, [self.first_port, self.second_port, self.third_port])

        expected_call_list = [mock.call(message_string),
                              mock.call('  ', self.first_port),
                              mock.call('  ', self.second_port),
                              mock.call('  ', self.third_port)]

        self.assertEqual(mock_print.mock_calls, expected_call_list)

    @mock.patch("virusscanner.parsing.util.graph_processing.print")
    def test_print_ports_does_nothing_with_empty_list(self, mock_print):
        GraphProcessor().print_ports("fake_message", [])

        self.assertEqual(mock_print.mock_calls, [])

    def test_find_dangling_ports_finds_ports(self):
        input_graph = [Connection(self.first_port, self.second_port),
                       Connection(self.first_port, self.third_port),
                       Connection(self.third_port, self.first_port)]

        adjacency_list = {self.first_port: (self.second_port, self.third_port), self.third_port: (self.first_port,)}

        self.assertEqual(GraphProcessor().find_dangling_ports(input_graph, adjacency_list, "end"), {self.second_port})

    def test_find_dangling_ports_finds_no_ports(self):
        input_graph = [Connection(self.first_port, self.second_port),
                       Connection(self.first_port, self.third_port),
                       Connection(self.third_port, self.first_port)]

        adjacency_list = {self.second_port: (self.first_port,), self.third_port: (self.first_port,),
                          self.first_port: (self.third_port,)}

        self.assertEqual(GraphProcessor().find_dangling_ports(input_graph, adjacency_list, "begin"), set())
