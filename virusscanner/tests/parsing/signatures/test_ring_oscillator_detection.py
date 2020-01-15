from unittest import TestCase, mock

from virusscanner.interface.datastructures.connection import Connection
from virusscanner.interface.datastructures.implementation_graph import Graph
from virusscanner.parsing.signatures.ring_oscillator_detection import CombinatorialLoopDetector


class TestCombinatorialLoopDetector(TestCase):
    @mock.patch("virusscanner.parsing.signatures.ring_oscillator_detection.GraphProcessor")
    @mock.patch("virusscanner.parsing.signatures.ring_oscillator_detection.networkx")
    def test_detect_virus_uses_networkx_results(self, mock_networkx, mock_processor):
        mock_input = mock.Mock()
        detector_under_test = CombinatorialLoopDetector(mock_input)
        mock_graph = mock.Mock()
        mock_input.get_connections_graph.return_value = mock_graph
        input_dict = dict()

        first_port = mock.Mock()
        second_port = mock.Mock()
        third_port = mock.Mock()

        connections_list = [Connection(first_port, second_port), Connection(second_port, third_port)]

        mock_graph.get_adjacency_list.return_value = input_dict
        mock_graph.connections = connections_list

        found_cycles = [[first_port, second_port], [second_port, first_port]]
        mock_networkx.simple_cycles.return_value = found_cycles
        score = detector_under_test.detect_virus()

        expected_path_list = [[first_port, second_port, first_port], [second_port, first_port, second_port]]

        mock_processor.return_value.print_paths.assert_called_once_with(mock.ANY, expected_path_list)
        self.assertEqual(score, 2)

    @mock.patch("virusscanner.parsing.signatures.ring_oscillator_detection.GraphProcessor")
    @mock.patch("virusscanner.parsing.signatures.ring_oscillator_detection.networkx")
    def test_detect_virus_skips_printing_without_cycles(self, mock_networkx, mock_processor):
        mock_input = mock.Mock()
        detector_under_test = CombinatorialLoopDetector(mock_input)
        mock_graph = mock.Mock()
        mock_input.get_connections_graph.return_value = mock_graph
        input_dict = dict()

        first_port = mock.Mock()
        second_port = mock.Mock()
        third_port = mock.Mock()

        connections_list = [Connection(first_port, second_port), Connection(second_port, third_port)]

        mock_graph.get_adjacency_list.return_value = input_dict
        mock_graph.connections = connections_list

        found_cycles = []
        mock_networkx.simple_cycles.return_value = found_cycles
        score = detector_under_test.detect_virus()

        mock_processor.return_value.print_paths.assert_not_called()
        self.assertEqual(score, 0)

    @mock.patch("virusscanner.parsing.signatures.ring_oscillator_detection.networkx")
    def test_detect_skips_ignored_attributes(self, mock_networkx):
        mock_input = mock.Mock()
        detector_under_test = CombinatorialLoopDetector(mock_input)
        mock_graph = mock.Mock()
        mock_input.get_connections_graph.return_value = mock_graph

        ignored_attribute = "fake"
        mock_input.get_ignored_loop_attributes_list.return_value = [ignored_attribute]

        first_port = mock.Mock()
        second_port = mock.Mock()
        third_port = mock.Mock()

        connections_list = [Connection(first_port, second_port, {ignored_attribute}),
                            Connection(second_port, third_port)]

        input_dict = {
            first_port: (second_port,),
            second_port: (third_port,)
        }
        mock_graph.get_adjacency_list.return_value = input_dict
        mock_graph.connections = connections_list

        detector_under_test.detect_virus()

        mock_networkx.DiGraph.assert_called_once_with({second_port: (third_port,)})

    @mock.patch("virusscanner.parsing.signatures.ring_oscillator_detection.networkx")
    def test_detect_does_preserve_other_end_ports(self, mock_networkx):
        mock_input = mock.Mock()
        detector_under_test = CombinatorialLoopDetector(mock_input)

        ignored_attribute = "fake"
        mock_input.get_ignored_loop_attributes_list.return_value = [ignored_attribute]

        first_port = mock.Mock()
        second_port = mock.Mock()
        third_port = mock.Mock()
        fourth_port = mock.Mock()

        connections_list = [Connection(first_port, second_port),
                            Connection(second_port, third_port),
                            Connection(third_port, fourth_port, {ignored_attribute}),
                            Connection(third_port, first_port)]

        expected_adjacency_list = {
            first_port: (second_port,),
            second_port: (third_port,),
            third_port: (first_port,)
        }

        input_graph = Graph(connections=connections_list)
        mock_input.get_connections_graph.return_value = input_graph

        detector_under_test.detect_virus()

        mock_networkx.DiGraph.assert_called_once_with(expected_adjacency_list)
