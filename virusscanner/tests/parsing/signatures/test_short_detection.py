from unittest import TestCase, mock

from virusscanner.parsing.signatures.short_detection import ShortCircuitDetector


class TestShortCircuitDetector(TestCase):
    @mock.patch("virusscanner.parsing.signatures.short_detection.GraphProcessor")
    def test_detect_virus_uses_graph_processor_results(self, mock_processor):
        mock_input = mock.Mock()
        detector_under_test = ShortCircuitDetector(mock_input)

        first_port = mock.Mock()
        second_port = mock.Mock()
        third_port = mock.Mock()

        adjacency_list = {first_port: (second_port,), second_port: (first_port, third_port),
                          third_port: (first_port, second_port)}
        shorting_ports = {second_port}

        mock_processor.return_value.find_matching_ports.return_value = shorting_ports
        mock_input.get_connections_graph.return_value.get_adjacency_list.return_value = adjacency_list

        score = detector_under_test.detect_virus()

        mock_processor.return_value.find_matching_ports.assert_called_once_with(
            mock_input.get_short_locations_list.return_value, mock_input.get_connections_graph.return_value.connections,
            ["end"])
        mock_processor.return_value.print_ports.assert_called_once_with(mock.ANY, (first_port, third_port))
        self.assertEqual(score, 1)
