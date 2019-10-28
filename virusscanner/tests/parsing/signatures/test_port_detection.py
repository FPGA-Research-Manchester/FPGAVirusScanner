from unittest import TestCase, mock

from virusscanner.parsing.signatures.node_detection import PortDetector


class TestPortDetector(TestCase):
    @mock.patch("virusscanner.parsing.signatures.node_detection.GraphProcessor")
    def test_detect_virus_uses_graph_processor_results(self, mock_processor):
        mock_input = mock.Mock()
        detector_under_test = PortDetector(mock_input)
        mock_processor.return_value.find_matching_ports.return_value = [mock.Mock(), mock.Mock()]

        score = detector_under_test.detect_virus()

        mock_processor.return_value.find_matching_ports.assert_called_once_with(
            mock_input.get_disallowed_port_list.return_value, mock_input.get_connections_graph.return_value.connections,
            ["begin", "end"])
        mock_processor.return_value.print_ports.assert_called_once_with(
            mock.ANY, mock_processor.return_value.find_matching_ports.return_value)
        self.assertEqual(score, 2)
