from unittest import TestCase, mock

from virusscanner.parsing.signatures.unspecified_path_detection import UnspecifiedPathDetector


class TestUnspecifiedPathDetector(TestCase):
    @mock.patch("virusscanner.parsing.signatures.unspecified_path_detection.GraphProcessor")
    def test_detect_virus_uses_graph_processor_results(self, mock_processor):
        mock_input = mock.Mock()
        detector_under_test = UnspecifiedPathDetector(mock_input)

        first_port = mock.Mock()
        second_port = mock.Mock()
        routing_port = mock.Mock()

        mock_processor.return_value.find_matching_ports.side_effect = [{first_port}, {second_port}, {routing_port}]

        reverse_adjacency_list = mock.Mock()

        mock_input.get_connections_graph.return_value.get_adjacency_list.side_effect = [reverse_adjacency_list]

        reverse_result = [[first_port, second_port], [second_port, routing_port]]
        reverse_expected_result = [[second_port, first_port], [routing_port, second_port]]
        mock_processor.return_value.find_all_paths.side_effect = [reverse_result]

        score = detector_under_test.detect_virus()

        expected_find_calls = [mock.call(reverse_adjacency_list, {second_port}, {first_port}, {routing_port})]
        self.assertEqual(mock_processor.return_value.find_all_paths.mock_calls, expected_find_calls)
        expected_print_calls = [mock.call(mock.ANY, reverse_expected_result)]
        self.assertEqual(mock_processor.return_value.print_paths.mock_calls, expected_print_calls)
        self.assertEqual(score, 2)

    @mock.patch("virusscanner.parsing.signatures.unspecified_path_detection.GraphProcessor")
    def test_detect_virus_skips_finding_routing_without_found_ports(self, mock_processor):
        detector_under_test = UnspecifiedPathDetector(mock.Mock())
        mock_processor.return_value.find_matching_ports.return_value = set()

        score = detector_under_test.detect_virus()
        mock_processor.return_value.print_paths.assert_not_called()
        self.assertEqual(mock_processor.return_value.find_matching_ports.call_count, 2)
        self.assertEqual(score, 0)

    @mock.patch("virusscanner.parsing.signatures.unspecified_path_detection.GraphProcessor")
    def test_detect_virus_skips_finding_paths_without_found_routing(self, mock_processor):
        detector_under_test = UnspecifiedPathDetector(mock.Mock())
        mock_processor.return_value.find_matching_ports.side_effect = [{mock.Mock}, set(), set()]

        detector_under_test.detect_virus()
        mock_processor.return_value.print_paths.assert_not_called()
        self.assertEqual(mock_processor.return_value.find_matching_ports.call_count, 3)
