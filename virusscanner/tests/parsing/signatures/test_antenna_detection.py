from unittest import TestCase, mock

from virusscanner.parsing.signatures.antenna_detection import AntennaDetector


class TestAntennaDetector(TestCase):
    @mock.patch("virusscanner.parsing.signatures.antenna_detection.GraphProcessor")
    def test_detect_virus_uses_graph_processor_results(self, mock_processor):
        mock_input = mock.Mock()
        detector_under_test = AntennaDetector(mock_input)

        first_port = mock.Mock()
        second_port = mock.Mock()
        third_port = mock.Mock()

        mock_processor.return_value.find_dangling_ports.side_effect = [{first_port, second_port},
                                                                       {second_port, third_port}]
        mock_processor.return_value.find_matching_ports.side_effect = [{second_port, third_port}, set()]

        score = detector_under_test.detect_virus()

        expected_calls = [mock.call(mock.ANY, {first_port}), mock.call(mock.ANY, {second_port, third_port})]
        self.assertEqual(mock_processor.return_value.print_ports.mock_calls, expected_calls)
        self.assertEqual(score, 3)
