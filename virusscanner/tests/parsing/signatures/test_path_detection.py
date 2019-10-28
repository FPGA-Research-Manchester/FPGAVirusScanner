from unittest import TestCase, mock

from virusscanner.parsing.signatures.path_detection import PathDetector


class TestPathDetector(TestCase):
    @mock.patch("virusscanner.parsing.signatures.path_detection.GraphProcessor")
    def test_detect_virus_uses_graph_processor_results(self, mock_processor):
        mock_input = mock.Mock()
        detector_under_test = PathDetector(mock_input)
        mock_processor.return_value.find_all_paths.return_value = [[mock.Mock], [mock.Mock]]
        score = detector_under_test.detect_virus()

        mock_processor.return_value.print_paths.assert_called_once_with(
            mock.ANY, mock_processor.return_value.find_all_paths.return_value)
        self.assertEqual(score, 2)

    @mock.patch("virusscanner.parsing.signatures.path_detection.GraphProcessor")
    def test_detect_virus_skips_printing_without_ports(self, mock_processor):
        mock_input = mock.Mock()
        detector_under_test = PathDetector(mock_input)

        mock_processor.return_value.find_matching_ports.return_value = set()
        score = detector_under_test.detect_virus()

        mock_processor.return_value.print_paths.assert_not_called()
        mock_processor.return_value.find_all_paths.assert_not_called()
        self.assertEqual(score, 0)
