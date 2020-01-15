from unittest import TestCase, mock

from virusscanner.parsing.signatures.fan_out_detection import FanOutDetector


class TestFanOutDetector(TestCase):
    @mock.patch("virusscanner.parsing.signatures.fan_out_detection.GraphProcessor")
    def test_detect_virus_skips_finding_paths_with_no_ports(self, mock_processor):
        detector_under_test = FanOutDetector(mock.Mock())
        mock_processor.return_value.find_matching_ports.return_value = set()

        score = detector_under_test.detect_virus()
        self.assertEqual(mock_processor.return_value.find_matching_ports.call_count, 2)
        self.assertEqual(score, 0)

    @mock.patch("virusscanner.parsing.signatures.fan_out_detection.GraphProcessor")
    def test_detect_virus_finds_two_ports_with_too_high_fan_out(self, mock_processor):
        first_begin_port = mock.Mock()
        second_begin_port = mock.Mock()
        third_begin_port = mock.Mock()
        mock_input = mock.Mock()

        mock_input.get_fan_out_threshold.return_value = 1

        detector_under_test = FanOutDetector(mock_input)
        mock_processor.return_value.find_matching_ports.return_value = mock.Mock()
        mock_processor.return_value.find_all_paths.return_value = [[first_begin_port, mock.Mock()],
                                                                   [first_begin_port, mock.Mock()],
                                                                   [second_begin_port, mock.Mock()],
                                                                   [second_begin_port, mock.Mock()],
                                                                   [third_begin_port, mock.Mock(), mock.Mock()]]

        score = detector_under_test.detect_virus()
        self.assertEqual(score, 2)

    @mock.patch("virusscanner.parsing.signatures.fan_out_detection.GraphProcessor")
    def test_detect_virus_returns_the_score_of_the_highest_fan_out(self, mock_processor):
        first_begin_port = mock.Mock()
        second_begin_port = mock.Mock()
        third_begin_port = mock.Mock()
        mock_input = mock.Mock()

        mock_input.get_fan_out_threshold.return_value = None

        detector_under_test = FanOutDetector(mock_input)
        mock_processor.return_value.find_matching_ports.return_value = mock.Mock()
        mock_processor.return_value.find_all_paths.return_value = [[first_begin_port, mock.Mock()],
                                                                   [first_begin_port, mock.Mock()],
                                                                   [second_begin_port, mock.Mock()],
                                                                   [second_begin_port, mock.Mock()],
                                                                   [second_begin_port, mock.Mock()],
                                                                   [third_begin_port, mock.Mock(), mock.Mock()]]

        score = detector_under_test.detect_virus()
        self.assertEqual(score, 3)
