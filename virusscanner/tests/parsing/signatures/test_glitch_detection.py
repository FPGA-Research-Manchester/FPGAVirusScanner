from unittest import TestCase, mock

from virusscanner.parsing.signatures.glitch_detection import GlitchyPathsDetector


class TestGlitchyPathsDetector(TestCase):
    @mock.patch("virusscanner.parsing.signatures.glitch_detection.GraphProcessor")
    def test_detector_skips_finding_paths_without_ports(self, mock_processor):
        mock_input = mock.Mock()
        detector_under_test = GlitchyPathsDetector(mock_input)
        mock_processor.return_value.find_matching_ports.side_effect = [[mock.Mock()], []]

        score = detector_under_test.detect_virus()

        mock_processor.return_value.print_ports.assert_not_called()
        mock_processor.return_value.find_all_paths.assert_not_called()
        self.assertEqual(score, 0)

    @mock.patch("virusscanner.parsing.signatures.glitch_detection.GraphProcessor")
    def test_detector_skips_calculating_scores_with_no_paths(self, mock_processor):
        mock_input = mock.Mock()
        detector_under_test = GlitchyPathsDetector(mock_input)
        mock_processor.return_value.find_matching_ports.return_value = [mock.Mock()]
        mock_processor.return_value.find_all_paths.return_value = []

        score = detector_under_test.detect_virus()

        mock_processor.return_value.print_ports.assert_not_called()
        mock_processor.return_value.is_connection_in_lut_tile.assert_not_called()
        self.assertEqual(score, 0)

    @mock.patch("virusscanner.parsing.signatures.glitch_detection.GraphProcessor")
    @mock.patch("virusscanner.parsing.signatures.glitch_detection.GlitchScoreCalculator")
    def test_detector_skips_calculating_scores_with_no_matching_tiles(self, mock_score_calculator, mock_processor):
        mock_input = mock.Mock()

        mock_input.get_connections_graph.return_value = mock.Mock()
        mock_input.get_glitch_score_threshold.return_value = 1
        detector_under_test = GlitchyPathsDetector(mock_input)

        found_path = [mock.Mock(), mock.Mock()]
        mock_processor.return_value.find_matching_ports.return_value = [mock.Mock()]
        mock_processor.return_value.find_all_paths.return_value = [found_path]
        mock_processor.return_value.is_connection_in_lut_tile.return_value = False

        score = detector_under_test.detect_virus()

        mock_processor.return_value.print_ports.assert_not_called()
        mock_processor.return_value.get_lut_value.assert_not_called()
        mock_score_calculator.return_value.calculate_lut_glitch_score.assert_not_called()
        self.assertEqual(score, 0)

    @mock.patch("virusscanner.parsing.signatures.glitch_detection.GraphProcessor")
    @mock.patch("virusscanner.parsing.signatures.glitch_detection.GlitchScoreCalculator")
    def test_detector_skips_calculating_scores_with_lut_values_tiles(self, mock_score_calculator, mock_processor):
        mock_input = mock.Mock()
        mock_graph = mock.Mock()

        mock_input.get_connections_graph.return_value = mock_graph
        mock_input.get_glitch_score_threshold.return_value = 1
        detector_under_test = GlitchyPathsDetector(mock_input)

        first_port = mock.Mock()
        second_port = mock.Mock()
        found_path = [first_port, second_port]
        mock_processor.return_value.find_matching_ports.return_value = [mock.Mock()]
        mock_processor.return_value.find_all_paths.return_value = [found_path]
        mock_processor.return_value.is_connection_in_lut_tile.return_value = True
        mock_processor.return_value.get_lut_value.return_value = None

        score = detector_under_test.detect_virus()

        mock_processor.return_value.print_ports.assert_not_called()
        mock_processor.return_value.get_lut_value.assert_called_once_with(second_port, mock_graph.lut_values)
        mock_score_calculator.return_value.calculate_lut_glitch_score.assert_not_called()
        self.assertEqual(score, 0)

    @mock.patch("virusscanner.parsing.signatures.glitch_detection.GraphProcessor")
    @mock.patch("virusscanner.parsing.signatures.glitch_detection.GlitchScoreCalculator")
    def test_detector_returns_highest_score_given_to_path(self, mock_score_calculator, mock_processor):
        first_lut_score = 1000
        second_lut_score = 501
        third_lut_score = 500

        mock_input = mock.Mock()
        mock_graph = mock.Mock()

        mock_input.get_connections_graph.return_value = mock_graph
        mock_input.get_glitch_score_threshold.return_value = None
        detector_under_test = GlitchyPathsDetector(mock_input)

        first_path = [mock.Mock(), mock.Mock(), mock.Mock()]
        second_path = [mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock()]
        mock_processor.return_value.find_matching_ports.return_value = [mock.Mock()]
        mock_processor.return_value.find_all_paths.return_value = [first_path, second_path]
        mock_processor.return_value.is_connection_in_lut_tile.side_effect = [True, True, True, False, True]
        mock_processor.return_value.get_lut_value.side_effect = ["01", "01", "10", "11"]

        mock_score_calculator.return_value.calculate_lut_glitch_score.side_effect = [first_lut_score, first_lut_score,
                                                                                     second_lut_score, third_lut_score]

        score = detector_under_test.detect_virus()

        self.assertEqual(mock_processor.return_value.print_ports.call_count, 1)
        self.assertEqual(mock_score_calculator.return_value.calculate_lut_glitch_score.call_count, 3)
        self.assertEqual(score, first_lut_score * 2)

    @mock.patch("virusscanner.parsing.signatures.glitch_detection.GraphProcessor")
    @mock.patch("virusscanner.parsing.signatures.glitch_detection.GlitchScoreCalculator")
    def test_detect_virus_returns_correct_score(self, mock_score_calculator, mock_processor):
        first_lut_score = 1000
        second_lut_score = 501
        third_lut_score = 500

        mock_input = mock.Mock()
        mock_graph = mock.Mock()

        mock_input.get_connections_graph.return_value = mock_graph
        mock_input.get_glitch_score_threshold.return_value = 1000
        detector_under_test = GlitchyPathsDetector(mock_input)

        first_path = [mock.Mock(), mock.Mock(), mock.Mock()]
        second_path = [mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock()]
        third_path = [mock.Mock(), mock.Mock()]
        mock_processor.return_value.find_matching_ports.return_value = [mock.Mock()]
        mock_processor.return_value.find_all_paths.return_value = [first_path, second_path, third_path]
        mock_processor.return_value.is_connection_in_lut_tile.side_effect = [True, True, True, False, True, True]
        mock_processor.return_value.get_lut_value.side_effect = ["01", "01", "10", "11", "01"]

        mock_score_calculator.return_value.calculate_lut_glitch_score.side_effect = [first_lut_score, second_lut_score,
                                                                                     third_lut_score]

        score = detector_under_test.detect_virus()

        self.assertEqual(mock_processor.return_value.print_ports.call_count, 2)
        self.assertEqual(mock_score_calculator.return_value.calculate_lut_glitch_score.call_count, 3)
        self.assertEqual(score, 2)
