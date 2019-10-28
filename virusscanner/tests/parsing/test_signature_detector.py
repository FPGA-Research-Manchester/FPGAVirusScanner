from unittest import TestCase, mock

from virusscanner.parsing import signature_detector


class TestSignatureDetector(TestCase):
    def setUp(self) -> None:
        open_patcher = mock.patch("virusscanner.parsing.signature_detector.open", new_callable=mock.mock_open())
        self.addCleanup(open_patcher.stop)
        self.mock_output_open = open_patcher.start()

        date_patcher = mock.patch("virusscanner.parsing.signature_detector.datetime")
        self.addCleanup(date_patcher.stop)
        self.mock_date = date_patcher.start()

        getattr_patcher = mock.patch("virusscanner.parsing.signature_detector.getattr")
        self.addCleanup(getattr_patcher.stop)
        self.mock_getattr = getattr_patcher.start()

        importlib_patcher = mock.patch("virusscanner.parsing.signature_detector.importlib")
        self.addCleanup(importlib_patcher.stop)
        self.mock_importlib = importlib_patcher.start()

    def test_parse_input_calls_signature_detector_twice(self):
        mock_input = mock.Mock()
        mock_input.get_virus_signatures.return_value = {"some.Class": 1.0, "some.other.MyClass": 1.0}
        mock_signature = mock.Mock()
        self.mock_getattr.return_value = mock_signature
        mock_signature.return_value.detect_virus.return_value = 0

        signature_detector.SignatureDetector().parse_input(mock_input)

        self.assertEqual(self.mock_importlib.import_module.call_count, 2)
        self.assertEqual(mock_signature.return_value.detect_virus.call_count, 2)

    def test_parse_input_calls_signature_detector_once_(self):
        mock_input = mock.Mock()
        mock_input.get_virus_signatures.return_value = {"some.Class": 1.0}
        mock_signature = mock.Mock()
        self.mock_getattr.return_value = mock_signature
        mock_signature.return_value.detect_virus.return_value = 0

        signature_detector.SignatureDetector().parse_input(mock_input)

        self.mock_importlib.import_module.assert_called_once_with("some")
        mock_signature.return_value.detect_virus.assert_called_once()

    def test_parse_input_writes_output_for_two_signatures(self):
        expected_first_class = "Class"
        expected_second_class = "MyClass"

        mock_input = mock.Mock()
        mock_input.get_virus_signatures.return_value = {"some." + expected_first_class: 1.0,
                                                        "some.other." + expected_second_class: 1.0}
        mock_signature = mock.Mock()
        self.mock_getattr.return_value = mock_signature
        expected_score = 0.0
        mock_signature.return_value.detect_virus.return_value = expected_score

        signature_detector.SignatureDetector().parse_input(mock_input)

        expected_call_list = [mock.call("Output for " + str(mock_input.input_file) + " generated at "
                                        + str(self.mock_date.datetime.now.return_value) + "\n\n"),
                              mock.call(expected_first_class + ": " + str(expected_score) + "\n"),
                              mock.call("Nothing found.\n\n"),
                              mock.call(expected_second_class + ": " + str(expected_score) + "\n"),
                              mock.call("Nothing found.\n\n"),
                              mock.call("Final score: 0.0\n")]

        self.assertEqual(self.mock_output_open.return_value.__enter__.return_value.write.mock_calls, expected_call_list)

        self.assertIn(mock.call("Final score: 0.0\n"),
                      self.mock_output_open.return_value.__enter__.return_value.write.mock_calls, )

    def test_parse_input_outputs_combined_score(self):
        mock_input = mock.Mock()
        mock_input.get_virus_signatures.return_value = {"some.Class": 1.0, "some.other.MyClass": 0.5}
        mock_signature = mock.Mock()
        self.mock_getattr.return_value = mock_signature
        mock_signature.return_value.detect_virus.side_effect = [1.5, 0.6]

        signature_detector.SignatureDetector().parse_input(mock_input)

        self.assertIn(mock.call("Final score: 1.8\n"),
                      self.mock_output_open.return_value.__enter__.return_value.write.mock_calls, )
