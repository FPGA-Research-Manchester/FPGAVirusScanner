from unittest import TestCase, mock

from virusscanner.interface.signature_options import SignatureOptions, SignatureOption


class TestSignatureOptions(TestCase):

    @mock.patch("virusscanner.interface.signature_options.CSVInput")
    def test_set_virus_signature_option_inputs_uses_csv_inputs(self, mock_csv_reader):
        expected_first_key = "a"
        expected_second_key = "b"
        expected_third_key = "c"

        expected_first_section = "fake_section"
        expected_second_section = "another_fake_section"

        expected_first_option = "option_a"
        expected_second_option = "option_b"
        expected_third_option = "option_c"

        first_signature = "A"
        second_signature = "B"
        third_signature = "C"

        signature_options_dict = {
            first_signature: [],
            second_signature: [
                SignatureOption(expected_first_key, expected_first_section, expected_first_option,
                                SignatureOptions._CSV_TYPE)],
            third_signature: [
                SignatureOption(expected_second_key, expected_second_section, expected_second_option,
                                SignatureOptions._CSV_TYPE),
                SignatureOption(expected_third_key, expected_second_section, expected_third_option,
                                SignatureOptions._CSV_TYPE)],
        }

        first_option_input = "fake1"
        second_option_input = "fake2"
        third_option_input = "fake3"

        mock_config_parser = mock.Mock()

        option_inputs = {(expected_first_section, expected_first_option): first_option_input,
                         (expected_second_section, expected_second_option): second_option_input,
                         (expected_second_section, expected_third_option): third_option_input}
        mock_config_parser.get.side_effect = lambda section, option: option_inputs.get(
            (section, option), "")

        expected_config_calls = [mock.call(expected_first_section, expected_first_option),
                                 mock.call(expected_second_section, expected_second_option),
                                 mock.call(expected_second_section, expected_third_option)]
        expected_reader_calls = [mock.call(first_option_input), mock.call(second_option_input),
                                 mock.call(third_option_input)]

        first_option_value = "fake_value1"
        second_option_value = "fake_value2"
        third_option_value = "fake_value3"

        file_contents = {first_option_input: first_option_value, second_option_input: second_option_value,
                         third_option_input: third_option_value}

        mock_csv_reader.return_value.get_regexps_list_from_file.side_effect = lambda file_name: file_contents.get(
            file_name, "")

        result_dict = dict()
        expected_result_dict = {expected_first_key: first_option_value, expected_second_key: second_option_value,
                                expected_third_key: third_option_value}

        with mock.patch.object(SignatureOptions, "_signature_options_dict", signature_options_dict):
            SignatureOptions().set_virus_signature_option_inputs({first_signature, second_signature, third_signature},
                                                                 result_dict, mock_config_parser)

        self.assertCountEqual(mock_config_parser.get.mock_calls, expected_config_calls)
        self.assertCountEqual(mock_csv_reader.return_value.get_regexps_list_from_file.mock_calls, expected_reader_calls)
        self.assertEqual(result_dict, expected_result_dict)

    @mock.patch("virusscanner.interface.signature_options.CSVInput")
    def test_set_virus_signature_option_inputs_uses_txt_inputs(self, mock_csv_reader):
        expected_key = "fake_key"
        expected_section = "fake_section"
        expected_option = "fake_option"
        input_signature = "fake_signature"

        signature_options_dict = {
            input_signature: [
                SignatureOption(expected_key, expected_section, expected_option,
                                SignatureOptions._TXT_TYPE)]
        }

        first_entry = "A"
        second_entry = "B"

        mock_config_parser = mock.Mock()
        result_dict = dict()

        with mock.patch.object(SignatureOptions, "_signature_options_dict", signature_options_dict):
            with mock.patch("virusscanner.interface.signature_options.open",
                            mock.mock_open(read_data=first_entry + "\n" + second_entry)):
                SignatureOptions().set_virus_signature_option_inputs({input_signature},
                                                                     result_dict, mock_config_parser)

        mock_config_parser.get.assert_called_once_with(expected_section, expected_option)
        mock_csv_reader.return_value.get_regexps_list_from_file.assert_not_called()
        self.assertEqual(result_dict, {expected_key: [first_entry, second_entry]})
