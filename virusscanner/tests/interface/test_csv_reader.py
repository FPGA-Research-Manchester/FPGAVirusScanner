import re
from unittest import TestCase, mock

from virusscanner.interface.csv_reader import CSVInput


class TestCSVInput(TestCase):
    def test_get_regexps_list_from_file_finds_regex(self):
        regex_key = "fake"
        another_regex_key = "another_fake"
        expected_string = "some_name"
        another_expected_string = "other_name"
        read_data = regex_key + "," + another_regex_key + "\n" + expected_string + "," + another_expected_string
        with mock.patch("virusscanner.interface.csv_reader.open", mock.mock_open(read_data=read_data)):
            test_csv_reader = CSVInput()
            test_csv_reader.REGEX_KEY_SET = (regex_key, another_regex_key)
            self.assertEqual(test_csv_reader.get_regexps_list_from_file("some_file"),
                             [{regex_key: re.compile(r"{}".format(expected_string)),
                               another_regex_key: re.compile(r"{}".format(another_expected_string))}])

    def test_get_regexps_list_from_file_finds_strings(self):
        regex_key = "fake"
        non_regex_key = "another_fake"
        expected_string = "some_name"
        another_expected_string = "other_name"
        read_data = non_regex_key + "\n" + expected_string + "\n" + another_expected_string
        with mock.patch("virusscanner.interface.csv_reader.open", mock.mock_open(read_data=read_data)):
            test_csv_reader = CSVInput()
            test_csv_reader.REGEX_KEY_SET = (regex_key,)
            self.assertEqual(test_csv_reader.get_regexps_list_from_file("some_file"),
                             [{non_regex_key: expected_string}, {non_regex_key: another_expected_string}])

    def test_get_regexps_list_from_file_skips_empty_fields(self):
        regex_key = "fake"
        non_regex_key = "another_fake"
        read_data = regex_key + "," + non_regex_key + "\n"
        with mock.patch("virusscanner.interface.csv_reader.open", mock.mock_open(read_data=read_data)):
            test_csv_reader = CSVInput()
            test_csv_reader.REGEX_KEY_SET = (regex_key,)
            self.assertEqual(test_csv_reader.get_regexps_list_from_file("some_file"), [])
