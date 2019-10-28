from configparser import ConfigParser
from typing import Set, Pattern, Union, Dict, List, NamedTuple

from virusscanner.interface.csv_reader import CSVInput


class SignatureOption(NamedTuple):
    """Class to define an option in the config for a signature."""
    list_key: str
    section: str
    option: str
    type: str


class SignatureOptions:
    """Class to help parse the signature options given in the config."""
    FAN_OUT_BEGIN_OPTION = "fan_out_begin"
    FAN_OUT_END_OPTION = "fan_out_end"
    DISALLOWED_PORT_OPTION = "disallowed_port"
    DISALLOWED_PATH_BEGIN_OPTION = "disallowed_begin_port"
    DISALLOWED_PATH_END_OPTION = "disallowed_end_port"
    ALLOWED_INPUT_ANTENNA_OPTION = "allowed_input_antenna"
    ALLOWED_OUTPUT_ANTENNA_OPTION = "allowed_output_antenna"
    SHORT_LOCATIONS_OPTION = "short_locations"
    SPECIFIED_PATH_BEGIN_OPTION = "specified_path_begin"
    SPECIFIED_PATH_END_OPTION = "specified_path_end"
    SPECIFIED_PATH_ROUTING_OPTION = "specified_path_routing"
    IGNORED_LOOP_ATTRIBUTES_OPTION = "ignored_loop_attributes"

    _CSV_TYPE = "csv"
    _TXT_TYPE = "txt"

    _signature_options_dict = \
        {
            'virusscanner.parsing.signatures.node_detection.PortDetector': [
                SignatureOption(DISALLOWED_PORT_OPTION, "node_detection", "disallowed_nodes_file", _CSV_TYPE)],
            'virusscanner.parsing.signatures.path_detection.PathDetector': [
                SignatureOption(DISALLOWED_PATH_BEGIN_OPTION, "path_detection", "disallowed_begin_nodes_file",
                                _CSV_TYPE),
                SignatureOption(DISALLOWED_PATH_END_OPTION, "path_detection", "disallowed_destination_nodes_file",
                                _CSV_TYPE)],
            'virusscanner.parsing.signatures.antenna_detection.AntennaDetector': [
                SignatureOption(ALLOWED_INPUT_ANTENNA_OPTION, "antenna_detection", "allowed_input_antennas_file",
                                _CSV_TYPE),
                SignatureOption(ALLOWED_OUTPUT_ANTENNA_OPTION, "antenna_detection", "allowed_input_antennas_file",
                                _CSV_TYPE)],
            'virusscanner.parsing.signatures.short_detection.ShortCircuitDetector': [
                SignatureOption(SHORT_LOCATIONS_OPTION, "short_detection", "short_location_file",
                                _CSV_TYPE)],
            'virusscanner.parsing.signatures.unspecified_path_detection.UnspecifiedPathDetector': [
                SignatureOption(SPECIFIED_PATH_BEGIN_OPTION, "unspecified_path_detection", "specified_begin_nodes_file",
                                _CSV_TYPE),
                SignatureOption(SPECIFIED_PATH_END_OPTION, "unspecified_path_detection", "specified_end_nodes_file",
                                _CSV_TYPE),
                SignatureOption(SPECIFIED_PATH_ROUTING_OPTION, "unspecified_path_detection",
                                "specified_routing_nodes_file", _CSV_TYPE)],
            'virusscanner.parsing.signatures.ring_oscillator_detection.CombinatorialLoopDetector': [
                SignatureOption(IGNORED_LOOP_ATTRIBUTES_OPTION, "ring_oscillator_detection",
                                "ignored_attributes_file", _TXT_TYPE)],
            'virusscanner.parsing.signatures.attribute_detection.AttributeDetector': [],
            'virusscanner.parsing.signatures.fan_out_detection.FanOutDetector': [
                SignatureOption(FAN_OUT_BEGIN_OPTION, "fan_out_detection", "fan_out_begin_nodes_file",
                                _CSV_TYPE),
                SignatureOption(FAN_OUT_END_OPTION, "fan_out_detection", "fan_out_end_nodes_file",
                                _CSV_TYPE)]
        }

    def __init__(self):
        csv_parser = CSVInput()

        self._type_handlers = {
            self._CSV_TYPE: csv_parser.get_regexps_list_from_file,
            self._TXT_TYPE: self.__get_list_of_entries_from_file
        }

    def set_virus_signature_option_inputs(self, virus_signature_set: Set[str],
                                          virus_signature_option_inputs: Dict[
                                              str, Union[List[str], List[Dict[str, Union[str, Pattern[str]]]]]],
                                          config_parser: ConfigParser) -> None:
        """Method to set virus signature option inputs from the given config.

        Args:
            virus_signature_set: Set of virus signatures defined in the config.
            virus_signature_option_inputs: Dictionary to be filled by this method based on what options are given.
            config_parser: Parser to read the config.
        """
        for given_virus_signature in virus_signature_set:
            for section_option in self._signature_options_dict[given_virus_signature]:
                virus_signature_option_inputs[section_option.list_key] = self._type_handlers[section_option.type](
                    config_parser.get(section_option.section, section_option.option))

    @staticmethod
    def __get_list_of_entries_from_file(txt_filename: str) -> List[str]:
        data = []
        with open(txt_filename, "r") as file_handle:
            for line in file_handle:
                data.append(line.strip())

        return data
