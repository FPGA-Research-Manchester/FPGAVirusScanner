from configparser import ConfigParser
from typing import List, Dict, Pattern, Union

from virusscanner.interface.datastructures.implementation_graph import Graph
from virusscanner.interface.json_graph_parser import GraphCreator
from virusscanner.interface.signature_options import SignatureOptions
from virusscanner.parsing.util.attributes_adder import AttributesAdder
from virusscanner.parsing.util.connections_remover import ConnectionRemover


class Input:
    """The Input class for the virusscanner package.

    Args:
        config: Input config file path.
        connections_graph_file: Input implemented connections graph file path.
        output_file: Name of the file to write the output of the scanners to.

    """
    __CONFIG_SCANNER_SECTION = "virus_signatures"
    __CONFIG_ATTRIBUTES_SECTION = "connection_attributes"
    __CONFIG_REMOVABLES_SECTION = "removables"

    __CONFIG_ATTRIBUTES_OPTION = "attributes_file"
    __CONFIG_REMOVABLES_OPTION = "connections_file"

    __virus_signature_option_inputs = dict()

    __chosen_virus_signatures = dict()

    def __init__(self, config: str, output_file: str, connections_graph_file: str) -> None:
        self.output_file = output_file
        self.input_file = connections_graph_file

        config_parser = self.__get_parser(config)
        self.__set_found_connections_from_json(connections_graph_file)

        self.__set_virus_signature_set(config_parser)
        SignatureOptions().set_virus_signature_option_inputs(set(self.__chosen_virus_signatures.keys()),
                                                             self.__virus_signature_option_inputs, config_parser)

        if config_parser.has_section(self.__CONFIG_ATTRIBUTES_SECTION):
            AttributesAdder().add_attributes_to_connections(
                config_parser.get(self.__CONFIG_ATTRIBUTES_SECTION, self.__CONFIG_ATTRIBUTES_OPTION),
                self.__found_connections_graph)

        # TODO: Change order to make adding attributes faster
        if config_parser.has_section(self.__CONFIG_REMOVABLES_SECTION):
            ConnectionRemover().remove_connections(
                config_parser.get(self.__CONFIG_REMOVABLES_SECTION, self.__CONFIG_REMOVABLES_OPTION),
                self.__found_connections_graph)

    def get_connections_graph(self) -> Graph:
        """Getter method to return found connections graph from the input design.

        Returns:
            Graph containing the found connections.

        """
        return self.__found_connections_graph

    def get_virus_signatures(self) -> Dict[str, float]:
        """Getter method to return given virus signature packages.

        Returns:
            Dictionary containing the names of the desired virus scanner packages with their respective
            score scaling factors.

        """
        return self.__chosen_virus_signatures

    def get_disallowed_port_list(self) -> List[Dict[str, Union[str, Pattern[str]]]]:
        """Getter method to return given disallowed port list

        Returns:
            List containing regular expressions to identify disallowed ports.

        """
        return self.__virus_signature_option_inputs[SignatureOptions.DISALLOWED_PORT_OPTION]

    def get_disallowed_begin_port_list(self) -> List[Dict[str, Union[str, Pattern[str]]]]:
        """Getter method to return given input port list to identify disallowed paths in the connections graph.

        Returns:
            List containing begin port regular expressions to identify disallowed connections.

        """
        return self.__virus_signature_option_inputs[SignatureOptions.DISALLOWED_PATH_BEGIN_OPTION]

    def get_disallowed_end_port_list(self) -> List[Dict[str, Union[str, Pattern[str]]]]:
        """Getter method to return given output port list to identify disallowed paths in the connections graph.

        Returns:
            List containing end port regular expressions to identify disallowed connections.

        """
        return self.__virus_signature_option_inputs[SignatureOptions.DISALLOWED_PATH_END_OPTION]

    def get_allowed_input_antenna_list(self) -> List[Dict[str, Union[str, Pattern[str]]]]:
        """Getter method to return given input port list to identify allowed antennas in the connections graph.

        Returns:
            List containing begin port regular expressions to identify allowed antennas.

        """
        return self.__virus_signature_option_inputs[SignatureOptions.ALLOWED_INPUT_ANTENNA_OPTION]

    def get_allowed_output_antenna_list(self) -> List[Dict[str, Union[str, Pattern[str]]]]:
        """Getter method to return given output port list to identify allowed antennas in the connections graph.

        Returns:
            List containing end port regular expressions to identify allowed antennas.

        """
        return self.__virus_signature_option_inputs[SignatureOptions.ALLOWED_OUTPUT_ANTENNA_OPTION]

    def get_short_locations_list(self) -> List[Dict[str, Union[str, Pattern[str]]]]:
        """Getter method to return given short location list to identify the ports which can short.

        Returns:
            List containing port regular expressions which can have it's inputs cause a short.
        """

        return self.__virus_signature_option_inputs[SignatureOptions.SHORT_LOCATIONS_OPTION]

    def get_specified_begin_port_list(self) -> List[Dict[str, Union[str, Pattern[str]]]]:
        """Getter method to return given input port list to identify allowed antennas in the connections graph.

        Returns:
            List containing begin port regular expressions to identify allowed antennas.
        """
        return self.__virus_signature_option_inputs[SignatureOptions.SPECIFIED_PATH_BEGIN_OPTION]

    def get_specified_end_port_list(self) -> List[Dict[str, Union[str, Pattern[str]]]]:
        """Getter method to return given input port list to identify allowed antennas in the connections graph.

        Returns:
            List containing begin port regular expressions to identify allowed antennas.
        """
        return self.__virus_signature_option_inputs[SignatureOptions.SPECIFIED_PATH_END_OPTION]

    def get_specified_routing_port_list(self) -> List[Dict[str, Union[str, Pattern[str]]]]:
        """Getter method to return given input port list to identify allowed antennas in the connections graph.

        Returns:
            List containing begin port regular expressions to identify allowed antennas.
        """
        return self.__virus_signature_option_inputs[SignatureOptions.SPECIFIED_PATH_ROUTING_OPTION]

    def get_ignored_loop_attributes_list(self) -> List[str]:
        """Getter method to return given list of attribute names to find connections to be ignored while finding loops.

        Returns:
            List containing attribute names for connections which should be ignored while finding loops.
        """
        return self.__virus_signature_option_inputs[SignatureOptions.IGNORED_LOOP_ATTRIBUTES_OPTION]

    def get_fan_out_begin_port_list(self) -> List[Dict[str, Union[str, Pattern[str]]]]:
        """Getter method to return given input port list to identify ports from which the fan-out is found out.

        Returns:
            List containing begin port regular expressions to identify fan-out begin ports.
        """
        return self.__virus_signature_option_inputs[SignatureOptions.FAN_OUT_BEGIN_OPTION]

    def get_fan_out_end_port_list(self) -> List[Dict[str, Union[str, Pattern[str]]]]:
        """Getter method to return given input port list to identify ports where the fan-out signal should end up.

        Returns:
            List containing begin port regular expressions to identify fan-out destination ports.
        """
        return self.__virus_signature_option_inputs[SignatureOptions.FAN_OUT_END_OPTION]

    def __set_virus_signature_set(self, config_parser: ConfigParser) -> None:
        for item in config_parser.items(self.__CONFIG_SCANNER_SECTION):
            if item[1] == "":
                self.__chosen_virus_signatures[item[0]] = 1.0
            else:
                self.__chosen_virus_signatures[item[0]] = float(item[1])

    def __set_found_connections_from_json(self, connections_graph_file: str) -> None:
        self.__found_connections_graph = GraphCreator().get_connections_from_json(connections_graph_file)

    @staticmethod
    def __get_parser(config: str) -> ConfigParser:
        config_parser = ConfigParser(allow_no_value=True)
        config_parser.optionxform = str
        if config_parser.read(config):
            return config_parser
        else:
            raise ValueError("Please enter a valid config file!")
