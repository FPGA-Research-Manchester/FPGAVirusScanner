from virusscanner.interface.input_interface import Input
from virusscanner.parsing.util.graph_processing import GraphProcessor
from virusscanner.parsing.signatures.abstract_signature import VirusSignature


class AntennaDetector(VirusSignature):
    """Initial class for detecting dangling antenna signals.

    Args:
        input_parameters: Input object containing data for this virus scanner.

    """

    def __init__(self, input_parameters: Input) -> None:
        self.__input_parameters = input_parameters
        self.__found_connections = self.__input_parameters.get_connections_graph()

    def detect_virus(self) -> float:
        graph_processor = GraphProcessor()

        dangling_input_port_list = graph_processor.find_dangling_ports(self.__found_connections.connections,
                                                                       self.__found_connections.get_adjacency_list(
                                                                           True),
                                                                       "begin")
        allowed_input_antenna_ports_list = graph_processor.find_matching_ports(
            self.__input_parameters.get_allowed_input_antenna_list(),
            self.__found_connections.connections, ["begin"])
        graph_processor.print_ports("Found the following dangling input ports:",
                                    dangling_input_port_list - allowed_input_antenna_ports_list)
        score = len(dangling_input_port_list - allowed_input_antenna_ports_list)
        dangling_output_port_list = graph_processor.find_dangling_ports(self.__found_connections.connections,
                                                                        self.__found_connections.get_adjacency_list(
                                                                            False),
                                                                        "end")
        allowed_output_antenna_ports_list = graph_processor.find_matching_ports(
            self.__input_parameters.get_allowed_output_antenna_list(),
            self.__found_connections.connections, ["end"])
        graph_processor.print_ports("Found the following dangling output ports:",
                                    dangling_output_port_list - allowed_output_antenna_ports_list)
        return score + len(dangling_output_port_list - allowed_output_antenna_ports_list)
