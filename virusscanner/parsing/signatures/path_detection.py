from virusscanner.interface.input_interface import Input
from virusscanner.parsing.util.graph_processing import GraphProcessor
from virusscanner.parsing.signatures.abstract_signature import VirusSignature


class PathDetector(VirusSignature):
    """Initial class for detecting given path usages in the given graph.

    Args:
        input_parameters: Input object containing data for this virus scanner.

    """

    def __init__(self, input_parameters: Input) -> None:
        self.__input_parameters = input_parameters
        self.__found_connections = input_parameters.get_connections_graph()

    def detect_virus(self) -> float:
        graph_processor = GraphProcessor()

        begin_ports = graph_processor.find_matching_ports(self.__input_parameters.get_disallowed_begin_port_list(),
                                                          self.__found_connections.connections, ["begin"])

        end_ports = graph_processor.find_matching_ports(self.__input_parameters.get_disallowed_end_port_list(),
                                                        self.__found_connections.connections, ["end"])

        adjacency_list = self.__found_connections.get_adjacency_list()

        score = 0
        if begin_ports and end_ports:
            found_paths = graph_processor.find_all_paths(adjacency_list, begin_ports, end_ports)
            graph_processor.print_paths("Found the following disallowed paths:", found_paths)
            score += len(found_paths)

        return score
