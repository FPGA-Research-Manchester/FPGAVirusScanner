from virusscanner.interface.input_interface import Input
from virusscanner.parsing.util.graph_processing import GraphProcessor
from virusscanner.parsing.signatures.abstract_signature import VirusSignature


class ShortCircuitDetector(VirusSignature):
    """Initial class for detecting multiple input drivers wire usages in the given graph.

    Args:
        input_parameters: Input object containing data for this virus scanner.

    """

    def __init__(self, input_parameters: Input) -> None:
        self.__input_parameters = input_parameters

    def detect_virus(self) -> float:
        graph_processor = GraphProcessor()

        adjacency_list = self.__input_parameters.get_connections_graph().get_adjacency_list(True)
        shorting_ports_set = graph_processor.find_matching_ports(
            self.__input_parameters.get_short_locations_list(),
            self.__input_parameters.get_connections_graph().connections, ["end"])

        score = 0
        for end_port in adjacency_list:
            if len(adjacency_list[end_port]) > 1 and end_port in shorting_ports_set:
                graph_processor.print_ports("{} has the following inputs which can cause a short:".format(end_port),
                                            adjacency_list[end_port])
                score += 1

        return score
