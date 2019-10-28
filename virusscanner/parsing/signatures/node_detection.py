from virusscanner.interface.input_interface import Input

from virusscanner.parsing.util.graph_processing import GraphProcessor
from virusscanner.parsing.signatures.abstract_signature import VirusSignature


class PortDetector(VirusSignature):
    """Initial class for detecting given port usages in the given graph.

    Args:
        input_parameters: Input object containing data for this virus scanner.

    """

    def __init__(self, input_parameters: Input) -> None:
        self.__input_parameters = input_parameters

    def detect_virus(self) -> float:
        graph_processor = GraphProcessor()
        disallowed_ports = graph_processor.find_matching_ports(
            self.__input_parameters.get_disallowed_port_list(),
            self.__input_parameters.get_connections_graph().connections, ["begin", "end"])

        graph_processor.print_ports("Found the following disallowed ports:", disallowed_ports)
        return len(disallowed_ports)
