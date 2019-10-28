from virusscanner.interface.input_interface import Input
from virusscanner.parsing.util.graph_processing import GraphProcessor
from virusscanner.parsing.signatures.abstract_signature import VirusSignature


class UnspecifiedPathDetector(VirusSignature):
    """Initial class for detecting path usages in the given graph which start from the specified port
    but don't follow the specified routing or end in the specified destination port.

    Args:
        input_parameters: Input object containing data for this virus scanner.

    """

    def __init__(self, input_parameters: Input) -> None:
        self.__input_parameters = input_parameters
        self.__found_connections = input_parameters.get_connections_graph()

    def detect_virus(self) -> float:
        graph_processor = GraphProcessor()

        begin_ports = graph_processor.find_matching_ports(self.__input_parameters.get_specified_begin_port_list(),
                                                          self.__found_connections.connections, ["begin"])

        end_ports = graph_processor.find_matching_ports(self.__input_parameters.get_specified_end_port_list(),
                                                        self.__found_connections.connections, ["end"])

        score = 0
        if begin_ports or end_ports:
            routing_ports = graph_processor.find_matching_ports(
                self.__input_parameters.get_specified_routing_port_list(),
                self.__found_connections.connections, ["begin", "end"])
            if routing_ports:
                found_reverse_paths = graph_processor.find_all_paths(self.__found_connections.get_adjacency_list(True),
                                                                     end_ports, begin_ports, routing_ports)
                for path in found_reverse_paths:
                    path.reverse()
                graph_processor.print_paths("Found the following disallowed paths from the end:", found_reverse_paths)
                score += len(found_reverse_paths)
            else:
                print("No routing ports found!")

        return score
