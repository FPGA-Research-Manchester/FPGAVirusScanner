from virusscanner.interface.input_interface import Input
from virusscanner.parsing.util.graph_processing import GraphProcessor
from virusscanner.parsing.signatures.abstract_signature import VirusSignature


class FanOutDetector(VirusSignature):
    """Initial class for detecting high fan-out signals.

    Args:
        input_parameters: Input object containing data for this virus scanner.

    """

    # TODO: Get it as an input parameter from the config
    __FAN_OUT_THRESHOLD = 100

    def __init__(self, input_parameters: Input) -> None:
        self.__input_parameters = input_parameters
        self.__found_connections = input_parameters.get_connections_graph()

    def detect_virus(self) -> float:
        graph_processor = GraphProcessor()

        begin_ports = graph_processor.find_matching_ports(self.__input_parameters.get_fan_out_begin_port_list(),
                                                          self.__found_connections.connections, ["begin"])

        end_ports = graph_processor.find_matching_ports(self.__input_parameters.get_fan_out_end_port_list(),
                                                        self.__found_connections.connections, ["end"])

        adjacency_list = self.__found_connections.get_adjacency_list()

        score = 0
        if begin_ports and end_ports:
            found_paths = graph_processor.find_all_paths(adjacency_list, begin_ports, end_ports)
            fan_out_counters = dict()
            for path in found_paths:
                fan_out_counters[path[0]] = fan_out_counters[path[0]] + 1 if path[0] in fan_out_counters else 1
            for begin_port in fan_out_counters:
                if fan_out_counters[begin_port] > self.__FAN_OUT_THRESHOLD:
                    print(begin_port, "has a fan-out of:", fan_out_counters[begin_port])
                    score += 1
        return score
