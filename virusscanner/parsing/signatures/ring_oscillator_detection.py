from typing import List, Dict, Tuple

import networkx

from virusscanner.interface.datastructures.connection import Connection
from virusscanner.interface.datastructures.port import Port
from virusscanner.interface.input_interface import Input
from virusscanner.parsing.util.graph_processing import GraphProcessor
from virusscanner.parsing.signatures.abstract_signature import VirusSignature


class CombinatorialLoopDetector(VirusSignature):
    """Initial class for detecting cycles in the given graph.

    Args:
        input_parameters: Input object containing data for this virus scanner.

    """

    def __init__(self, input_parameters: Input) -> None:
        self.__input_parameters = input_parameters

    def detect_virus(self) -> float:
        adjacency_list = dict(self.__input_parameters.get_connections_graph().get_adjacency_list())
        self.__remove_synchronous_connections(adjacency_list,
                                              self.__input_parameters.get_connections_graph().connections,
                                              self.__input_parameters.get_ignored_loop_attributes_list())

        # In the future networkx could get replaced. Or the package could get used even more.
        found_cycles = list(networkx.simple_cycles(networkx.DiGraph(adjacency_list)))

        score = 0
        if found_cycles:
            for cycle_index in range(len(found_cycles)):
                score += 1
                found_cycles[cycle_index].append(found_cycles[cycle_index][0])
            GraphProcessor().print_paths("Found the following cycles:", found_cycles)

        return score

    @staticmethod
    def __remove_synchronous_connections(adjacency_list: Dict[Port, Tuple[Port, ...]],
                                         connections_list: List[Connection], ignored_attributes: List[str]) -> None:
        for connection in connections_list:
            if any(attribute in ignored_attributes for attribute in connection.attributes):
                remaining_end_port_list = list(adjacency_list[connection.begin])
                remaining_end_port_list.remove(connection.end)
                if remaining_end_port_list:
                    adjacency_list[connection.begin] = tuple(remaining_end_port_list)
                else:
                    adjacency_list.pop(connection.begin)
