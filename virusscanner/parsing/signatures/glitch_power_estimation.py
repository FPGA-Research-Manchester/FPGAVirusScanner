import resource
import sys
from typing import Dict, List, Set, Tuple

from virusscanner.interface.datastructures.connection import Connection
from virusscanner.interface.datastructures.port import Port
from virusscanner.interface.input_interface import Input
from virusscanner.parsing.util.glitch_score_calculator import GlitchScoreCalculator

from virusscanner.parsing.util.graph_processing import GraphProcessor
from virusscanner.parsing.signatures.abstract_signature import VirusSignature


# TODO: Add unittests
class GlitchPowerEstimator(VirusSignature):
    """Initial class for estimating how much does the activity of the circuit draw power.

    Args:
        input_parameters: Input object containing data for this virus scanner.

    """

    DEFAULT_POWER_COST = 1.0
    MAX_SIGNAL_ACTIVITY = 20.0

    def __init__(self, input_parameters: Input) -> None:
        self.__input_parameters = input_parameters
        self.__found_connections = input_parameters.get_connections_graph()

    # TODO: Remove recursion limit raise and make the search iterative.
    def detect_virus(self) -> float:
        sys.setrecursionlimit(10 ** 6)
        resource.setrlimit(resource.RLIMIT_STACK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        graph_processor = GraphProcessor()
        begin_ports = self.__get_end_ports_with_attributes(
            self.__input_parameters.get_glitch_power_begin_attribute_list(),
            self.__found_connections.connections)

        end_ports = self.__get_end_ports_with_attributes(
            self.__input_parameters.get_glitch_power_end_attribute_list(),
            self.__found_connections.connections)

        adjacency_list = self.__found_connections.get_adjacency_list()
        if begin_ports:
            return self.output_max_scoring_connection(
                self.__get_connection_scores(begin_ports, end_ports, adjacency_list, graph_processor))
        return 0

    @staticmethod
    def __get_end_ports_with_attributes(attribute_list: List[str], connection_list: List[Connection]) -> Set[
            Port]:
        matching_ports = set()
        for connection in connection_list:
            for attribute in attribute_list:
                if attribute in connection.attributes:
                    matching_ports.add(connection.end)
        return matching_ports

    def __get_connection_scores(self, begin_ports: Set[Port], end_ports: Set[Port],
                                adjacency_list: Dict[Port, Tuple[Port, ...]],
                                graph_processor: GraphProcessor) -> Dict[Connection, float]:
        found_glitch_scores = dict()
        connection_scores = dict()
        chance_of_switch = 1.0
        for start_port in begin_ports:
            self.__score_paths_from_start_port(start_port, adjacency_list, end_ports, graph_processor,
                                               GlitchScoreCalculator(), connection_scores, found_glitch_scores,
                                               chance_of_switch, [start_port])
        return connection_scores

    def __score_paths_from_start_port(self, start_port: Port, adjacency_list_dict: Dict[Port, Tuple[Port, ...]],
                                      end_ports_set: Set[Port], graph_processor: GraphProcessor,
                                      glitch_scorer: GlitchScoreCalculator,
                                      connection_scores_dict: Dict[Connection, float],
                                      found_glitch_scores_dict: Dict[str, float], input_chance_of_switch: float,
                                      current_path_stack: List[Port]) -> None:

        for connecting_port in adjacency_list_dict.get(start_port, []):
            self.__update_connection_switch_count(connecting_port, connection_scores_dict, input_chance_of_switch,
                                                  start_port)

            self.__expand_on_connecting_port(start_port, connecting_port, adjacency_list_dict, end_ports_set,
                                             graph_processor, glitch_scorer, connection_scores_dict,
                                             found_glitch_scores_dict, input_chance_of_switch, current_path_stack)

    def __expand_on_connecting_port(self, start_port: Port, connecting_port: Port,
                                    adjacency_list_dict: Dict[Port, Tuple[Port, ...]], end_ports_set: Set[Port],
                                    graph_processor: GraphProcessor, glitch_scorer: GlitchScoreCalculator,
                                    connection_scores_dict: Dict[Connection, float],
                                    found_glitch_scores_dict: Dict[str, float], input_chance_of_switch: float,
                                    current_path_stack: List[Port]) -> None:
        if connecting_port not in current_path_stack:
            current_path_stack.append(connecting_port)
            if connecting_port not in end_ports_set and connection_scores_dict.get(
                    Connection(start_port, connecting_port), 1.0) < self.MAX_SIGNAL_ACTIVITY:
                self.__score_paths_from_start_port(connecting_port, adjacency_list_dict, end_ports_set,
                                                   graph_processor, glitch_scorer, connection_scores_dict,
                                                   found_glitch_scores_dict,
                                                   self.__get_current_switch_chance(start_port, connecting_port,
                                                                                    graph_processor, glitch_scorer,
                                                                                    found_glitch_scores_dict,
                                                                                    input_chance_of_switch),
                                                   current_path_stack)
            current_path_stack.pop()

    def __get_current_switch_chance(self, start_port: Port, connecting_port: Port, graph_processor: GraphProcessor,
                                    glitch_scorer: GlitchScoreCalculator, found_glitch_scores_dict: Dict[str, float],
                                    input_chance_of_switch: float):
        current_chance_of_switch = input_chance_of_switch
        if graph_processor.is_connection_in_lut_tile(start_port.tile, connecting_port.tile,
                                                     self.__found_connections.lut_values):
            lut_value = graph_processor.get_lut_value(connecting_port, self.__found_connections.lut_values)
            if lut_value:
                current_chance_of_switch *= self.get_glitch_score(found_glitch_scores_dict, glitch_scorer,
                                                                  lut_value)
        return current_chance_of_switch

    @staticmethod
    def __update_connection_switch_count(connecting_port, connection_scores_dict, input_chance_of_switch,
                                         start_port):
        current_connection = Connection(start_port, connecting_port)
        if current_connection in connection_scores_dict:
            connection_scores_dict[current_connection] += input_chance_of_switch
        else:
            connection_scores_dict[current_connection] = input_chance_of_switch

    @staticmethod
    def get_glitch_score(found_glitch_scores: Dict[str, float], glitch_scorer: GlitchScoreCalculator,
                         lut_config: str) -> float:
        if lut_config not in found_glitch_scores:
            found_glitch_scores[lut_config] = glitch_scorer.calculate_switch_likelihood_with_glitch_score(lut_config)
        return found_glitch_scores[lut_config]

    def output_max_scoring_connection(self, connection_scores: Dict[Connection, float]) -> float:
        glitch_score_sum = 0

        if self.__input_parameters.get_connection_value_switch_power_cost_list():
            for connection in self.__found_connections.connections:
                power_cost_found = False
                for power_cost_line in self.__input_parameters.get_connection_value_switch_power_cost_list():
                    if power_cost_line["begin_tile_type"].match(connection.begin.tile.name) and \
                            power_cost_line["begin_tile_x"].match(str(connection.begin.tile.x)) and \
                            power_cost_line["begin_tile_y"].match(str(connection.begin.tile.y)) and \
                            power_cost_line["begin_port"].match(connection.begin.name) and \
                            power_cost_line["end_tile_type"].match(connection.end.tile.name) and \
                            power_cost_line["end_tile_x"].match(str(connection.end.tile.x)) and \
                            power_cost_line["end_tile_y"].match(str(connection.end.tile.y)) and \
                            power_cost_line["end_port"].match(connection.end.name):
                        if power_cost_found:
                            raise ValueError(str(connection) + " has multiple power costs given!")
                        else:
                            glitch_score_sum += connection_scores.get(connection, 1.0) * float(
                                power_cost_line["power_cost"])
                            power_cost_found = True
                if not power_cost_found:
                    glitch_score_sum += connection_scores.get(connection, 1.0) * self.DEFAULT_POWER_COST
        else:
            for connection in self.__found_connections.connections:
                glitch_score_sum += connection_scores.get(connection, 1.0)

        if self.__input_parameters.get_glitch_power_threshold() \
                and self.__input_parameters.get_glitch_power_threshold() > glitch_score_sum:
            return 0
        else:
            print("Overall glitchiness is", glitch_score_sum)
            return glitch_score_sum
