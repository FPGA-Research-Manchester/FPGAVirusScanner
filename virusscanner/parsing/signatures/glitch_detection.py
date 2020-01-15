from typing import Dict, List

from virusscanner.interface.datastructures.port import Port
from virusscanner.interface.input_interface import Input
from virusscanner.parsing.util.glitch_score_calculator import GlitchScoreCalculator

from virusscanner.parsing.util.graph_processing import GraphProcessor
from virusscanner.parsing.signatures.abstract_signature import VirusSignature


class GlitchyPathsDetector(VirusSignature):
    """Initial class for detecting high glitch factors.

    Args:
        input_parameters: Input object containing data for this virus scanner.

    """

    def __init__(self, input_parameters: Input) -> None:
        self.__input_parameters = input_parameters
        self.__found_connections = input_parameters.get_connections_graph()

    def detect_virus(self) -> float:
        graph_processor = GraphProcessor()

        begin_ports = graph_processor.find_matching_ports(self.__input_parameters.get_glitch_path_begin_port_list(),
                                                          self.__found_connections.connections, ["begin"])

        end_ports = graph_processor.find_matching_ports(self.__input_parameters.get_glitch_path_end_port_list(),
                                                        self.__found_connections.connections, ["end"])

        adjacency_list = self.__found_connections.get_adjacency_list()

        if begin_ports and end_ports:
            found_paths = graph_processor.find_all_paths(adjacency_list, begin_ports, end_ports)
            if found_paths:
                glitch_score_threshold = self.__input_parameters.get_glitch_score_threshold()
                if glitch_score_threshold:
                    return self.output_path_scores_over_threshold(found_paths, graph_processor,
                                                                  self.__get_path_scores(found_paths, graph_processor),
                                                                  glitch_score_threshold)
                else:
                    return self.output_max_scoring_path(found_paths, graph_processor,
                                                        self.__get_path_scores(found_paths, graph_processor))
        return 0

    def __get_path_scores(self, found_paths: List[List[Port]], graph_processor: GraphProcessor) -> Dict[int, int]:
        found_glitch_scores = dict()
        path_scores = dict.fromkeys(range(len(found_paths)), 0)
        for path_index in range(len(found_paths)):
            self.__score_path(found_glitch_scores, GlitchScoreCalculator(), found_paths[path_index], path_index,
                              path_scores, graph_processor)
        return path_scores

    def __score_path(self, found_glitch_scores: Dict[str, int], glitch_scorer: GlitchScoreCalculator, path: List[Port],
                     path_index: int, path_scores: Dict[int, int], graph_processor: GraphProcessor) -> None:
        for port_index in range(len(path) - 1):
            if graph_processor.is_connection_in_lut_tile(path[port_index].tile, path[port_index + 1].tile,
                                                         self.__found_connections.lut_values):
                lut_value = graph_processor.get_lut_value(path[port_index + 1], self.__found_connections.lut_values)
                if lut_value:
                    path_scores[path_index] += self.get_glitch_score(found_glitch_scores, glitch_scorer, lut_value)

    @staticmethod
    def get_glitch_score(found_glitch_scores: Dict[str, int], glitch_scorer: GlitchScoreCalculator,
                         lut_config: str) -> int:
        if lut_config not in found_glitch_scores:
            found_glitch_scores[lut_config] = glitch_scorer.calculate_lut_glitch_score(lut_config)
        return found_glitch_scores[lut_config]

    @staticmethod
    def output_path_scores_over_threshold(found_paths: List[List[Port]], graph_processor: GraphProcessor,
                                          path_scores: Dict[int, int], score_threshold: int) -> int:
        signature_score = 0
        for path_id in path_scores:
            if path_scores[path_id] > score_threshold:
                graph_processor.print_ports(
                    "Score of " + str(path_scores[path_id]) + " found for the following path: ",
                    found_paths[path_id])
                signature_score += 1
        return signature_score

    @staticmethod
    def output_max_scoring_path(found_paths: List[List[Port]], graph_processor: GraphProcessor,
                                path_scores: Dict[int, int]) -> int:
        max_glitch_path_id = max(path_scores.keys(), key=(lambda k: path_scores[k]))
        if path_scores[max_glitch_path_id]:
            graph_processor.print_ports(
                "Score of " + str(path_scores[max_glitch_path_id]) + " for the following path: ",
                found_paths[max_glitch_path_id])
        return path_scores[max_glitch_path_id]
