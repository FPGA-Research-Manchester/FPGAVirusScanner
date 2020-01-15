from virusscanner.interface.input_interface import Input

from virusscanner.parsing.signatures.abstract_signature import VirusSignature


class AttributeDetector(VirusSignature):
    """Initial class for detecting forbidden attributes

    Args:
        input_parameters: Input object containing data for this virus scanner.

    """

    def __init__(self, input_parameters: Input) -> None:
        self.__input_parameters = input_parameters
        self.__list_of_disallowed_attributes = input_parameters.get_disallowed_attributes_list()

    def detect_virus(self) -> float:
        fault_count_dict = dict.fromkeys(self.__list_of_disallowed_attributes, 0)
        for connection in self.__input_parameters.get_connections_graph().connections:
            for attribute in self.__list_of_disallowed_attributes:
                if attribute in connection.attributes:
                    fault_count_dict[attribute] += 1

        score = 0
        for attribute in fault_count_dict:
            if fault_count_dict[attribute] != 0:
                score += fault_count_dict[attribute]
                print(str(fault_count_dict[attribute]), attribute, "connections found!")

        return score
