from virusscanner.interface.input_interface import Input

from virusscanner.parsing.signatures.abstract_signature import VirusSignature


# TODO: Update README
# TODO: Make it take an input instead of hard coding
class AttributeDetector(VirusSignature):
    """Initial class for detecting forbidden attributes

    Args:
        input_parameters: Input object containing data for this virus scanner.

    """

    def __init__(self, input_parameters: Input) -> None:
        self.__input_parameters = input_parameters

    def detect_virus(self) -> float:
        fault_count = 0
        for connection in self.__input_parameters.get_connections_graph().connections:
            if "LATCH" in connection.attributes:
                fault_count += 1

        if fault_count != 0:
            print(str(fault_count), "latch connections found!")

        return fault_count
