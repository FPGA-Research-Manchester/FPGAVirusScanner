import json
from typing import Optional

from virusscanner.interface.datastructures.connection import Connection
from virusscanner.interface.datastructures.dataclassesjson import DataClassesJSONEncoder
from virusscanner.interface.datastructures.implementation_graph import Graph
from virusscanner.interface.datastructures.port import Port
from virusscanner.interface.datastructures.tile import Tile


class GraphCreator:
    """Class to contain util methods to handle the implementation graph being read from or written to the JSON file."""

    @staticmethod
    def output_graph(connections_graph: Graph, output_json_file: Optional[str]) -> None:
        """Method to output the given graph of connections to the given file if given and to the standard output
        if no file name is given.

        Args:
            connections_graph: Graph of found connections to be output.
            output_json_file: Name of the output file.

        """
        if output_json_file:
            with open(output_json_file, "w") as json_file_handle:
                json.dump(connections_graph.connections, json_file_handle, cls=DataClassesJSONEncoder)
        else:
            for connection in connections_graph.connections:
                print(connection)

    @staticmethod
    def get_connections_from_json(input_json_file: str) -> Graph:
        """Method to get the connections from the given JSON file.

        Args:
            input_json_file: File path to the JSON file which contains the desired connections.

        Returns:
            Graph object containing the data from the JSON file.

        """
        with open(input_json_file, "r") as json_file_handle:
            json_data = json.load(json_file_handle)

        found_connections_list = []
        for connection in json_data["CONNECTIONS"]:
            for field in connection:
                if "tile" in connection[field]:
                    connection[field]["tile"] = Tile(**connection[field]["tile"])
                    connection[field] = Port(**connection[field])
                else:
                    connection[field] = set(connection[field])
            found_connections_list.append(Connection(**connection))
        if "LUT_VALUES" in json_data:
            return Graph(connections=found_connections_list, lut_values=json_data["LUT_VALUES"])
        else:
            return Graph(connections=found_connections_list)
