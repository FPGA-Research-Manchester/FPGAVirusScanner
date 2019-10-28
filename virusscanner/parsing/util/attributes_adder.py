from virusscanner.interface.csv_reader import CSVInput
from virusscanner.interface.datastructures.implementation_graph import Graph


class AttributesAdder:
    """Class to add attributes to the implemented graph"""
    @staticmethod
    def add_attributes_to_connections(attributes_filename: str, input_graph: Graph) -> None:
        """Method to add attributes specified in the given CSV file to the desired connections.

        Args:
            attributes_filename: File path to the CSV file specifying the attributes.
            input_graph: Graph containing the design's connections.
        """
        for attribute_requirement in CSVInput().get_regexps_list_from_file(attributes_filename):
            for connection in input_graph.connections:
                if attribute_requirement["begin_tile_type"].match(connection.begin.tile.name) and \
                        attribute_requirement["begin_tile_x"].match(str(connection.begin.tile.x)) and \
                        attribute_requirement["begin_tile_y"].match(str(connection.begin.tile.y)) and \
                        attribute_requirement["begin_port"].match(connection.begin.name) and \
                        attribute_requirement["end_tile_type"].match(connection.end.tile.name) and \
                        attribute_requirement["end_tile_x"].match(str(connection.end.tile.x)) and \
                        attribute_requirement["end_tile_y"].match(str(connection.end.tile.y)) and \
                        attribute_requirement["end_port"].match(connection.end.name):
                    connection.attributes.add(attribute_requirement["attribute_name"])
