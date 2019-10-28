from virusscanner.interface.datastructures.implementation_graph import Graph


class ConnectionRemover:
    # TODO: Change these kind of searches from list iteration to using hash functions (i.e sets)
    @staticmethod
    def remove_connections(connections_file: str, found_connections_graph: Graph) -> None:
        with open(connections_file, "r") as connections_file_handle:
            for line in connections_file_handle:
                line = line.strip()
                if line != "":
                    for connection in found_connections_graph.connections:
                        if str(connection) == line:
                            found_connections_graph.remove_connection(connection)