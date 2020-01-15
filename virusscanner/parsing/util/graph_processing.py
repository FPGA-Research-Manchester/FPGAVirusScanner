import copy
from typing import List, Dict, Tuple, Pattern, Optional, Set, Union

from virusscanner.interface.datastructures.connection import Connection
from virusscanner.interface.datastructures.port import Port
from virusscanner.interface.datastructures.tile import Tile


class GraphProcessor:
    """Class which contains methods for processing the given implemented graph."""

    @staticmethod
    def make_adjacency_list_from_connections_list(connections_list: List[Connection], begin: str,
                                                  end: str) -> Dict[Port, Tuple[Port, ...]]:
        """Method to make a new adjacency list given the implemented graph of connections.
        The list contains the given begin port and a tuple of ports it connects to.

        Args:
            connections_list: List of connections representing the implemented graph.
            begin: Key string noting which port in the connection is the begin node.
            end: Key string noting which port in the connection is the end node.

        Returns:
            Dictionary of ports showing the adjacent end ports to the connected begin port.
        """
        adjacency_list = dict()
        for current_connection in connections_list:
            if getattr(current_connection, begin) not in adjacency_list:
                adjacency_list[getattr(current_connection, begin)] = [getattr(current_connection, end)]
            else:
                adjacency_list[getattr(current_connection, begin)].append(getattr(current_connection, end))
        for key in adjacency_list:
            adjacency_list[key] = tuple(adjacency_list[key])
        return adjacency_list

    @staticmethod
    def find_matching_ports(port_regexps_list: List[Dict[str, Union[str, Pattern[str]]]],
                            connections_graph: List[Connection], port_key_list: List[str]) -> Set[Port]:
        """Method to find all of the ports which match the given regular expressions.

        Args:
            port_regexps_list: List holding the regular expressions for different values in the ports.
            connections_graph: List of connections representing the implemented graph.
            port_key_list: Key string noting which type of ports the function should find matches to.

        Returns:
            Set of ports which match the given regular expressions.
        """
        matching_ports_list = set()
        for port_regexps in port_regexps_list:
            for connection in connections_graph:
                for port_key in port_key_list:
                    current_port = getattr(connection, port_key)
                    if port_regexps["tile_type"].match(current_port.tile.name) and \
                            port_regexps["tile_x"].match(str(current_port.tile.x)) and \
                            port_regexps["tile_y"].match(str(current_port.tile.y)) and \
                            port_regexps["port"].match(current_port.name):
                        matching_ports_list.add(current_port)

        return matching_ports_list

    @staticmethod
    def print_ports(message: str, ports_collection: Union[List[Port], Set[Port], Tuple[Port]]) -> None:
        """Method to print out the ports in the given list.

        Args:
            message: String which will be printed out before the given ports.
            ports_collection: Collection of ports to be printed.
        """
        if ports_collection:
            print(message)
            for port in ports_collection:
                print("  ", port)

    @staticmethod
    def print_paths(message: str, paths_list: List[List[Port]]) -> None:
        """Method to print out the given paths.

        Args:
            message: String which will be printed out before the given paths.
            paths_list: List of paths which contain ports in the path.
        """
        if paths_list and paths_list[0]:
            paths_list = [path for path in paths_list if path]
            print(message)
            for path in paths_list:
                print("  ", end="")  # indentation
                for node_index in range(len(path) - 1):
                    print(path[node_index], end=" -> ")
                print(path[len(path) - 1])

    def find_all_paths(self, adjacency_list: Dict[Port, Tuple[Port, ...]], begin_ports: Set[Port],
                       end_ports: Set[Port], routing_ports: Optional[Set[Port]] = None) -> List[List[Port]]:
        """Method to find all of the specified paths using DFS in the given implemented graph. If the routing_ports
        argument is given then all of the paths are reported which don't end up in the specified port through the
        routing ports.

        Args:
            adjacency_list: Adjacency list of the given implemented graph.
            begin_ports: Set of ports from which paths must begin.
            end_ports: Set of ports where the found paths must end.
            routing_ports: Optional list of ports which specify which ports can be used in the path.

        Returns:
            List of found paths.
        """

        found_paths = []
        visited_ports = set()
        if routing_ports:
            for start_port in begin_ports:
                self.depth_first_invalid_path_search_with_routing(start_port, end_ports, routing_ports, adjacency_list,
                                                                  found_paths, visited_ports)
        else:
            for start_port in begin_ports:
                self.depth_first_search(start_port, end_ports, adjacency_list, found_paths)
        return found_paths

    def depth_first_search(self, start_port: Port, end_ports_set: Set[Port],
                           adjacency_list: Dict[Port, Tuple[Port, ...]],
                           found_paths_list: List[List[Port]], current_path_stack: Optional[List[Port]] = None) -> None:
        """Method to do a DFS to recursively find all of the paths to the destination port from the start port.

        Args:
            start_port: Port representing the current location in the graph.
            end_ports_set: Set of ports representing specified destination ports.
            adjacency_list: Adjacency list showing all of the connections in the given implemented graph design.
            found_paths_list: List of paths already found which will be updated with this method calls.
            current_path_stack: List containing nodes currently already visited.
        """
        current_path_stack = current_path_stack if current_path_stack else [start_port]

        for connecting_port in adjacency_list.get(start_port, []):
            if connecting_port not in current_path_stack:
                current_path_stack.append(connecting_port)
                if connecting_port in end_ports_set:
                    found_paths_list.append(copy.copy(current_path_stack))
                else:
                    self.depth_first_search(connecting_port, end_ports_set, adjacency_list, found_paths_list,
                                            current_path_stack)
                current_path_stack.pop()

    def depth_first_invalid_path_search_with_routing(self, start_port: Port, end_ports_set: Set[Port],
                                                     routing_ports_set: Set[Port],
                                                     adjacency_list: Dict[Port, Tuple[Port, ...]],
                                                     found_paths_list: List[List[Port]], visited_ports_set: Set[Port],
                                                     current_path_stack: Optional[List[Port]] = None) -> None:
        """Method to do a DFS to recursively find all of the paths not the destination port from the start port using
        the valid routing ports.

        Args:
            visited_ports_set: Set of visited ports.
            start_port: Port representing the current location in the graph.
            end_ports_set: Set of ports representing valid destination ports.
            routing_ports_set: Set of ports representing valid routing ports.
            adjacency_list: Adjacency list showing all of the connections in the given implemented graph design.
            found_paths_list: List of paths already found which will be updated with this method calls.
            current_path_stack: List containing nodes currently already visited.
        """
        current_path_stack = current_path_stack if current_path_stack else [start_port]
        if start_port not in visited_ports_set:
            visited_ports_set.add(start_port)

        for connecting_port in adjacency_list.get(start_port, []):
            if connecting_port not in current_path_stack and connecting_port not in visited_ports_set:
                current_path_stack.append(connecting_port)
                visited_ports_set.add(connecting_port)
                if connecting_port in routing_ports_set:
                    self.depth_first_invalid_path_search_with_routing(connecting_port, end_ports_set, routing_ports_set,
                                                                      adjacency_list, found_paths_list,
                                                                      visited_ports_set, current_path_stack)
                elif connecting_port not in end_ports_set:
                    found_paths_list.append(copy.copy(current_path_stack))
                current_path_stack.pop()

    @staticmethod
    def find_dangling_ports(connections_list: List[Connection], adjacency_list: Dict[Port, Tuple[Port, ...]],
                            dangling_port_type: str) -> Set[Port]:
        """Method to find all of the ports which aren't connected to any further ports.

        Args:
            adjacency_list: Dictionary showing how ports are connected.
            connections_list: List of connections representing the implemented graph.
            dangling_port_type: Key string noting if the dangling port is an input port or output port.

        Returns:
            Set of ports which don't lead to anywhere or don't have any signals to drive.
        """
        return {getattr(connection, dangling_port_type) for connection in connections_list if
                getattr(connection, dangling_port_type) not in adjacency_list}

    @staticmethod
    def is_connection_in_lut_tile(begin_port_tile: Tile, end_port_tile: Tile,
                                  graph_lut_values: Dict[str, Dict[str, str]]) -> bool:
        """Method to say if the given connection is in a defined LUT tile in the given graph.

        Args:
            begin_port_tile: Tile object noting the begin of the given connection.
            end_port_tile: Tile object noting the end of the given connection.
            graph_lut_values: Dictionary holding all of the LUT values.

        Returns:
            Boolean which says if the given connection is in a tile with LUTs.
        """
        return begin_port_tile == end_port_tile and str(begin_port_tile) in graph_lut_values

    @staticmethod
    def get_lut_value(end_port: Port, graph_lut_values_dict: Dict[str, Dict[str, str]]) -> Optional[str]:
        """Method to check if the given port is a valid port going through a LUT.

        Args:
            end_port: Port of the end of the connection going through a LUT.
            graph_lut_values_dict: Values of all of the LUTs in the graph.
            
        Returns:
            LUT value if there is one for the given begin port.
        """

        return graph_lut_values_dict[str(end_port.tile)].get(end_port.name)
