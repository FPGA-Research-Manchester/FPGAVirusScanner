from dataclasses import dataclass, field
from typing import List, Dict, Tuple

from virusscanner.interface.datastructures.connection import Connection
from virusscanner.interface.datastructures.port import Port


@dataclass
class Graph:
    """Dataclass for holding implemented graph connections. In the future could be replaced by networkx.DiGraph."""
    connections: List[Connection] = field(default_factory=list)
    lut_values: Dict[str, Dict[str, str]] = field(default_factory=dict)  # TODO change to Dict[Port...
    __adjacency_list: Dict[Port, Tuple[Port, ...]] = field(default_factory=dict, init=False, repr=False, compare=False)
    __reverse_adjacency_list: Dict[Port, Tuple[Port, ...]] = field(default_factory=dict, init=False, repr=False,
                                                                   compare=False)

    def add_connection(self, new_connection: Connection) -> None:
        """Method for adding new connections to the graph. New addition also clears the saved adjacency lists.

        Args:
            new_connection: Connection to be added to the graph.
        """
        self.connections.append(new_connection)
        if self.__adjacency_list:
            self.__adjacency_list = dict()
        if self.__reverse_adjacency_list:
            self.__reverse_adjacency_list = dict()

    def remove_connection(self, connection_to_be_removed: Connection) -> None:
        """Method for removing connections to the graph. This call also clears the saved adjacency lists.

        Args:
            connection_to_be_removed: Connection to be removed from the graph.
        """
        self.connections.remove(connection_to_be_removed)
        if self.__adjacency_list:
            self.__adjacency_list = dict()
        if self.__reverse_adjacency_list:
            self.__reverse_adjacency_list = dict()

    def get_adjacency_list(self, is_reverse: bool = False) -> Dict[Port, Tuple[Port, ...]]:
        """Method to return an adjacency list of the graph.

        Args:
            is_reverse: Boolean to note if the adjacency list should be from the end ports to the begin ports or not.

        Returns:
            Dictionary of ports pointing to tuples of ports to which they are connected to.
        """
        if is_reverse:
            if not self.__reverse_adjacency_list:
                self.__make_adjacency_lists()
            return self.__reverse_adjacency_list
        else:
            if not self.__adjacency_list:
                self.__make_adjacency_lists()
            return self.__adjacency_list

    def __make_adjacency_lists(self) -> None:
        initial_ordered_dict = dict()
        reverse_ordered_dict = dict()
        for connection in self.connections:
            if connection.begin in initial_ordered_dict:
                initial_ordered_dict[connection.begin].append(connection.end)
            else:
                initial_ordered_dict[connection.begin] = [connection.end]
            if connection.end in reverse_ordered_dict:
                reverse_ordered_dict[connection.end].append(connection.begin)
            else:
                reverse_ordered_dict[connection.end] = [connection.begin]
        for key in initial_ordered_dict:
            self.__adjacency_list[key] = tuple(initial_ordered_dict[key])
        for key in reverse_ordered_dict:
            self.__reverse_adjacency_list[key] = tuple(reverse_ordered_dict[key])
