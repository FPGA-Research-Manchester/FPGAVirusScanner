from unittest import TestCase, mock

from virusscanner.interface.datastructures.connection import Connection
from virusscanner.interface.datastructures.implementation_graph import Graph
from virusscanner.parsing.signatures.attribute_detection import AttributeDetector


class TestAttributeDetector(TestCase):
    def test_detect_virus_will_detect_no_disallowed_connections(self):
        mock_input = mock.Mock()

        first_attribute = "fake_attribute1"
        second_attribute = "fake_attribute2"
        third_attribute = "fake_attribute3"
        fourth_attribute = "fake_attribute4"

        first_connection = Connection(mock.Mock(), mock.Mock(), {first_attribute})
        second_connection = Connection(mock.Mock(), mock.Mock(), {first_attribute})
        third_connection = Connection(mock.Mock(), mock.Mock(), {first_attribute, second_attribute})

        mock_input.get_connections_graph.return_value = Graph(
            connections=[first_connection, second_connection, third_connection])
        mock_input.get_disallowed_attributes_list.return_value = [third_attribute, fourth_attribute]

        self.assertEqual(AttributeDetector(mock_input).detect_virus(), 0)

    def test_detect_virus_outputs_the_correct_score(self):
        mock_input = mock.Mock()

        first_attribute = "fake_attribute1"
        second_attribute = "fake_attribute2"
        third_attribute = "fake_attribute3"
        fourth_attribute = "fake_attribute4"

        first_connection = Connection(mock.Mock(), mock.Mock(), {first_attribute})
        second_connection = Connection(mock.Mock(), mock.Mock(), {first_attribute})
        third_connection = Connection(mock.Mock(), mock.Mock(), {first_attribute, second_attribute, third_attribute})
        fourth_attribute = Connection(mock.Mock(), mock.Mock(), {fourth_attribute, second_attribute})

        mock_input.get_connections_graph.return_value = Graph(
            connections=[first_connection, second_connection, third_connection, fourth_attribute])
        mock_input.get_disallowed_attributes_list.return_value = [first_attribute, second_attribute]

        self.assertEqual(AttributeDetector(mock_input).detect_virus(), 5)
