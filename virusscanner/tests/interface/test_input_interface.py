from unittest import TestCase, mock

from virusscanner.interface.input_interface import Input


class TestInput(TestCase):

    def setUp(self) -> None:
        options_patcher = mock.patch("virusscanner.interface.input_interface.SignatureOptions")
        self.addCleanup(options_patcher.stop)
        self.mock_options = options_patcher.start()

        attributes_patcher = mock.patch("virusscanner.interface.input_interface.AttributesAdder")
        self.addCleanup(attributes_patcher.stop)
        self.mock_attributes = attributes_patcher.start()

    @mock.patch("virusscanner.interface.input_interface.ConfigParser")
    def test_input_raises_error_with_non_existing_config(self, mock_parser):
        mock_parser.return_value.read.return_value = []
        with self.assertRaises(ValueError):
            Input("fake_file", "output.txt", "another_fake_file")

    @mock.patch("virusscanner.interface.input_interface.ConfigParser")
    @mock.patch("virusscanner.interface.input_interface.GraphCreator")
    def test_get_virus_signature_set_returns_given_signatures(self, mock_creator, mock_parser):
        expected_config = "fake_config"
        expected_signature = "fake_signature"
        another_expected_signature = "another_fake_signature"

        expected_scale = 123.456

        mock_parser.return_value.has_section.return_value = False
        mock_parser.return_value.items.return_value = [(expected_signature, ""),
                                                       (another_expected_signature, str(expected_scale))]
        expected_signatures_and_scales_dict = {expected_signature: 1.0, another_expected_signature: expected_scale}

        self.assertEqual(Input(expected_config, "output.txt", "fake_file").get_virus_signatures(),
                         expected_signatures_and_scales_dict)

        mock_parser.return_value.read.assert_called_once_with(expected_config)
        mock_creator.return_value.get_connections_from_json.assert_called_once()

    @mock.patch("virusscanner.interface.input_interface.ConfigParser")
    @mock.patch("virusscanner.interface.input_interface.GraphCreator")
    def test_get_found_connections_returns_json_connections(self, mock_creator, mock_parser):
        mock_parser.return_value.has_section.return_value = False

        self.assertEqual(
            Input("some_config", "output.txt", connections_graph_file="some_json").get_connections_graph(),
            mock_creator.return_value.get_connections_from_json.return_value)

        self.assertEqual(mock_parser.return_value.get.call_count, 0)

    @mock.patch("virusscanner.interface.input_interface.ConfigParser")
    @mock.patch("virusscanner.interface.input_interface.GraphCreator")
    def test_input_uses_attribute_adder(self, mock_creator, mock_parser):
        mock_parser.return_value.has_section.side_effect = [True, False]

        Input("some_config", "output.txt", connections_graph_file="some_json")

        mock_creator.return_value.get_connections_from_json.assert_called_once()
        mock_parser.return_value.get.assert_called_once()
        self.mock_attributes.return_value.add_attributes_to_connections.assert_called_once()

    @mock.patch("virusscanner.interface.input_interface.ConfigParser")
    @mock.patch("virusscanner.interface.input_interface.GraphCreator")
    def test_input_uses_signature_options(self, mock_creator, mock_parser):
        mock_parser.return_value.has_section.return_value = False

        Input("some_config", "output.txt", connections_graph_file="some_json")

        mock_creator.return_value.get_connections_from_json.assert_called_once()
        self.mock_options.return_value.set_virus_signature_option_inputs.assert_called_once()

    @mock.patch("virusscanner.interface.input_interface.ConfigParser")
    @mock.patch("virusscanner.interface.input_interface.GraphCreator")
    @mock.patch("virusscanner.interface.input_interface.ConnectionRemover")
    def test_input_removes_wanted_connections(self, mock_remover, mock_creator, mock_parser):
        mock_parser.return_value.has_section.side_effect = [True, False]

        Input("some_config", "output.txt", connections_graph_file="some_json")

        mock_creator.return_value.get_connections_from_json.assert_called_once()
        mock_parser.return_value.get.assert_called_once()
        self.mock_attributes.return_value.add_attributes_to_connections.assert_not_called()
        mock_remover.return_value.remove_connections.assert_called_once()
