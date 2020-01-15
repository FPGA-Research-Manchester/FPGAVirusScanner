from unittest import TestCase, mock

from virusscanner.interface.datastructures.port import Port


class TestPort(TestCase):
    def test_port_str_is_correct(self):
        fake_tile = mock.Mock()
        port_name = "fake_port"
        port_under_test = Port(fake_tile, port_name)
        self.assertEqual(str(port_under_test), str(fake_tile) + " " + port_name)
