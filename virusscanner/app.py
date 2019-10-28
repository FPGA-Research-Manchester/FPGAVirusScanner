import click
from virusscanner.interface import input_interface
from virusscanner.parsing import signature_detector


@click.command()
@click.option("-c", "--config", "config", type=click.Path(), required=True,
              help="Config file to configure the virusscanner")
@click.option("-g", "--connections-graph", "connections_graph", type=click.Path(), required=True,
              help="JSON file containing the connections graph of the input design")
@click.option("-o", "--output-file", "output_file", type=click.Path(), required=True, help="Output file path")
def main(config: str, connections_graph: str, output_file: str) -> None:
    """Program to scan the given design for viruses with the given resources defined in the config"""
    signature_detector.SignatureDetector().parse_input(
        input_interface.Input(config, output_file, connections_graph))
