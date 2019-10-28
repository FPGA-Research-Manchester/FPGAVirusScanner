import contextlib
import datetime
import importlib
import io

import click

from virusscanner.interface.input_interface import Input


class SignatureDetector:
    """This class contains the main method for the virusscanner package executing the desired scanners."""

    def parse_input(self, input_interface: Input) -> None:
        """ Method to execute the given scanners with the given input.
        Then the output of the scanners is collected and output to the specified output file.

        Args:
            input_interface: Input object containing data for the virus scans.

        """
        self.__write_output_header(input_interface.output_file, input_interface.input_file)

        print("Starting virus signature scans...", end="")
        score_sum = 0.0
        with click.progressbar(iterable=input_interface.get_virus_signatures(),
                               label="Virus signature scanning:",
                               show_pos=True, show_eta=False,
                               item_show_func=self.__get_current_signature_name) as virus_scanner_progress_tracker:
            for virus_signature in virus_scanner_progress_tracker:
                module_name, class_name = virus_signature.rsplit(".", 1)
                signature_class_ = getattr(importlib.import_module(module_name), class_name)
                text_stream = io.StringIO()
                with contextlib.redirect_stdout(text_stream):
                    latest_score = input_interface.get_virus_signatures()[virus_signature] * signature_class_(
                        input_interface).detect_virus()
                score_sum += latest_score
                with open(input_interface.output_file, "a") as output_file_handle:
                    output_file_handle.write(class_name + ": " + str(latest_score) + "\n")
                    signature_output = text_stream.getvalue()
                    if signature_output != "":
                        output_file_handle.write(signature_output + "\n")
                    else:
                        output_file_handle.write("Nothing found.\n\n")
        with open(input_interface.output_file, "a") as output_file_handle:
            output_file_handle.write("Final score: " + str(score_sum) + "\n")
            print("\nFinal score: " + str(score_sum) + "\n")

    @staticmethod
    def __write_output_header(output_file: str, input_file: str) -> None:
        with open(output_file, "a+") as output_file_handle:
            output_file_handle.write(
                "Output for {} generated at {}\n\n".format(input_file, str(datetime.datetime.now())))

    @staticmethod
    def __get_current_signature_name(virus_signature: str) -> str:
        if virus_signature is None:
            return ""
        else:
            return virus_signature.rpartition(".")[2]
