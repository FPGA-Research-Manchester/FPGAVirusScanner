import csv
import re
from typing import List, Dict, Pattern, Union


class CSVInput:
    """Class for reading regular expressions from the given CSV files"""
    REGEX_KEY_SET = (
        "tile_type", "tile_x", "tile_y", "input_port", "output_port", "port", "begin_tile_type", "begin_tile_x",
        "begin_tile_y", "begin_port", "end_tile_type", "end_tile_x", "end_tile_y", "end_port"
    )  # Set of keys which mark which csv columns are regular expressions.

    def get_regexps_list_from_file(self, csv_filename: str) -> List[Dict[str, Union[str, Pattern[str]]]]:
        """Method to open and read the given csv file and return the regular expressions and strings given.

        Args:
            csv_filename: File path to the CSV file.

        Returns:
            List of dictionaries holding the given values of each CSV column.
        """
        with open(csv_filename, "r") as csv_file_handle:
            reader = csv.DictReader(csv_file_handle)
            regexps_list = []
            for row in reader:
                current_regex_line = dict()
                for key in row:
                    if row[key]:
                        if key in self.REGEX_KEY_SET:
                            current_regex_line[key] = re.compile(r"{}".format(row[key]))
                        else:
                            current_regex_line[key] = row[key]
                regexps_list.append(current_regex_line)
        return regexps_list
