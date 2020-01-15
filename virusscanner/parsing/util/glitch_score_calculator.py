import math
import itertools


# TODO: Write additional unittests
class GlitchScoreCalculator:
    """Class for calculating different scores given a LUT value."""

    def calculate_lut_glitch_score(self, input_lut_value: str) -> int:
        """Method to calculate a score which helps understand how likely the LUT is to produce glitches.

        Args:
            input_lut_value: String representing the binary of the LUT value.

        Returns:
            Integer representing the glitchiness score of the LUT value.
        """
        return self.__get_lut_glitch_score_with_input_count(self.__get_input_count(input_lut_value), input_lut_value)

    def calculate_max_switch_count(self, input_lut_value: str) -> int:
        """Method to calculate what is the highest switch count the given LUT value can produce.

        Args:
            input_lut_value: String representing the binary of the LUT value.

        Returns:
            Integer representing the maximum amount of times the output can change when the input changes.
        """
        return self.__calculate_max_switch_count_with_input_count(self.__get_input_count(input_lut_value),
                                                                  input_lut_value)

    def calculate_switch_likelihood_with_max_switch(self, input_lut_value: str) -> float:
        """Method to calculate what is the likelihood that the output changes with a single input bit change.

        Args:
            input_lut_value: String representing the binary of the LUT value.

        Returns:
            Float representing the probability that the output can change when the input changes considering the max
            amount of times the output can change if all 4 inputs change.
        """
        amount_of_inputs = self.__get_input_count(input_lut_value)

        return self.__calculate_max_switch_count_with_input_count(amount_of_inputs, input_lut_value) / amount_of_inputs

    def calculate_switch_likelihood_with_glitch_score(self, input_lut_value: str) -> float:
        """Method to calculate what is the likelihood that the output changes with a single input bit change.

        Args:
            input_lut_value: String representing the binary of the LUT value.

        Returns:
            Float representing the probability that the output can change when the input changes.
        """
        amount_of_inputs = self.__get_input_count(input_lut_value)
        return self.__get_lut_glitch_score_with_input_count(amount_of_inputs,
                                                            input_lut_value) / self._get_max_score_given_input_count(
            amount_of_inputs)

    @staticmethod
    def _get_max_score_given_input_count(amount_of_inputs):
        return amount_of_inputs * pow(2, amount_of_inputs)

    @staticmethod
    def __get_lut_glitch_score_with_input_count(amount_of_inputs, input_lut_value):
        switch_count = 0
        for start_state in range(2 ** amount_of_inputs):
            for bit_index in range(amount_of_inputs):
                finish_state = start_state ^ (1 << bit_index)
                if input_lut_value[start_state] != input_lut_value[finish_state]:
                    switch_count += 1
        return switch_count

    def __calculate_max_switch_count_with_input_count(self, amount_of_inputs, input_lut_value):
        max_switch_count = 0
        for start_state in range(2 ** amount_of_inputs):
            switch_count = self.__get_max_switch_count_for_input(start_state, input_lut_value, amount_of_inputs)
            if switch_count == amount_of_inputs:
                return switch_count
            elif switch_count > max_switch_count:
                max_switch_count = switch_count
        return max_switch_count

    @staticmethod
    def __get_max_switch_count_for_input(initial_input: int, lut_bin_str: str, digits_count: int) -> int:
        current_max_switch_count = 0
        for order in itertools.permutations(range(digits_count)):
            current_result_value = lut_bin_str[initial_input]
            current_switch_count = 0
            current_input = initial_input
            for change_index in order:
                current_input ^= (1 << change_index)
                if lut_bin_str[current_input] != current_result_value:
                    current_result_value = lut_bin_str[current_input]
                    current_switch_count += 1
            if current_max_switch_count < current_switch_count:
                current_max_switch_count = current_switch_count
            if current_max_switch_count == digits_count:
                return current_max_switch_count
        return current_max_switch_count

    def __get_input_count(self, input_lut_value):
        assert (self.__is_power_of_two(len(input_lut_value)))
        return int(math.log(len(input_lut_value), 2))

    @staticmethod
    def __is_power_of_two(num: int) -> bool:
        return ((num & (num - 1)) == 0) and num != 0
