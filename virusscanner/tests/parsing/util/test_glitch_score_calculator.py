from unittest import TestCase

from virusscanner.parsing.util.glitch_score_calculator import GlitchScoreCalculator


class TestGlitchScoreCalculator(TestCase):

    def test_calculate_lut_glitch_score_throws_assertion_error(self):
        with self.assertRaises(AssertionError):
            GlitchScoreCalculator().calculate_lut_glitch_score("011")

    def test_calculate_lut_glitch_score_returns_correct_and_score(self):
        self.assertEqual(GlitchScoreCalculator().calculate_lut_glitch_score("0001"), 4)
        self.assertEqual(GlitchScoreCalculator().calculate_lut_glitch_score("00010011"), 10)

    def test_calculate_lut_glitch_score_returns_zero(self):
        self.assertEqual(GlitchScoreCalculator().calculate_lut_glitch_score("0000"), 0)

    def test_calculate_max_switch_count_throws_assertion_error(self):
        with self.assertRaises(AssertionError):
            GlitchScoreCalculator().calculate_max_switch_count("011")

    def test_calculate_max_switch_count_returns_correct_and_score(self):
        self.assertEqual(GlitchScoreCalculator().calculate_max_switch_count("0001"), 2)
        self.assertEqual(GlitchScoreCalculator().calculate_max_switch_count("00010011"), 3)

    def test_calculate_max_switch_count_returns_zero(self):
        self.assertEqual(GlitchScoreCalculator().calculate_max_switch_count("0000"), 0)
