import unittest
from check_cli_docs import validate_coverage


class Coverage(unittest.TestCase):
    def test_missing_option_or_exit_is_rejected(self):
        help_text = {'validate': 'Options:\n  --strict  Resolve inheritance\n'}
        with self.assertRaisesRegex(ValueError, 'help coverage'):
            validate_coverage('# CLI\n', help_text)
        with self.assertRaisesRegex(ValueError, 'exit contract'):
            validate_coverage('<!-- cli-help: validate -->\n```text\n'+help_text['validate']+'```\n', help_text)


if __name__ == '__main__':
    unittest.main()
