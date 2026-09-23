import unittest
from qualify_docs import runner_inventory

class Qualification(unittest.TestCase):
    def test_every_runnable_example_has_an_executed_runner(self):
        with self.assertRaisesRegex(ValueError,'unmapped'):
            runner_inventory({'new.md:1':{'kind':'runnable','runner':'scripts/new_unrun.py'}})
    def test_inventory_selects_no_phantom_runners(self):
        self.assertEqual(runner_inventory({'sample:1':{'kind':'runnable','runner':'scripts/test_docs_policies.py'}}),['scripts/test_docs_policies.py'])

if __name__=='__main__':
    unittest.main()
