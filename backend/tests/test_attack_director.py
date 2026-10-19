import unittest
import threading
import time
from unittest.mock import patch

from backend.utils import attack_director


class AttackDirectorTests(unittest.TestCase):
    def setUp(self):
        self.active_scenario = patch.object(
            attack_director, '_active_scenario', None
        )
        self.scenario_status = patch.object(
            attack_director, '_scenario_status', {}
        )
        self.cancel_events = patch.object(
            attack_director, '_scenario_cancel_events', {}
        )
        self.active_scenario.start()
        self.scenario_status.start()
        self.cancel_events.start()
        self.addCleanup(self.cancel_events.stop)
        self.addCleanup(self.scenario_status.stop)
        self.addCleanup(self.active_scenario.stop)

    def test_only_one_scenario_can_run_at_a_time(self):
        scenario_id = attack_director._start_scenario('portscan')

        with self.assertRaises(RuntimeError):
            attack_director._start_scenario('brute_force')

        attack_director._end_scenario(scenario_id)
        self.assertIsNone(attack_director.get_active_scenario())

    def test_stop_request_cancels_scenario_and_marks_it_stopped(self):
        log_patch = patch.object(attack_director, '_log')
        log_patch.start()
        self.addCleanup(log_patch.stop)
        scenario_id = attack_director.simulate_portscan()
        self.assertTrue(attack_director.request_stop_scenario(scenario_id))

        deadline = time.monotonic() + 2
        while attack_director.get_active_scenario() and time.monotonic() < deadline:
            threading.Event().wait(0.01)

        self.assertIsNone(attack_director.get_active_scenario())
        self.assertEqual(
            attack_director.get_scenario_status(scenario_id)['status'],
            'STOPPED',
        )
        self.assertIsNone(attack_director.get_active_scenario())

    def test_unknown_scenario_does_not_dispatch(self):
        self.assertIsNone(attack_director.run_simulation('unknown'))


if __name__ == '__main__':
    unittest.main()
