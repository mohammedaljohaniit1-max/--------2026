"""Offline validation of reviewed program scope and execution gates. No target scans."""
import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

import burhan as b
import burhan_programs as p
from test_burhan import ROOT


class ProgramTests(unittest.TestCase):
    def setUp(self):
        # Review cutoffs must block real runs without making offline tests date-dependent.
        clock = patch.object(b, 'utcnow', return_value=dt.datetime(2026, 9, 12, tzinfo=dt.timezone.utc))
        clock.start()
        self.addCleanup(clock.stop)

    def test_catalog_has_two_public_programs(self):
        catalog = p.load_catalog()
        self.assertEqual({x['id'] for x in catalog['programs']}, {'clario', 'cs-money'})
        self.assertTrue(all(x['policy_url'].startswith('https://hackerone.com/') for x in catalog['programs']))

    def test_clario_all_twenty_web_assets_and_explicit_exclusions(self):
        catalog = p.load_catalog()
        program = p.selected_programs(catalog, 'clario')[0]
        plan = p.build_plan('clario', catalog)
        origins = [site for stage in plan['stages'] for site in stage['policy']['origins']]
        self.assertEqual(len(origins), 20)
        self.assertEqual(set(origins), set(program['scan_origins']))
        self.assertEqual(len(plan['stages']), 2)
        for blocked in program['explicit_out_of_scope_assets']:
            for stage in plan['stages']:
                with self.assertRaises(b.GuardError):
                    b.Policy(**stage['policy']).allowed('https://' + blocked + '/')

    def test_cs_money_subset_and_blog_exclusion(self):
        plan = p.build_plan('cs-money')
        self.assertEqual(len(plan['stages']), 1)
        policy = b.Policy(**plan['stages'][0]['policy'])
        self.assertEqual(set(policy.origins), {'https://cs.money', 'https://3d.cs.money'})
        for url in ['https://cs.money/blog', 'https://cs.money/%62log/post', 'https://blog.cs.money/', 'https://support.cs.money/']:
            with self.subTest(url=url), self.assertRaises(b.GuardError):
                policy.allowed(url)
        self.assertIn('NOT full scope', plan['stages'][0]['scope_completeness'])

    def test_all_plan_is_bounded_and_offline(self):
        with patch.object(b, 'resolve') as resolver, patch.object(socket, 'create_connection') as connect:
            plan = p.build_plan('all')
        resolver.assert_not_called()
        connect.assert_not_called()
        self.assertEqual(len(plan['stages']), 3)
        self.assertEqual(plan['maximum_request_attempts'], 308)
        for stage in plan['stages']:
            policy = b.Policy(**stage['policy'])
            policy.validate()
            self.assertEqual(policy.interval_seconds, 2)
            self.assertLessEqual(len(policy.origins), 10)

    def test_unknown_selector_rejected(self):
        with self.assertRaises(b.GuardError):
            p.build_plan('unreviewed')

    def test_snapshot_expiration_blocks_network(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            with patch.object(b, 'utcnow', return_value=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)), patch.object(b.Transport, 'get') as get:
                with self.assertRaises(b.GuardError):
                    p.run_programs('all', Path(td)/'out', True)
            get.assert_not_called()
            self.assertFalse((Path(td)/'out').exists())

    def test_missing_acknowledgement_blocks_before_network(self):
        with patch.object(b.Transport, 'get') as get, self.assertRaises(b.GuardError):
            p.run_programs('all', ROOT/'must-not-be-created', False)
        get.assert_not_called()
        self.assertFalse((ROOT/'must-not-be-created').exists())

    def test_candidate_is_saved_before_stop(self):
        policy = b.Policy(**p.build_plan('cs-money')['stages'][0]['policy'])
        assessment = p.ProgramAssessment(policy)
        with self.assertRaises(b.StopScan):
            assessment.add('js_test', 'https://cs.money/app.js', 'candidate', 'Synthetic signal', {}, [], 'Review', 'Unproven')
        self.assertTrue(assessment.review_stop)
        self.assertEqual(len(assessment.findings), 1)
        self.assertEqual(assessment.findings[0]['state'], 'candidate')

    def test_observations_do_not_force_review_stop(self):
        policy = b.Policy(**p.build_plan('cs-money')['stages'][0]['policy'])
        assessment = p.ProgramAssessment(policy)
        assessment.add('headers', 'https://cs.money/', 'observation', 'Header note', {}, [], 'Review', 'No impact')
        self.assertFalse(assessment.review_stop)

    def test_batch_stops_and_lists_unexecuted_stages(self):
        def fake_run(assessment):
            assessment.review_stop = True
            assessment.state = 'partial'
            assessment.stop_reason = 'synthetic manual-review stop'
            return assessment.report()
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            out = Path(td)/'batch'
            with patch.object(p.ProgramAssessment, 'run', autospec=True, side_effect=fake_run), patch.object(b.Transport, 'get') as get, contextlib.redirect_stdout(io.StringIO()):
                code = p.run_programs('all', out, True)
            get.assert_not_called()
            summary = json.loads((out/'batch.json').read_text())
            self.assertEqual(code, 2)
            self.assertEqual(len(summary['runs']), 1)
            self.assertEqual(summary['unexecuted_stages'], ['clario-2', 'cs-money-1'])
            self.assertTrue(b.verify_report(out/'clario-1'))

    def test_cli_list_show_plan_never_send_requests(self):
        with patch.object(b.Transport, 'get') as get, contextlib.redirect_stdout(io.StringIO()):
            for arguments in [['programs','list'], ['programs','show','clario'], ['programs','plan','all']]:
                self.assertEqual(b.main(arguments), 0)
        get.assert_not_called()

    def test_all_mock_stages_complete_sequentially(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            out = Path(td)/'batch'
            with patch.object(p.ProgramAssessment, 'run', autospec=True, side_effect=lambda a: a.report()), patch.object(p.time, 'sleep') as sleep, patch.object(b.Transport, 'get') as get, contextlib.redirect_stdout(io.StringIO()):
                code = p.run_programs('all', out, True)
            get.assert_not_called()
            self.assertEqual(sleep.call_count, 2)
            self.assertEqual(code, 0)
            summary = json.loads((out/'batch.json').read_text())
            self.assertEqual([r['stage'] for r in summary['runs']], ['clario-1','clario-2','cs-money-1'])
            self.assertFalse(summary['stopped'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
