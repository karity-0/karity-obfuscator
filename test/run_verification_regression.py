"""Verify selection/coverage/fallback/sharding without building any VM."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run_ci
from verification import (ROOT, Check, FEATURE_SUITES, PASS_FEATURES, impact,
                          select_checks, shards, actions_matrix, validate_manifest,
                          changed_paths)
from verification import BACKEND_FEATURES


class VerificationTests(unittest.TestCase):
    def test_manifest_has_no_unregistered_regressions_or_passes(self):
        validate_manifest(run_ci.REGRESSIONS, run_ci.CHECKS)
        with self.assertRaisesRegex(ValueError, 'out of sync'):
            validate_manifest(run_ci.REGRESSIONS + ('forgotten',), run_ci.CHECKS)
        with patch.dict(PASS_FEATURES, {'unregistered_pass': 'strings'}):
            with self.assertRaisesRegex(ValueError, 'Passes need verification ownership'):
                validate_manifest(run_ci.REGRESSIONS, run_ci.CHECKS)
        with patch.dict(BACKEND_FEATURES, {'unregistered_backend': 'backends'}):
            with self.assertRaisesRegex(ValueError, 'Backends need verification ownership'):
                validate_manifest(run_ci.REGRESSIONS, run_ci.CHECKS)

    def test_string_changes_include_cff_and_late_output_contracts(self):
        for path in ('obfuscator/passes/string_obfuscation.py',
                     'obfuscator/passes/string_flow_obfuscation.py',
                     'obfuscator/passes/string_mosaic.py'):
            plan = select_checks(run_ci.CHECKS, level='related', paths=(path,))
            names = {c.name for c in plan.checks}
            self.assertEqual('related', plan.level)
            self.assertTrue({'string_obf', 'string_encode', 'function_cost',
                             'vm_output_emitter', 'line_state', 'pass_contract'} <= names)
            self.assertNotIn('synthesis_dag', names)
            self.assertNotIn('kes_integration', names)
        numeric = select_checks(run_ci.CHECKS, level='related',
                                paths=('obfuscator/passes/literal_mosaic.py',))
        self.assertTrue({'strings', 'numbers', 'functions'} <= numeric.features)

    def test_safe_full_fallback_for_shared_and_unknown_paths(self):
        for path in ('obfuscator/pipeline.py', 'obfuscator/registry.py',
                     'obfuscator/parser51.py', '.github/workflows/ci.yml',
                     'obfuscator/passes/new_pass.py', 'obfuscator/vm/new_module.lua'):
            plan = select_checks(run_ci.CHECKS, level='related', paths=(path,))
            self.assertEqual('full', plan.level, path)
            self.assertEqual(len(run_ci.CHECKS), len(plan.checks))
        with self.assertRaises(ValueError):
            select_checks(run_ci.CHECKS, level='typo')
        with self.assertRaises(ValueError):
            select_checks(run_ci.CHECKS, level='related', features=('typo',))

    def test_docs_and_known_test_changes_do_not_select_unrelated_vm_matrices(self):
        docs = select_checks(run_ci.CHECKS, level='related',
                             paths=('README.md', 'docs/passes/stringEncode.md'))
        self.assertTrue(all(c.quick for c in docs.checks))
        self.assertNotIn('semantic_scripts', {c.name for c in docs.checks})
        contract = next(c for c in docs.checks if c.name == 'pass_contract')
        self.assertIn('--quick', contract.command)
        selected = select_checks(run_ci.CHECKS, level='related',
                                 paths=('test/run_function_cost_regression.py',))
        self.assertIn('function_cost', {c.name for c in selected.checks})
        self.assertIn('strings', selected.features)

    def test_shards_cover_every_check_once_and_are_deterministic(self):
        plan = select_checks(run_ci.CHECKS, level='full')
        groups = shards(plan.checks, 4)
        flattened = [c.name for group in groups for c in group]
        self.assertCountEqual([c.name for c in plan.checks], flattened)
        self.assertEqual(len(set(flattened)), len(flattened))
        self.assertEqual(groups, shards(tuple(reversed(plan.checks)), 4))
        serial = sum(c.seconds for c in plan.checks)
        slowest = max(sum(c.seconds for c in group) for group in groups)
        self.assertLess(slowest, serial/2)
        for group in groups:
            quick = [c.quick for c in group]
            self.assertEqual(quick, sorted(quick, reverse=True))
        matrix = actions_matrix(plan)
        self.assertEqual(12, len(matrix['include']))
        for platform in ('ubuntu-latest', 'windows-latest'):
            for version in ('3.12', '3.15'):
                jobs = [j for j in matrix['include'] if j['os'] == platform and j['python'] == version]
                if not jobs:
                    continue
                self.assertCountEqual(flattened, [n for j in jobs for n in j['selection']['checks']])
        quick = select_checks(run_ci.CHECKS, level='quick')
        self.assertEqual(3, len(actions_matrix(quick)['include']))

    def test_matrix_roundtrip_preserves_commands_and_rejects_unknown_ids(self):
        parent = select_checks(run_ci.CHECKS, level='related', features=('strings',))
        for job in actions_matrix(parent)['include']:
            args = SimpleNamespace(level=None, feature=[], changed=None, github=False,
                                   selection_env='KARITY_CHECK_SELECTION', shard=None)
            with patch.dict(os.environ, {'KARITY_CHECK_SELECTION': json.dumps(job['selection'])}):
                plan = run_ci.plan_from_args(args)
            expected = {c.name: c.command for c in parent.checks}
            self.assertEqual([expected[c.name] for c in plan.checks], [c.command for c in plan.checks])
        for checks in ([], ['docs', 'docs'], ['unknown'], ['synthesis_dag']):
            data = {'level': 'quick', 'features': [], 'checks': checks}
            with patch.dict(os.environ, {'KARITY_CHECK_SELECTION': json.dumps(data)}):
                with self.assertRaises(ValueError):
                    run_ci.plan_from_args(args)

    def test_git_base_failure_is_full_and_rename_reads_both_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            def git(*args):
                subprocess.run(['git', *args], cwd=root, check=True, capture_output=True)
            git('init')
            git('-c', 'user.name=Contract', '-c', 'user.email=contract@example.invalid',
                'commit', '--allow-empty', '-m', 'initial')
            (root / 'old.py').write_text('pass\n')
            git('add', 'old.py')
            git('-c', 'user.name=Contract', '-c', 'user.email=contract@example.invalid',
                'commit', '-m', 'source')
            (root / 'old.py').rename(root / 'new.py')
            self.assertEqual(('new.py', 'old.py'), changed_paths('HEAD', root))
            self.assertIsNone(changed_paths('missing-ref', root))
        args = SimpleNamespace(level='related', feature=['strings'], changed='missing',
                               github=False, selection_env=None, shard=None)
        with patch('run_ci.changed_paths', return_value=None):
            self.assertEqual('full', run_ci.plan_from_args(args).level)

    def test_actions_event_policy_requires_full_before_main_or_manual_runs(self):
        for event, ref, base, expected in (
            ('push', 'refs/heads/dev', '', 'related'),
            ('pull_request', 'refs/pull/2/merge', 'dev', 'related'),
            ('push', 'refs/heads/main', '', 'full'),
            ('pull_request', 'refs/pull/2/merge', 'main', 'full'),
            ('workflow_dispatch', 'refs/heads/dev', '', 'full'),
        ):
            args = SimpleNamespace(level=None, feature=[], changed=None, github=True,
                                   selection_env=None, shard=None)
            env = {'GITHUB_EVENT_NAME':event,'GITHUB_REF':ref,'GITHUB_BASE_REF':base,
                   'VERIFICATION_BASE':'valid-base'}
            with patch.dict(os.environ,env), patch('run_ci.changed_paths',return_value=('docs/verification.md',)):
                self.assertEqual(expected,run_ci.plan_from_args(args).level)

    def test_failure_propagation_and_keep_going_report(self):
        checks = (Check('first', ('one.py',), frozenset()),
                  Check('second', ('two.py',), frozenset()))
        plan = select_checks(checks, level='full')
        for keep_going, count in ((False, 1), (True, 2)):
            with tempfile.TemporaryDirectory() as folder, redirect_stdout(io.StringIO()), patch('run_ci.subprocess.run',
                    side_effect=[SimpleNamespace(returncode=1), SimpleNamespace(returncode=0)]) as runner:
                report = Path(folder)/'report.json'
                self.assertEqual(1, run_ci.execute(plan, keep_going=keep_going, report=report))
                self.assertEqual(count, runner.call_count)
                record = json.loads(report.read_text())
                self.assertFalse(record['passed'])
                self.assertEqual(1, record['checks'][0]['exit_code'])


if __name__ == '__main__':
    unittest.main()
