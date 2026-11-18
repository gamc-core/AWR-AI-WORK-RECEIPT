"""Contract tests. All modifications occur in disposable, independent packages."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('awr_verify', ROOT / 'verifier' / 'verify.py')
awr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(awr)


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.package = Path(self.tmp.name) / 'package'
        shutil.copytree(ROOT / 'examples' / 'accepted', self.package)
        self.path = self.package / 'receipt.json'
        self.receipt = awr.parse_json(self.path.read_bytes())

    def save(self):
        self.receipt = awr.seal(self.receipt)
        self.path.write_bytes(json.dumps(self.receipt, ensure_ascii=False, indent=2).encode('utf-8'))

    def result(self, category):
        self.save()
        return awr.verify(self.path)['checks'][category]

    def add_document(self, eid, kind, value):
        raw = json.dumps(value, ensure_ascii=False, indent=2).encode('utf-8')
        sha = hashlib.sha256(raw).hexdigest()
        (self.package / 'objects' / sha).write_bytes(raw)
        self.receipt['evidence'] = [e for e in self.receipt['evidence'] if e['id'] != eid]
        self.receipt['evidence'].append({'id': eid, 'kind': kind, 'description': 'Synthetic test evidence',
                                      'object': {'state': 'OBJECT', 'sha256': sha, 'size_bytes': len(raw), 'evidence_reference': None}})

    def discard_binding(self):
        self.receipt['authorization']['work_binding'] = None
        self.receipt['authorization']['scope']['evidence_reference'] = None

    def unknown_before(self):
        self.discard_binding()
        self.receipt['changes'][0]['before'] = {'state': 'UNKNOWN', 'sha256': None, 'size_bytes': None, 'evidence_reference': None}

    def validation_fixture(self, baseline_failures, current_failures, environment='synthetic-local'):
        population = ['existing', 'new', 'fixed', 'pass']
        for eid, phase, failures in [('baseline', 'BEFORE', baseline_failures), ('validation', 'AFTER', current_failures)]:
            self.add_document(eid, 'VALIDATION', {'work_id': self.receipt['work_id'], 'scope': 'Synthetic comparison',
                'method': 'Synthetic same test suite', 'environment': environment, 'subject_sha256': self.receipt['changes'][0]['before' if phase == 'BEFORE' else 'after']['sha256'],
                'subject_role': 'DOCUMENTED_WORK', 'phase': phase, 'test_ids_run': population,
                'failing_test_ids': failures, 'outcome': 'FAIL' if failures else 'PASS'})
        self.receipt['validation'] = {'current': 'validation', 'baseline': 'baseline'}

    def test_accepted_and_exact_byte_change(self):
        r = awr.verify(self.path)
        self.assertEqual(r['exit_code'], 0)
        self.assertEqual(r['checks']['OBJECT_INTEGRITY']['status'], 'VERIFIED')
        delta = r['checks']['CHANGE_EVIDENCE']['detail'][0]['byte_delta']
        self.assertEqual(delta['removed_bytes'], 0)
        self.assertEqual(delta['added_hex'], b' B7.'.hex())
        self.assertEqual(r['checks']['DISPOSITION']['detail']['claim']['value'], 'ACCEPTED')

    def test_accepted_roles_do_not_assign_an_ai_model_to_backend_execution(self):
        r = awr.verify(self.path)
        executor = r['checks']['EXECUTOR_CLAIM']['detail']
        self.assertEqual(executor['executor']['value'], 'Native backend of the source system')
        self.assertEqual(executor['model']['classification'], 'UNKNOWN')
        self.assertIsNone(executor['model']['value'])
        e = next(e for e in self.receipt['evidence'] if e['id'] == 'derivation')
        d = awr.parse_json((self.package / 'objects' / e['object']['sha256']).read_bytes())
        self.assertEqual(d['roles']['change_text'], 'Gonzalo Montero')
        self.assertEqual(d['roles']['promotion_authority'], 'Gonzalo Montero')
        self.assertNotEqual(d['roles']['proposal_transformation'], d['roles']['execution'])
        self.assertIn('not a unique act', awr.render_human(r))

    def test_examples_ship_only_referenced_objects_and_plain_decisions(self):
        for family in ('accepted', 'honest-failure'):
            package = ROOT / 'examples' / family
            receipt = awr.parse_json((package / 'receipt.json').read_bytes())
            needed = {e['object']['sha256'] for e in receipt['evidence'] if e['object']['state'] == 'OBJECT'}
            needed.update(c[phase]['sha256'] for c in receipt['changes'] for phase in ('before', 'after') if c[phase]['state'] == 'OBJECT')
            self.assertEqual(needed, {p.name for p in (package / 'objects').iterdir()})
            self.assertNotIn('intervention_', b''.join(p.read_bytes() for p in (package / 'objects').iterdir()).decode('utf-8'))
            self.assertEqual(awr.verify(package / 'receipt.json')['exit_code'], 0)

    def test_timestamp_contract_matches_documented_precision_and_calendar(self):
        for value in ('2026-09-30T12:00:00Z', '2026-09-30T12:00:00.123Z', '2026-09-30T12:00:00.123456Z'):
            self.receipt['recorded_at'] = value
            self.assertEqual(self.result('RECEIPT_STRUCTURE')['status'], 'VERIFIED')
        for value in ('2026-09-30T12:00:00.1Z', '2026-09-30T12:00:00.1234567Z', '2026-02-30T12:00:00Z'):
            self.receipt['recorded_at'] = value
            self.assertEqual(self.result('RECEIPT_STRUCTURE')['status'], 'MISMATCH')

    def test_receipt_alteration_detected(self):
        self.receipt['work_id'] = 'tampered'
        self.path.write_bytes(json.dumps(self.receipt).encode('utf-8'))
        r = awr.verify(self.path)
        self.assertEqual(r['exit_code'], 2)
        self.assertEqual(r['checks']['RECEIPT_INTEGRITY']['status'], 'MISMATCH')

    def test_missing_required_object(self):
        sha = self.receipt['changes'][0]['after']['sha256']
        (self.package / 'objects' / sha).unlink()
        self.assertEqual(awr.verify(self.path)['exit_code'], 1)

    def test_missing_human_object_remains_missing(self):
        e = next(e for e in self.receipt['evidence'] if e['kind'] == 'HUMAN_ACT')
        (self.package / 'objects' / e['object']['sha256']).unlink()
        r = awr.verify(self.path)
        self.assertEqual(r['exit_code'], 1)
        self.assertFalse(r['checks']['AUTHORIZATION_DOCUMENTATION']['detail']['human_act_bytes_match'])

    def test_object_hash_mismatch(self):
        sha = self.receipt['changes'][0]['after']['sha256']
        (self.package / 'objects' / sha).write_bytes(b'wrong')
        self.assertEqual(awr.verify(self.path)['checks']['OBJECT_INTEGRITY']['status'], 'MISMATCH')

    def test_object_size_mismatch(self):
        self.receipt['changes'][0]['after']['size_bytes'] += 1
        self.assertEqual(self.result('OBJECT_INTEGRITY')['status'], 'MISMATCH')

    def test_unknown_before_is_not_absent(self):
        self.unknown_before()
        d = self.result('CHANGE_EVIDENCE')['detail'][0]
        self.assertEqual(d['before'], 'UNKNOWN')
        self.assertEqual(d['status'], 'UNKNOWN')
        self.assertNotIn('byte_delta', d)

    def test_hash_only_before_is_not_available_bytes(self):
        self.discard_binding()
        self.receipt['changes'][0]['before']['state'] = 'HASH_ONLY'
        d = self.result('CHANGE_EVIDENCE')['detail'][0]
        self.assertEqual(d['before'], 'HASH_ONLY')
        self.assertNotIn('byte_delta', d)

    def test_absent_before_requires_matching_observation(self):
        self.discard_binding()
        self.add_document('absence', 'OBSERVATION', {'work_id': self.receipt['work_id'], 'target': 'README.md', 'phase': 'before', 'state': 'ABSENT'})
        self.receipt['changes'][0]['before'] = {'state': 'ABSENT', 'sha256': None, 'size_bytes': None, 'evidence_reference': 'absence'}
        d = self.result('CHANGE_EVIDENCE')['detail'][0]
        self.assertEqual(d['before'], 'ABSENT')
        self.assertEqual(d['status'], 'PARTIAL')
        self.assertNotIn('byte_delta', d)
        self.receipt['changes'][0]['before']['evidence_reference'] = None
        self.assertEqual(self.result('RECEIPT_STRUCTURE')['status'], 'MISMATCH')

    def test_after_integrity_kept_with_unknown_before(self):
        self.unknown_before()
        self.assertEqual(self.result('OBJECT_INTEGRITY')['status'], 'VERIFIED')

    def test_documentation_does_not_authenticate_identity(self):
        r = awr.verify(self.path)
        self.assertEqual(r['checks']['AUTHORIZATION_DOCUMENTATION']['status'], 'CONSISTENT')
        self.assertFalse(r['identity_authenticated'])
        self.assertEqual(r['checks']['AUTHORIZATION_DOCUMENTATION']['detail']['identity'], 'UNKNOWN')
        self.assertEqual(r['checks']['EXECUTOR_CLAIM']['status'], 'RECORDED')

    def test_no_text_is_consistent_not_verified_approval(self):
        self.add_document('human_act', 'HUMAN_ACT', 'unused')
        raw = b'NO'
        sha = hashlib.sha256(raw).hexdigest()
        (self.package / 'objects' / sha).write_bytes(raw)
        e = next(e for e in self.receipt['evidence'] if e['id'] == 'human_act')
        e['object'].update(sha256=sha, size_bytes=len(raw))
        self.receipt['authorization']['human_act']['value'] = 'NO'
        e = next(e for e in self.receipt['evidence'] if e['id'] == 'binding')
        binding = awr.parse_json((self.package / 'objects' / e['object']['sha256']).read_bytes())
        binding['human_act_sha256'] = sha
        self.add_document('binding', 'AUTHORIZATION_BINDING', binding)
        self.save()
        r = awr.verify(self.path)
        self.assertEqual(r['checks']['AUTHORIZATION_DOCUMENTATION']['status'], 'CONSISTENT')
        self.assertIn('Approval text: "NO"', awr.render_human(r))
        self.assertFalse(r['identity_authenticated'])

    def test_failed_validation_is_shown_as_record_not_verified_success(self):
        self.validation_fixture([], ['new'])
        self.save()
        r = awr.verify(self.path)
        self.assertEqual(r['checks']['VALIDATION_EVIDENCE']['status'], 'CONSISTENT')
        self.assertIn('Validation outcome recorded: FAIL', awr.render_human(r))
        self.assertEqual(r['checks']['FAILURE_COMPARISON']['detail']['new'], ['new'])

    def test_human_output_includes_decision_limits_and_later_note(self):
        r = awr.verify(ROOT / 'examples/honest-failure/receipt.json')
        text = awr.render_human(r)
        self.assertIn('Decision recorded:', text)
        self.assertIn('Limitations recorded:', text)
        self.assertIn('Later note records (DECLARED):', text)
        self.assertEqual(r['checks']['DISPOSITION']['status'], 'CONSISTENT')
        self.assertEqual(r['checks']['LIMITATIONS']['status'], 'RECORDED')

    def test_authorization_binding_wrong_work_rejected(self):
        e = next(e for e in self.receipt['evidence'] if e['kind'] == 'AUTHORIZATION_BINDING')
        d = awr.parse_json((self.package / 'objects' / e['object']['sha256']).read_bytes())
        d['work_id'] = 'other-work'
        self.add_document('binding', 'AUTHORIZATION_BINDING', d)
        self.assertEqual(self.result('RECEIPT_STRUCTURE')['status'], 'MISMATCH')

    def test_validation_record_present(self):
        check = awr.verify(self.path)['checks']['VALIDATION_EVIDENCE']
        self.assertEqual(check['status'], 'CONSISTENT')
        self.assertEqual(check['detail']['current']['subject_role'], 'HISTORICAL_ORIGINAL')

    def test_validation_record_absent_is_explicit(self):
        self.receipt['validation']['current'] = None
        self.assertEqual(self.result('VALIDATION_EVIDENCE')['status'], 'MISSING')
        self.assertEqual(awr.verify(self.path)['exit_code'], 0)

    def test_baseline_comparable_new_persisting_resolved(self):
        self.validation_fixture(['existing', 'fixed'], ['existing', 'new'])
        d = self.result('FAILURE_COMPARISON')
        self.assertEqual(d['status'], 'VERIFIED')
        self.assertEqual(d['detail'], {'new': ['new'], 'persisting': ['existing'], 'resolved': ['fixed'], 'causality': 'UNKNOWN'})
        self.assertFalse(awr.verify(self.path)['causality_proven'])

    def test_no_baseline_stays_unknown(self):
        self.assertEqual(awr.verify(self.path)['checks']['FAILURE_COMPARISON']['status'], 'UNKNOWN')

    def test_non_comparable_environment_stays_unknown(self):
        self.validation_fixture(['existing'], ['new'])
        e = next(e for e in self.receipt['evidence'] if e['id'] == 'baseline')
        d = awr.parse_json((self.package / 'objects' / e['object']['sha256']).read_bytes())
        d['environment'] = 'different-environment'
        self.add_document('baseline', 'VALIDATION', d)
        self.assertEqual(self.result('FAILURE_COMPARISON')['status'], 'UNKNOWN')

    def test_unrun_baseline_test_prevents_comparison(self):
        self.validation_fixture(['existing'], ['new'])
        e = next(e for e in self.receipt['evidence'] if e['id'] == 'baseline')
        d = awr.parse_json((self.package / 'objects' / e['object']['sha256']).read_bytes())
        d['test_ids_run'].append('not-run-after')
        self.add_document('baseline', 'VALIDATION', d)
        self.assertEqual(self.result('FAILURE_COMPARISON')['status'], 'UNKNOWN')

    def test_failure_outside_population_rejected(self):
        self.validation_fixture(['impossible'], [])
        self.assertEqual(self.result('RECEIPT_STRUCTURE')['status'], 'MISMATCH')

    def test_validation_subject_must_bind_to_phase(self):
        self.validation_fixture([], [])
        e = next(e for e in self.receipt['evidence'] if e['id'] == 'validation')
        d = awr.parse_json((self.package / 'objects' / e['object']['sha256']).read_bytes())
        d['subject_sha256'] = '1' * 64
        self.add_document('validation', 'VALIDATION', d)
        self.assertEqual(self.result('RECEIPT_STRUCTURE')['status'], 'MISMATCH')

    def test_same_baseline_reference_rejected(self):
        self.receipt['validation']['baseline'] = 'validation'
        self.assertEqual(self.result('RECEIPT_STRUCTURE')['status'], 'MISMATCH')

    def test_disposition_unknown_does_not_become_accepted(self):
        self.receipt['disposition'] = {'value': None, 'classification': 'UNKNOWN', 'evidence_reference': None}
        self.assertEqual(self.result('DISPOSITION')['status'], 'UNKNOWN')

    def test_honest_failure_and_additive_correction(self):
        r = awr.verify(ROOT / 'examples/honest-failure/receipt.json')
        self.assertEqual(r['exit_code'], 0)
        self.assertEqual(r['checks']['DISPOSITION']['detail']['claim']['value'], 'KEPT_AS_EVIDENCE_NOT_ACCEPTED')
        self.assertEqual(r['checks']['CHANGE_EVIDENCE']['detail'][0]['before'], 'UNKNOWN')
        self.assertTrue(r['relations'][0]['record']['raw_secured_before_removal'])
        self.assertFalse(r['relations'][0]['record']['record_completed_before_removal'])
        self.assertFalse(r['relations'][0]['record']['prior_record_modified'])

    def test_canonicalization_unicode_null_arrays_and_integer_bounds(self):
        self.assertEqual(awr.canonical_bytes({'z': None, 'a': ['é', '\n', 1, True]}), b'{"a":["\xc3\xa9","\\n",1,true],"z":null}')
        self.assertEqual(awr.canonical_bytes({'b': 2, 'a': 1}), awr.canonical_bytes({'a': 1, 'b': 2}))
        self.assertNotEqual(awr.canonical_bytes([1, 2]), awr.canonical_bytes([2, 1]))
        for raw in (b'1.0', b'1e0', b'NaN', b'Infinity', b'9007199254740992', b'"\\ud800"'):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                awr.parse_json(raw)

    def test_whitespace_does_not_change_receipt_digest(self):
        compact = json.dumps(self.receipt).encode('utf-8')
        self.path.write_bytes(compact)
        self.assertEqual(awr.verify(self.path)['exit_code'], 0)

    def test_duplicate_keys_rejected_recursively(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}'):
            with self.assertRaises(awr.ContractError):
                awr.parse_json(raw)

    def test_ambiguous_structure_dangling_references_and_unknown_claims(self):
        for mutate in (lambda r: r.update(extra='x'),
                       lambda r: r['changes'][0]['before'].update(state='UNKNOWN'),
                       lambda r: r['executor'].update(classification='UNKNOWN'),
                       lambda r: r['executor'].update(evidence_reference='not-existing'),
                       lambda r: r['evidence'].append(copy.deepcopy(r['evidence'][0]))):
            with self.subTest(mutate=mutate):
                self.receipt = awr.parse_json((ROOT / 'examples/accepted/receipt.json').read_bytes())
                mutate(self.receipt)
                self.assertEqual(self.result('RECEIPT_STRUCTURE')['status'], 'MISMATCH')

    def test_object_crlf_and_unicode_bytes_are_not_normalized(self):
        sha = self.receipt['changes'][0]['before']['sha256']
        p = self.package / 'objects' / sha
        p.write_bytes(p.read_bytes().replace(b'\r\n', b'\n'))
        self.assertEqual(awr.verify(self.path)['checks']['OBJECT_INTEGRITY']['status'], 'MISMATCH')

    def test_resealed_package_requires_external_anchor(self):
        old = self.receipt['integrity']['digest']
        self.receipt['receipt_id'] = 'different-but-self-consistent'
        self.save()
        self.assertEqual(awr.verify(self.path)['exit_code'], 0)
        self.assertEqual(awr.verify(self.path, old)['exit_code'], 2)

    def unicode_packet(self):
        self.receipt['limitations'].append('UTF-8: \u2260 \u4e2d \U0001f642')
        self.save()
        return dict(os.environ, PYTHONIOENCODING='cp1252:strict')

    def test_utf8_stdout_redirected_and_json_pipe(self):
        env = self.unicode_packet()
        command = [sys.executable, '-I', '-S', '-B', str(ROOT / 'verifier/verify.py'), str(self.path)]
        output = Path(self.tmp.name) / 'redirected.txt'
        with output.open('wb') as stream:
            p = subprocess.run(command, stdout=stream, stderr=subprocess.PIPE, env=env, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('UTF-8: \u2260 \u4e2d \U0001f642', output.read_bytes().decode('utf-8'))
        p = subprocess.run(command + ['--json'], capture_output=True, env=env, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        parsed = json.loads(p.stdout.decode('utf-8'))
        self.assertIn('UTF-8: \u2260 \u4e2d \U0001f642', parsed['checks']['LIMITATIONS']['detail'])

    def test_utf8_human_output_through_pipe(self):
        env = self.unicode_packet()
        producer = subprocess.Popen([sys.executable, '-I', '-S', '-B', str(ROOT / 'verifier/verify.py'), str(self.path)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            consumer = subprocess.run([sys.executable, '-I', '-S', '-B', '-c',
                "import sys; data=sys.stdin.buffer.read(); data.decode('utf-8'); sys.stdout.buffer.write(data)"],
                stdin=producer.stdout, capture_output=True, timeout=30)
            producer.stdout.close()
            producer.wait(timeout=30)
            self.assertEqual(producer.returncode, 0, producer.stderr.read())
            self.assertEqual(consumer.returncode, 0, consumer.stderr)
            self.assertIn('\u4e2d \U0001f642', consumer.stdout.decode('utf-8'))
        finally:
            if producer.poll() is None:
                producer.kill()
                producer.wait()
            producer.stdout.close()
            producer.stderr.close()

    def test_access_error_is_not_missing_evidence(self):
        original = awr._read_bytes
        blocked = self.receipt['changes'][0]['after']['sha256']
        def read(path):
            if path.name == blocked:
                raise PermissionError('synthetic access denial')
            return original(path)
        with patch.object(awr, '_read_bytes', side_effect=read):
            r = awr.verify(self.path)
        self.assertEqual(r['exit_code'], 3)
        self.assertEqual(r['checks']['OBJECT_INTEGRITY']['status'], 'ACCESS_ERROR')
        self.assertEqual(awr.verify(self.path)['exit_code'], 0)

    def test_output_failure_has_tool_exit(self):
        class BrokenOutput:
            def write(self, text):
                raise UnicodeEncodeError('ascii', '\u4e2d', 0, 1, 'synthetic output failure')
            def flush(self):
                pass
        import io
        with patch.object(awr.sys, 'stdout', BrokenOutput()), patch.object(awr.sys, 'stderr', io.StringIO()):
            self.assertEqual(awr.main([str(self.path)]), 3)

    def test_closed_stdout_process_has_tool_exit(self):
        command = [sys.executable, '-I', '-S', '-B', str(ROOT / 'verifier/verify.py')]
        for family in ('accepted', 'honest-failure'):
            for flags in ([], ['--json']):
                with self.subTest(family=family, flags=flags):
                    process = subprocess.Popen(
                        command + [str(ROOT / 'examples' / family / 'receipt.json')] + flags,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    try:
                        process.stdout.close()
                        process.wait(timeout=30)
                        error = process.stderr.read()
                        self.assertEqual(process.returncode, 3, error)
                        self.assertIn(b'TOOL_ERROR: could not write UTF-8 output', error)
                        self.assertNotIn(b'Exception ignored', error)
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.wait()
                        process.stderr.close()

    def test_honest_failure_reports_partial_documentation_not_approval(self):
        result = awr.verify(ROOT / 'examples/honest-failure/receipt.json')
        authorization = result['checks']['AUTHORIZATION_DOCUMENTATION']
        self.assertEqual(authorization['status'], 'PARTIAL')
        self.assertIsNone(authorization['detail']['approval_text'])
        self.assertFalse(result['identity_authenticated'])
        text = awr.render_human(result)
        self.assertIn('Approval text: not supplied', text)
        self.assertIn('Authorization scope recorded (DECLARED): Saving evidence and cleanup only; the accidental write was not authorized', text)
        self.assertIn('PARTIAL means incomplete documentation, not partial approval.', text)

    def test_human_and_json_labels_represent_same_checks(self):
        aliases = {'CHANGE_RECORD': 'CHANGE_EVIDENCE',
                   'APPROVAL_RECORD': 'AUTHORIZATION_DOCUMENTATION',
                   'EXECUTOR': 'EXECUTOR_CLAIM',
                   'VALIDATION_RECORD': 'VALIDATION_EVIDENCE',
                   'DISPOSITION_RECORD': 'DISPOSITION'}
        command = [sys.executable, '-I', '-S', '-B', str(ROOT / 'verifier/verify.py')]
        for family in ('accepted', 'honest-failure'):
            path = str(ROOT / 'examples' / family / 'receipt.json')
            human = subprocess.run(command + [path], capture_output=True, timeout=30)
            machine = subprocess.run(command + [path, '--json'], capture_output=True, timeout=30)
            self.assertEqual(human.returncode, machine.returncode)
            self.assertEqual(machine.returncode, 0, machine.stderr)
            checks = json.loads(machine.stdout.decode('utf-8'))['checks']
            rendered = dict(line.split() for line in human.stdout.decode('utf-8').splitlines()
                            if len(line.split()) == 2 and line.split()[0] in aliases)
            for label, key in aliases.items():
                self.assertEqual(rendered[label], checks[key]['status'])

    def test_receipt_access_error_has_tool_exit(self):
        with patch.object(awr, '_read_bytes', side_effect=PermissionError('synthetic receipt denial')):
            r = awr.verify(self.path)
        self.assertEqual(r['exit_code'], 3)
        self.assertEqual(r['checks']['RECEIPT_STRUCTURE']['status'], 'TOOL_ERROR')

    def test_relative_and_deep_paths_with_actual_present_objects(self):
        relative = os.path.relpath(ROOT / 'examples/accepted/receipt.json', ROOT)
        p = subprocess.run([sys.executable, '-I', '-S', '-B', 'verifier/verify.py', relative, '--json'],
                           cwd=ROOT, capture_output=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        deep = Path(self.tmp.name)
        while len(str(deep / 'objects' / ('f' * 64))) < 310:
            deep /= 'deep-path-segment'
        if not deep.resolve().is_relative_to(Path(self.tmp.name).resolve()):
            self.fail('Deep-path fixture escaped its temporary workspace')
        destination = Path('\\\\?\\' + str(deep)) if os.name == 'nt' else deep
        shutil.copytree(self.package, destination)
        self.addCleanup(shutil.rmtree, destination)
        result = awr.verify(deep / 'receipt.json')
        self.assertEqual(result['exit_code'], 0, result)
        self.assertEqual(result['checks']['OBJECT_INTEGRITY']['status'], 'VERIFIED')
        self.assertGreater(len(str(deep / 'objects' / ('f' * 64))), 260)

    def test_external_digest_accepts_uppercase_hex(self):
        self.assertEqual(awr.verify(self.path, self.receipt['integrity']['digest'].upper())['exit_code'], 0)

    def test_verifier_version_and_json_format_version(self):
        command = [sys.executable, '-I', '-S', '-B', str(ROOT / 'verifier/verify.py')]
        p = subprocess.run(command + ['--version'], capture_output=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.decode('utf-8').strip(), 'AI Work Receipt verifier 0.1.0')
        p = subprocess.run(command + [str(self.path), '--json'], capture_output=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        result = json.loads(p.stdout.decode('utf-8'))
        self.assertEqual(result['format_version'], '0.1')
        self.assertEqual(result['verifier_version'], '0.1.0')

    def test_windows_reported_path_error_is_not_missing(self):
        blocked = self.receipt['changes'][0]['after']['sha256']
        original = awr._read_bytes
        def read(path):
            if path.name == blocked:
                error = FileNotFoundError('synthetic Windows path error')
                error.winerror = 206
                raise error
            return original(path)
        with patch.object(awr, '_read_bytes', side_effect=read):
            result = awr.verify(self.path)
        self.assertEqual(result['exit_code'], 3)
        self.assertEqual(result['checks']['OBJECT_INTEGRITY']['status'], 'ACCESS_ERROR')

    def test_independence_in_copied_packet_with_file_and_network_audit(self):
        isolated = Path(self.tmp.name) / 'independent'
        for directory in ('verifier', 'spec', 'examples'):
            shutil.copytree(ROOT / directory, isolated / directory)
        # -I -S excludes PYTHONPATH, user site and third-party site initialization.
        # The audit hook allows file opens only in this packet or the local Python
        # runtime, and rejects any socket operation. No source workspace is read.
        runner = r"""
import os, sys, runpy
packet = os.path.realpath(sys.argv[1])
allowed = [packet, os.path.realpath(sys.base_prefix)]
def audit(event, args):
    if event.startswith('socket.'):
        raise RuntimeError('Network operation forbidden')
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        p = os.path.normcase(os.path.realpath(os.fsdecode(args[0])))
        if not any(os.path.commonpath([p, os.path.normcase(base)]) == os.path.normcase(base) for base in allowed):
            raise RuntimeError('Read outside standalone packet/runtime: ' + p)
sys.addaudithook(audit)
for family in ('accepted', 'honest-failure'):
    sys.argv = [os.path.join(packet, 'verifier', 'verify.py'), os.path.join(packet, 'examples', family, 'receipt.json'), '--json']
    try:
        runpy.run_path(sys.argv[0], run_name='__main__')
    except SystemExit as e:
        if e.code != 0:
            raise
print('INDEPENDENCE VERIFIED: copied packet, isolated runtime, file-open and socket audit')
"""
        env = dict(os.environ)
        env.pop('PYTHONPATH', None)
        env.pop('PYTHONHOME', None)
        p = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', runner, str(isolated)],
                           cwd=isolated, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('INDEPENDENCE VERIFIED', p.stdout)


if __name__ == '__main__':
    unittest.main()
