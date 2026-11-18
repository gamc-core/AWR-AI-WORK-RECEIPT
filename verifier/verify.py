"""Offline checks of recorded work. Standard library only; no authenticity claims."""
import argparse
import copy
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sys

FORMAT_VERSION = '0.1'
VERIFIER_VERSION = '0.1.0'

CATEGORIES = (
    'RECEIPT_STRUCTURE', 'RECEIPT_INTEGRITY', 'OBJECT_INTEGRITY',
    'CHANGE_EVIDENCE', 'AUTHORIZATION_DOCUMENTATION', 'EXECUTOR_CLAIM',
    'VALIDATION_EVIDENCE', 'FAILURE_COMPARISON', 'DISPOSITION', 'LIMITATIONS',
)
SHA = re.compile(r'^[0-9a-f]{64}$')
MAX_INT = 9007199254740991


class ContractError(ValueError):
    pass


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def _reject_number(value):
    raise ContractError('non-integer JSON number: ' + value)


def _json_domain(value):
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > MAX_INT:
            raise ContractError('integer outside exact v0.1 range')
    elif type(value) is str:
        value.encode('utf-8', errors='strict')
    elif type(value) is list:
        for item in value:
            _json_domain(item)
    elif type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                raise ContractError('JSON key must be a string')
            _json_domain(key)
            _json_domain(child)
    else:
        raise ContractError('unsupported JSON value')


def parse_json(data):
    # Strict UTF-8: no BOM, duplicate keys, floats, NaN, infinity or lone surrogates.
    value = json.loads(data.decode('utf-8'), object_pairs_hook=_pairs,
                       parse_float=_reject_number, parse_constant=_reject_number)
    _json_domain(value)
    return value


def canonical_bytes(value):
    _json_domain(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def receipt_digest(receipt):
    body = copy.deepcopy(receipt)
    body['integrity'].pop('digest', None)
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def seal(receipt):
    result = copy.deepcopy(receipt)
    result['integrity']['digest'] = receipt_digest(result)
    return result


def _schema_check(value, schema, document, where='$'):
    """Validate only the fixed keyword subset used by our bundled schema.

    This is not a general JSON Schema implementation. Unsupported keywords fail
    closed so a future spec edit cannot silently disable structural checks.
    """
    known = {'$schema', '$id', 'title', 'description', '$defs', '$ref', 'type',
             'properties', 'required', 'additionalProperties', 'enum', 'const',
             'anyOf', 'oneOf', 'items', 'minItems', 'uniqueItems', 'minLength',
             'pattern', 'minimum', 'maximum'}
    if set(schema) - known:
        raise ContractError('unsupported schema keyword')
    if '$ref' in schema:
        prefix = '#/$defs/'
        if not schema['$ref'].startswith(prefix):
            raise ContractError('only local definition references are allowed')
        return _schema_check(value, document['$defs'][schema['$ref'][len(prefix):]], document, where)
    for key in ('anyOf', 'oneOf'):
        if key in schema:
            matched = 0
            for branch in schema[key]:
                try:
                    _schema_check(value, branch, document, where)
                    matched += 1
                except ContractError:
                    pass
            if (key == 'oneOf' and matched != 1) or (key == 'anyOf' and matched == 0):
                raise ContractError(where + ': no unambiguous matching shape')
    if 'const' in schema and (type(value) is not type(schema['const']) or value != schema['const']):
        raise ContractError(where + ': incorrect constant')
    if 'enum' in schema and not any(type(value) is type(v) and value == v for v in schema['enum']):
        raise ContractError(where + ': invalid enum')
    typ = schema.get('type')
    types = {'object': dict, 'array': list, 'string': str, 'integer': int,
             'null': type(None), 'boolean': bool}
    if typ and type(value) is not types[typ]:
        raise ContractError(where + ': expected ' + typ)
    if typ == 'object':
        missing = set(schema.get('required', [])) - set(value)
        extra = set(value) - set(schema.get('properties', {}))
        if missing or (extra and schema.get('additionalProperties') is False):
            raise ContractError(where + ': missing or unknown fields ' + str(sorted(missing | extra)))
        for key, child in value.items():
            if key in schema.get('properties', {}):
                _schema_check(child, schema['properties'][key], document, where + '.' + key)
    elif typ == 'array':
        if len(value) < schema.get('minItems', 0):
            raise ContractError(where + ': too few items')
        if schema.get('uniqueItems') and len({canonical_bytes(v) for v in value}) != len(value):
            raise ContractError(where + ': duplicate items')
        for item in value:
            _schema_check(item, schema['items'], document, where + '[]')
    elif typ == 'string':
        if len(value) < schema.get('minLength', 0) or ('pattern' in schema and not re.fullmatch(schema['pattern'], value)):
            raise ContractError(where + ': invalid string')
    elif typ == 'integer':
        if value < schema.get('minimum', -MAX_INT) or value > schema.get('maximum', MAX_INT):
            raise ContractError(where + ': integer outside bounds')


def _semantic_structure(receipt):
    ids = [e['id'] for e in receipt['evidence']]
    targets = [c['target'] for c in receipt['changes']]
    if len(ids) != len(set(ids)) or len(targets) != len(set(targets)):
        raise ContractError('duplicate evidence id or change target')
    datetime.fromisoformat(receipt['recorded_at'].replace('Z', '+00:00'))
    def walk(value):
        if type(value) is dict:
            if set(value) == {'value', 'classification', 'evidence_reference'}:
                if (value['classification'] == 'UNKNOWN') != (value['value'] is None):
                    raise ContractError('UNKNOWN claims must have null value; other claims need a value')
                if value['classification'] == 'VERIFIED' and value['evidence_reference'] is None:
                    raise ContractError('VERIFIED claim requires an evidence reference')
            if value.get('evidence_reference') is not None and value['evidence_reference'] not in ids:
                raise ContractError('dangling evidence reference')
            for child in value.values():
                walk(child)
        elif type(value) is list:
            for child in value:
                walk(child)
    walk(receipt)
    for ref in [receipt['authorization']['work_binding'], *receipt['validation'].values()]:
        if ref is not None and ref not in ids:
            raise ContractError('dangling binding or validation reference')
    if receipt['validation']['baseline'] is not None and receipt['validation']['baseline'] == receipt['validation']['current']:
        raise ContractError('baseline and current must be distinct records')
    if receipt['validation']['baseline'] is not None and receipt['validation']['current'] is None:
        raise ContractError('baseline without current validation')
    for rel in receipt['relations']:
        if rel['target_work_id'] != receipt['work_id']:
            raise ContractError('v0.1 correction must refer to the represented work')


def _delta(before, after):
    prefix = 0
    while prefix < min(len(before), len(after)) and before[prefix] == after[prefix]:
        prefix += 1
    suffix = 0
    while suffix < min(len(before), len(after)) - prefix and before[-suffix-1] == after[-suffix-1]:
        suffix += 1
    old = before[prefix:len(before)-suffix if suffix else len(before)]
    new = after[prefix:len(after)-suffix if suffix else len(after)]
    return {'equal': before == after, 'offset': prefix, 'removed_bytes': len(old),
            'added_bytes': len(new), 'removed_hex': old[:64].hex(), 'added_hex': new[:64].hex(),
            'preview_complete': max(len(old), len(new)) <= 64}



def _read_bytes(path):
    # Windows extended paths avoid the legacy MAX_PATH limit without changing
    # registry settings. No object bytes or path components are normalized.
    name = str(path)
    if os.name == 'nt' and len(name) >= 240 and not name.startswith('\\\\?\\'):
        name = ('\\\\?\\UNC\\' + name[2:]) if name.startswith('\\\\') else '\\\\?\\' + name
    return Path(name).read_bytes()

def verify(receipt_path, expected_digest=None):
    report = {'format_version': FORMAT_VERSION, 'verifier_version': VERIFIER_VERSION, 'receipt_id': None, 'checks': {k: {'status': 'UNKNOWN', 'detail': 'Not evaluated'} for k in CATEGORIES},
              'identity_authenticated': False, 'causality_proven': False, 'exit_code': 0}
    def put(name, status, detail):
        report['checks'][name] = {'status': status, 'detail': detail}
    try:
        path = Path(receipt_path).resolve()
        receipt = parse_json(_read_bytes(path))
        schema_path = Path(__file__).resolve().parent.parent / 'spec' / 'receipt.schema.json'
        schema = parse_json(_read_bytes(schema_path))
        _schema_check(receipt, schema, schema)
        _semantic_structure(receipt)
        report['receipt_id'] = receipt['receipt_id']
        put('RECEIPT_STRUCTURE', 'VERIFIED', 'v0.1 structure and reference consistency')
    except OSError as error:
        put('RECEIPT_STRUCTURE', 'TOOL_ERROR', str(error))
        report['exit_code'] = 3
        return report
    except (ValueError, UnicodeError, KeyError, RecursionError) as error:
        put('RECEIPT_STRUCTURE', 'MISMATCH', str(error))
        report['exit_code'] = 2
        return report
    actual = receipt_digest(receipt)
    report['computed_digest'] = actual
    anchored = expected_digest is not None
    if expected_digest is not None:
        expected_digest = expected_digest.lower()
    if expected_digest is not None and not SHA.fullmatch(expected_digest):
        put('RECEIPT_INTEGRITY', 'MISMATCH', 'Invalid external expected digest')
    elif actual != receipt['integrity']['digest'] or (anchored and actual != expected_digest):
        put('RECEIPT_INTEGRITY', 'MISMATCH', 'Receipt or external digest does not match')
    else:
        put('RECEIPT_INTEGRITY', 'VERIFIED', 'Canonical digest matches' + (' external expected digest' if anchored else '; no independent authenticity anchor'))
    if report['checks']['RECEIPT_INTEGRITY']['status'] != 'VERIFIED':
        report['exit_code'] = 2
        return report

    # Every lookup is the digest filename inside the package's own objects directory.
    objects_root = path.parent / 'objects'
    cache = {}
    object_results = []
    def object_bytes(desc, label, record=False):
        if desc['state'] != 'OBJECT':
            return None
        sha = desc['sha256']
        if sha in cache:
            data, status, access_detail = cache[sha]
        else:
            data = None
            access_detail = None
            try:
                candidate = objects_root / sha
                candidate.resolve().relative_to(objects_root.resolve())
                data = _read_bytes(candidate)
                status = 'VERIFIED' if hashlib.sha256(data).hexdigest() == sha else 'MISMATCH'
            except FileNotFoundError as error:
                # Some Windows APIs report a long-path failure as ENOENT.
                # Extended-path reads should remove that ambiguity. An explicit
                # invalid/too-long name still is an access error, not absence.
                status = 'ACCESS_ERROR' if getattr(error, 'winerror', None) == 206 else 'MISSING'
                access_detail = str(error)
            except OSError as error:
                status = 'ACCESS_ERROR'
                access_detail = str(error)
            except ValueError:
                status = 'MISMATCH'
                access_detail = 'Object path escapes the objects directory'
            cache[sha] = (data, status, access_detail)
        if status == 'VERIFIED' and len(data) != desc['size_bytes']:
            status = 'MISMATCH'
        if record:
            item = {'reference': label, 'sha256': sha, 'status': status}
            if access_detail is not None:
                item['detail'] = access_detail
            object_results.append(item)
        return data if status == 'VERIFIED' else None
    evidence = {e['id']: e for e in receipt['evidence']}
    for e in receipt['evidence']:
        object_bytes(e['object'], e['id'], record=True)
    for change in receipt['changes']:
        for phase in ('before', 'after'):
            object_bytes(change[phase], change['target'] + ':' + phase, record=True)
    statuses = {r['status'] for r in object_results}
    gaps = any(d['state'] != 'OBJECT' for d in [e['object'] for e in receipt['evidence']])
    object_status = 'ACCESS_ERROR' if 'ACCESS_ERROR' in statuses else 'MISMATCH' if 'MISMATCH' in statuses else 'MISSING' if 'MISSING' in statuses else 'PARTIAL' if gaps else 'VERIFIED'
    put('OBJECT_INTEGRITY', object_status, object_results)
    if object_status in ('ACCESS_ERROR', 'MISSING', 'MISMATCH'):
        report['exit_code'] = {'ACCESS_ERROR': 3, 'MISMATCH': 2, 'MISSING': 1}[object_status]

    def document(ref, kind):
        if ref is None:
            return None
        e = evidence[ref]
        if e['kind'] != kind:
            raise ContractError('wrong evidence kind for ' + ref)
        b = object_bytes(e['object'], ref)
        return parse_json(b) if b is not None else None
    def record_shape(doc, required):
        if type(doc) is not dict or set(doc) != set(required):
            raise ContractError('invalid evidence document fields')
    def bound(doc):
        if doc['work_id'] != receipt['work_id']:
            raise ContractError('evidence document bound to another work')

    try:
        changes = []
        for c in receipt['changes']:
            before, after = object_bytes(c['before'], c['target']), object_bytes(c['after'], c['target'])
            entry = {'target': c['target'], 'before': c['before']['state'], 'after': c['after']['state']}
            if before is not None and after is not None:
                entry.update(status='VERIFIED', byte_delta=_delta(before, after))
            elif c['before']['state'] == 'ABSENT':
                d = document(c['before']['evidence_reference'], 'OBSERVATION')
                if d is not None:
                    record_shape(d, ('work_id', 'target', 'phase', 'state'))
                    bound(d)
                    if (d['target'], d['phase'], d['state']) != (c['target'], 'before', 'ABSENT'):
                        raise ContractError('absence observation does not match BEFORE')
                entry.update(status='PARTIAL', note='Documented absence, not an empty before object; after bytes ' + ('match' if after is not None else 'unavailable'))
            else:
                entry.update(status='UNKNOWN', note='No complete BEFORE/AFTER byte comparison')
            changes.append(entry)
        put('CHANGE_EVIDENCE', 'VERIFIED' if all(c['status'] == 'VERIFIED' for c in changes) else 'PARTIAL', changes)

        auth = receipt['authorization']
        human = auth['human_act']
        act_bytes = None
        if human['evidence_reference']:
            e = evidence[human['evidence_reference']]
            if e['kind'] != 'HUMAN_ACT':
                raise ContractError('human act references wrong kind')
            act_bytes = object_bytes(e['object'], e['id'])
            if act_bytes is not None and act_bytes.decode('utf-8') != human['value']:
                raise ContractError('human act bytes disagree with claim')
        binding = document(auth['work_binding'], 'AUTHORIZATION_BINDING')
        if binding is not None:
            record_shape(binding, ('work_id', 'scope', 'human_act_sha256', 'targets', 'representation'))
            bound(binding)
            if binding['human_act_sha256'] is not None and (type(binding['human_act_sha256']) is not str or not SHA.fullmatch(binding['human_act_sha256'])):
                raise ContractError('invalid human act digest in binding')
            if binding['scope'] != auth['scope']['value']:
                raise ContractError('authorization scope differs from binding')
            expected_targets = [{'target': c['target'], 'before_sha256': c['before']['sha256'], 'after_sha256': c['after']['sha256']} for c in receipt['changes']]
            if binding['targets'] != expected_targets or binding['representation'] not in ('DERIVED_EXAMPLE', 'DOCUMENTED_WORK'):
                raise ContractError('authorization work binding does not match represented changes')
            if act_bytes is not None and binding['human_act_sha256'] != hashlib.sha256(act_bytes).hexdigest():
                raise ContractError('authorization binding disagrees with supplied human act')
        put('AUTHORIZATION_DOCUMENTATION', 'CONSISTENT' if act_bytes is not None and binding is not None else 'PARTIAL' if binding is not None or act_bytes is not None else 'UNKNOWN',
            {'approval_text': human['value'], 'human_act_bytes_match': act_bytes is not None, 'work_binding_documented': binding is not None,
             'scope_claim': auth['scope'], 'identity': 'UNKNOWN', 'authority': 'UNKNOWN' if auth['scope']['classification'] == 'UNKNOWN' else 'DECLARED',
             'meaning': 'The text and work references agree; this does not establish approval, identity or authority'})

        put('EXECUTOR_CLAIM', 'UNKNOWN' if receipt['executor']['classification'] == 'UNKNOWN' else 'RECORDED',
            {'executor': receipt['executor'], 'model': receipt['executor_model'], 'authentication': 'UNKNOWN'})

        def validation(ref):
            d = document(ref, 'VALIDATION')
            if d is None:
                return None
            record_shape(d, ('work_id', 'scope', 'method', 'environment', 'subject_sha256', 'subject_role', 'phase', 'test_ids_run', 'failing_test_ids', 'outcome'))
            bound(d)
            for key in ('scope', 'method', 'environment', 'outcome'):
                if type(d[key]) is not str or not d[key]:
                    raise ContractError('invalid validation ' + key)
            if not isinstance(d['subject_sha256'], str) or not SHA.fullmatch(d['subject_sha256']) or d['subject_role'] not in ('HISTORICAL_ORIGINAL', 'DOCUMENTED_WORK'):
                raise ContractError('invalid validation subject')
            for key in ('test_ids_run', 'failing_test_ids'):
                ids = d[key]
                if ids is not None and (type(ids) is not list or any(type(i) is not str or not i for i in ids) or len(ids) != len(set(ids))):
                    raise ContractError('invalid validation test identities')
            if d['failing_test_ids'] is not None and (d['test_ids_run'] is None or not set(d['failing_test_ids']) <= set(d['test_ids_run'])):
                raise ContractError('failures outside recorded test population')
            return d
        current, baseline = validation(receipt['validation']['current']), validation(receipt['validation']['baseline'])
        if (current is not None and current['phase'] != 'AFTER') or (baseline is not None and baseline['phase'] != 'BEFORE'):
            raise ContractError('validation phase does not match reference role')
        for d, phase in ((current, 'after'), (baseline, 'before')):
            if d is not None and d['subject_role'] == 'DOCUMENTED_WORK' and d['subject_sha256'] not in {c[phase]['sha256'] for c in receipt['changes']}:
                raise ContractError('validation subject differs from represented phase')
        put('VALIDATION_EVIDENCE', 'CONSISTENT' if current is not None else 'MISSING',
            {'current': current, 'baseline': baseline, 'meaning': 'Records checked, tests not rerun; historical validation does not validate derived bytes'})
        comparable = current is not None and baseline is not None
        if comparable:
            keys = ('work_id', 'scope', 'method', 'environment', 'subject_role')
            comparable = all(current[k] == baseline[k] for k in keys)
            comparable = comparable and all(d['test_ids_run'] is not None and d['failing_test_ids'] is not None for d in (current, baseline))
            comparable = comparable and bool(baseline['test_ids_run']) and set(baseline['test_ids_run']) <= set(current['test_ids_run'])
        if comparable:
            old, new = set(baseline['failing_test_ids']), set(current['failing_test_ids'])
            put('FAILURE_COMPARISON', 'VERIFIED', {'new': sorted(new-old), 'persisting': sorted(new & old), 'resolved': sorted(old-new), 'causality': 'UNKNOWN'})
        else:
            put('FAILURE_COMPARISON', 'UNKNOWN', 'No comparable documented baseline; no failure attribution')

        disposition = receipt['disposition']
        d = document(disposition['evidence_reference'], 'DISPOSITION')
        if d is not None:
            record_shape(d, ('work_id', 'decision', 'scope', 'actor'))
            bound(d)
            if d['decision'] != disposition['value'] or type(d['scope']) is not str or not d['scope'] or type(d['actor']) is not str or not d['actor']:
                raise ContractError('disposition documentation does not match')
        put('DISPOSITION', 'UNKNOWN' if disposition['classification'] == 'UNKNOWN' else 'CONSISTENT' if d is not None else 'PARTIAL',
            {'claim': disposition, 'record': d, 'meaning': 'Recorded decision, not authenticated authority or acceptance inferred from validation'})
        for relation in receipt['relations']:
            d = document(relation['evidence_reference'], 'CORRECTION')
            if d is None:
                put('CHANGE_EVIDENCE', 'PARTIAL', {'changes': changes, 'correction': 'MISSING'})
            else:
                record_shape(d, ('work_id', 'type', 'prior_record_modified', 'sequence', 'raw_secured_before_removal', 'record_completed_before_removal'))
                bound(d)
                if d['type'] != 'ADDITIVE_CORRECTION' or d['prior_record_modified'] is not False or type(d['sequence']) is not list or any(type(x) is not str for x in d['sequence']) or type(d['raw_secured_before_removal']) is not bool or type(d['record_completed_before_removal']) is not bool:
                    raise ContractError('invalid additive correction document')
                report.setdefault('relations', []).append({'classification': 'DECLARED', 'record': d})
        put('LIMITATIONS', 'RECORDED', receipt['limitations'] + [
            'Document integrity is not human authentication.',
            'An execution record does not prove that execution happened.',
            'A new failure does not establish causality.',
            'Preserved does not mean current.',
            'A self-consistent package can be fabricated or resealed; an independently held digest is needed to detect that replacement.',
        ])
    except (ValueError, UnicodeError, KeyError, TypeError, RecursionError) as error:
        put('RECEIPT_STRUCTURE', 'MISMATCH', 'Evidence semantic contract: ' + str(error))
        report['exit_code'] = 3 if report['exit_code'] == 3 else 2
    return report



def render_human(result):
    """Present outcomes and boundaries alongside check states, without JSON walls."""
    aliases = {'CHANGE_EVIDENCE': 'CHANGE_RECORD',
               'AUTHORIZATION_DOCUMENTATION': 'APPROVAL_RECORD',
               'EXECUTOR_CLAIM': 'EXECUTOR', 'VALIDATION_EVIDENCE': 'VALIDATION_RECORD',
               'DISPOSITION': 'DISPOSITION_RECORD'}
    lines = ['AI Work Receipt v0.1 | ' + (result['receipt_id'] or 'unreadable receipt')]
    checks = result['checks']
    for name, check in checks.items():
        lines.append(aliases.get(name, name).ljust(23) + check['status'])
        if check['status'] in ('MISMATCH', 'TOOL_ERROR', 'ACCESS_ERROR', 'MISSING') and isinstance(check['detail'], str):
            lines.append('  ' + str(check['detail']))
    def detail(name):
        d = checks[name]['detail']
        return d if isinstance(d, dict) else {}
    objects = checks['OBJECT_INTEGRITY']['detail']
    if isinstance(objects, list):
        for obj in objects:
            if obj['status'] in ('MISSING', 'MISMATCH', 'ACCESS_ERROR'):
                lines.append('Object ' + obj['reference'] + ': ' + obj['status'])
                if obj.get('detail'):
                    lines.append('  ' + obj['detail'])
    auth = detail('AUTHORIZATION_DOCUMENTATION')
    if auth:
        text = auth.get('approval_text')
        lines.append('Approval text: ' + (json.dumps(text, ensure_ascii=False) if text is not None else 'not supplied'))
        scope = auth.get('scope_claim')
        if scope and scope['value'] is not None:
            lines.append('Authorization scope recorded (' + scope['classification'] + '): ' + scope['value'])
        if checks['AUTHORIZATION_DOCUMENTATION']['status'] == 'PARTIAL':
            lines.append('  PARTIAL means incomplete documentation, not partial approval.')
        lines.append('  Text matching is not an approval decision or an authenticated identity.')
    validation = detail('VALIDATION_EVIDENCE').get('current')
    if validation:
        lines.append('Validation outcome recorded: ' + validation['outcome'])
        lines.append('  Tests were not rerun; subject: ' + validation['subject_role'])
    disposition = detail('DISPOSITION').get('record')
    if disposition:
        lines.append('Decision recorded: ' + disposition['decision'])
        lines.append('  Scope: ' + disposition['scope'])
    executor = detail('EXECUTOR_CLAIM')
    if executor:
        lines.append('Executor recorded: ' + (executor['executor']['value'] or 'UNKNOWN'))
        lines.append('Executor model: ' + (executor['model']['value'] or 'UNKNOWN'))
    changes = checks['CHANGE_EVIDENCE']['detail']
    if isinstance(changes, dict):
        changes = changes.get('changes', [])
    if isinstance(changes, list):
        for change in changes:
            lines.append('Change: ' + change['target'] + ' | BEFORE ' + change['before'] + ' | AFTER ' + change['after'])
            delta = change.get('byte_delta')
            if delta:
                lines.append('  Byte comparison: offset {offset}, removed {removed_bytes}, added {added_bytes}'.format(**delta))
    failures = detail('FAILURE_COMPARISON')
    if failures:
        for label in ('new', 'persisting', 'resolved'):
            lines.append('Failures ' + label + ': ' + ', '.join(failures[label]))
        lines.append('  Recorded sets compared; failure causality remains UNKNOWN.')
    for relation in result.get('relations', []):
        lines.append('Later note records (DECLARED):')
        lines.extend('  ' + item for item in relation['record']['sequence'])
        lines.append('  The first record was not rewritten.')
    limits = checks['LIMITATIONS']['detail']
    if isinstance(limits, list):
        lines.append('Limitations recorded:')
        lines.extend('  - ' + item for item in limits)
    lines.extend([
        'VERIFIED: recomputed or checked. CONSISTENT: supplied records agree.',
        'RECORDED: reported, not authenticated. UNKNOWN: not established here.',
        'Identity authentication: UNKNOWN | Failure causality: UNKNOWN',
        'Exit ' + str(result['exit_code']) + ': 0=no required integrity defect; 1=missing OBJECT; 2=mismatch/invalid; 3=tool/access/output error.',
    ])
    return '\n'.join(lines)


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='strict', newline='\n')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version='AI Work Receipt verifier ' + VERIFIER_VERSION)
    parser.add_argument('receipt', type=Path)
    parser.add_argument('--json', action='store_true', help='machine-readable result')
    parser.add_argument('--expected-digest', help='independently held canonical receipt digest')
    args = parser.parse_args(argv)
    result = verify(args.receipt, args.expected_digest)
    try:
        print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else render_human(result))
        sys.stdout.flush()
    except (OSError, UnicodeError):
        # Prevent another buffered stdout flush at interpreter shutdown from
        # replacing exit 3 with CPython's exit 120 after a closed-pipe error.
        try:
            stdout_fd = sys.stdout.fileno()
            null_fd = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(null_fd, stdout_fd)
            finally:
                os.close(null_fd)
        except (AttributeError, OSError, ValueError):
            pass
        # Exit 1 is exclusively an evidence condition, never an output failure.
        try:
            sys.stderr.write('TOOL_ERROR: could not write UTF-8 output\n')
        except (OSError, UnicodeError):
            pass
        return 3
    return result['exit_code']


if __name__ == '__main__':
    sys.exit(main())
