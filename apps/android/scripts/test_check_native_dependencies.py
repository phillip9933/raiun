#!/usr/bin/env python3
"""Disconnected regressions for native inventory/provenance/advisory checks."""
import json
import struct
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import check_native_dependencies as checker


class NativeCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.apk = self.root / 'app.apk'
        self.aar = self.root / 'library.aar'
        self.inventory = self.root / 'inventory.json'
        self.pins = self.root / 'pins'
        self.entry = 'lib/arm64-v8a/libtest.so'
        self.source = 'jni/arm64-v8a/libtest.so'
        self.write_zip(self.apk, {self.entry: b'original native payload'})
        self.write_zip(self.aar, {self.source: b'original native payload'})
        self.artifact_hash = checker.digest(self.aar.read_bytes())
        self.pins.write_text(self.artifact_hash + '  example:library:1.0\n')
        self.data = {
            'schema_version': 1, 'evidence_files': {},
            'artifacts': {'example:library:1.0': {'sha256': self.artifact_hash}},
            'components': {'test': {'version': '1.0', 'source_tag': 'v1.0',
                'artifacts': ['example:library:1.0'], 'evidence': ['https://example.org/source'],
                'coverage_gap': 'Only declared source, not complete transitive coverage',
                'osv_query': {'package': {'ecosystem': 'GIT', 'name': 'https://example.org/source.git'}, 'version': 'v1.0'}}},
            'libraries': [{'apk_entry': self.entry, 'source_entry': self.source,
                'sha256': checker.digest(b'original native payload'), 'artifact': 'example:library:1.0', 'components': ['test']}],
            'review_findings': []}

    def write_zip(self, path, members):
        with zipfile.ZipFile(path, 'w') as archive:
            for key, value in members.items():
                archive.writestr(key, value)

    def run_check(self, scan=False):
        self.inventory.write_text(json.dumps(self.data))
        return checker.run(self.inventory, self.pins, self.apk, [self.root], scan)

    def test_exact_bytes_bind_apk_artifact_and_pin(self):
        result = self.run_check()
        self.assertEqual('verified', result['integrity']['status'])
        self.assertEqual(checker.digest(self.apk.read_bytes()), result['integrity']['apk_sha256'])
        self.assertEqual('bounded_check_complete_with_coverage_gaps', result['status'])

    def test_missing_library(self):
        self.write_zip(self.apk, {})
        self.assertIn('missing=', self.run_check()['error'])

    def test_unexpected_library_including_other_abi(self):
        self.write_zip(self.apk, {self.entry:b'original native payload', 'lib/armeabi-v7a/libnew.so':b'new'})
        self.assertIn('unexpected=', self.run_check()['error'])

    def test_changed_library(self):
        self.write_zip(self.apk, {self.entry:b'changed'})
        self.assertIn('SHA-256 mismatch', self.run_check()['error'])

    def test_corrupt_deflate_member_reports_unavailable(self):
        with zipfile.ZipFile(self.apk, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(self.entry, b'original native payload')
        raw = bytearray(self.apk.read_bytes())
        name_length, extra_length = struct.unpack_from('<HH', raw, 26)
        payload = 30 + name_length + extra_length
        # BFINAL=1, BTYPE=3: an invalid DEFLATE block type, not merely a CRC mismatch.
        raw[payload] = (raw[payload] & ~7) | 7
        self.apk.write_bytes(raw)
        result = self.run_check()
        self.assertEqual('unavailable', result['status'])
        self.assertIn('could not be decompressed', result['error'])

    def test_unsupported_native_compression_reports_unavailable(self):
        with zipfile.ZipFile(self.apk, 'w', compression=zipfile.ZIP_BZIP2) as archive:
            archive.writestr(self.entry, b'original native payload')
        result = self.run_check()
        self.assertEqual('unavailable', result['status'])
        self.assertIn('unsupported native ZIP compression', result['error'])

    def test_duplicate_native_entry(self):
        with zipfile.ZipFile(self.apk, 'a') as archive:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                archive.writestr(self.entry,b'duplicate')
        self.assertIn('duplicate native ZIP', self.run_check()['error'])

    def test_missing_artifact_not_inferred_from_filename(self):
        self.aar.unlink()
        self.assertIn('missing pinned AAR', self.run_check()['error'])

    def test_artifact_bytes_must_match_pin(self):
        self.write_zip(self.aar, {self.source:b'changed'})
        self.assertIn('missing pinned AAR', self.run_check()['error'])

    def test_source_library_must_match_apk_even_with_valid_artifact_pin(self):
        self.write_zip(self.aar, {self.source:b'changed'})
        sha = checker.digest(self.aar.read_bytes())
        self.data['artifacts']['example:library:1.0']['sha256'] = sha
        self.pins.write_text(sha+'  example:library:1.0\n')
        self.assertIn('AAR/APK native provenance mismatch', self.run_check()['error'])

    def test_pin_change_requires_provenance_update(self):
        self.pins.write_text('0'*64+'  example:library:1.0\n')
        self.assertIn('pin mismatch', self.run_check()['error'])

    def test_version_change_requires_source_identity_update(self):
        self.data['components']['test']['version'] = '2.0'
        self.assertIn('version/tag mismatch', self.run_check()['error'])

    def test_missing_component_provenance(self):
        self.data['components']['test']['evidence'] = []
        self.assertIn('missing provenance', self.run_check()['error'])

    def test_source_manifest_hash_mismatch(self):
        self.data['evidence_files']['source.json'] = '0'*64
        (self.root/'source.json').write_text('{}')
        self.assertIn('source evidence hash mismatch', self.run_check()['error'])

    def test_missing_source_evidence_file(self):
        self.data['evidence_files']['missing.json'] = '0'*64
        self.assertEqual('unavailable', self.run_check()['status'])

    def test_source_evidence_path_traversal(self):
        self.data['evidence_files']['../source.json'] = '0'*64
        self.assertIn('invalid native evidence record', self.run_check()['error'])

    def test_malformed_root_and_component_objects(self):
        for malformed in [[], None, 'invalid', {'schema_version':1, 'evidence_files':[]}]:
            with self.subTest(malformed=malformed):
                self.inventory.write_text(json.dumps(malformed))
                self.assertEqual('unavailable', checker.run(self.inventory,self.pins)['status'])
        self.data['components']['test'] = []
        self.assertEqual('unavailable',self.run_check()['status'])

    def test_native_zip_size_limit(self):
        with patch.object(checker, 'MAX_LIBRARY', 4):
            self.assertIn('size limit',self.run_check()['error'])

    def test_pagination_limit_is_not_a_complete_scan(self):
        reply = {'results':[{'next_page_token':'again'}]}
        with patch.object(checker.osv,'_post_queries',return_value=reply):
            self.assertIn('pagination exceeded',self.run_check(scan=True)['error'])

    def test_unsupported_cpe_not_sent_as_osv_ecosystem(self):
        self.data['components']['test']['osv_query']['package']['ecosystem'] = 'CPE'
        self.assertIn('invalid native query identity', self.run_check()['error'])

    def test_failed_response_is_unavailable(self):
        with patch.object(checker.osv, '_post_queries', side_effect=checker.osv.CheckUnavailable('OSV request failed')):
            result = self.run_check(scan=True)
        self.assertEqual('unavailable', result['status'])
        self.assertEqual('verified', result['integrity']['status'])
        self.assertEqual('unavailable', result['advisories']['status'])

    def test_malformed_response_is_unavailable(self):
        with patch.object(checker.osv, '_post_queries', return_value={'results':[{'error':'bad'}]}):
            self.assertEqual('unavailable', self.run_check(scan=True)['status'])

    def test_advisories_and_pagination_retained(self):
        replies = [{'results':[{'vulns':[{'id':'CVE-TEST-1'}], 'next_page_token':'next'}]}, {'results':[{'vulns':[{'id':'CVE-TEST-2'}]}]}]
        with patch.object(checker.osv, '_post_queries', side_effect=replies) as post:
            result = self.run_check(scan=True)
        self.assertEqual('attention_required', result['status'])
        self.assertEqual(['CVE-TEST-1','CVE-TEST-2'], result['advisories']['matches']['test'])
        self.assertEqual('next', post.call_args.args[0][0]['page_token'])

    def test_no_matches_still_reports_coverage_gaps(self):
        with patch.object(checker.osv, '_post_queries', return_value={'results':[{}]}):
            result = self.run_check(scan=True)
        self.assertEqual('bounded_check_complete_with_coverage_gaps', result['status'])
        self.assertIn('test',result['coverage_gaps'])
        self.assertEqual('no_matches_in_queried_sources',result['advisories']['status'])

    def test_manual_finding_not_hidden_by_empty_osv_result(self):
        self.data['review_findings'] = [{'id':'CVE-TEST-1','component':'test'}]
        with patch.object(checker.osv, '_post_queries', return_value={'results':[{}]}):
            result = self.run_check(scan=True)
        self.assertEqual('attention_required',result['status'])
        self.assertEqual('CVE-TEST-1',result['review_findings'][0]['id'])

    def add_resolution_evidence(self, name, content):
        (self.root/name).write_text(content)
        self.data['evidence_files'][name] = checker.digest(content.encode())

    def resolution(self, advisory_id='OSV-TEST-1', **overrides):
        item = {
            'component': 'test', 'id': advisory_id, 'status': 'fixed',
            'justification': 'source_patch_applied',
            'artifacts': {'example:library:1.0': self.artifact_hash},
            'evidence_files': ['fix-evidence.json'],
            'rationale': 'The pinned native artifact includes the reviewed source patch.',
        }
        item.update(overrides)
        return item

    def test_fixed_and_component_absent_resolutions_keep_raw_matches(self):
        self.add_resolution_evidence('fix-evidence.json', 'fixed source build evidence')
        self.add_resolution_evidence('absent-evidence.json', 'component absent evidence')
        self.data['resolutions'] = [
            self.resolution('OSV-TEST-1'),
            self.resolution('CVE-TEST-2', status='not_affected',
                            justification='component_not_present',
                            evidence_files=['absent-evidence.json'],
                            rationale='The vulnerable decoder component is not present.'),
        ]
        with patch.object(checker.osv, '_post_queries', return_value={
                'results': [{'vulns': [{'id': 'OSV-TEST-1'}, {'id': 'CVE-TEST-2'}]}]}):
            result = self.run_check(scan=True)
        self.assertEqual('bounded_check_complete_with_coverage_gaps', result['status'])
        self.assertEqual(['OSV-TEST-1', 'CVE-TEST-2'],
                         result['advisories']['matches']['test'])
        self.assertEqual('matches_found', result['advisories']['status'])
        self.assertEqual([], result['review_summary']['unresolved'])
        self.assertEqual({'fixed', 'not_affected'},
                         {entry['status'] for entry in result['review_summary']['resolved']})

    def test_known_manual_finding_can_be_resolved_without_scan(self):
        self.add_resolution_evidence('fix-evidence.json', 'fixed source build evidence')
        self.data['review_findings'] = [{'id': 'OSV-TEST-1', 'component': 'test'}]
        self.data['resolutions'] = [self.resolution()]
        result = self.run_check()
        self.assertEqual('bounded_check_complete_with_coverage_gaps', result['status'])
        self.assertEqual('OSV-TEST-1', result['review_findings'][0]['id'])
        self.assertEqual('OSV-TEST-1', result['review_summary']['resolved'][0]['id'])

    def test_new_osv_id_without_exact_resolution_stays_attention(self):
        self.add_resolution_evidence('fix-evidence.json', 'fixed source build evidence')
        self.data['review_findings'] = [{'id': 'OSV-TEST-1', 'component': 'test'}]
        self.data['resolutions'] = [self.resolution()]
        with patch.object(checker.osv, '_post_queries', return_value={
                'results': [{'vulns': [{'id': 'OSV-TEST-1'}, {'id': 'OSV-NEW-2'}]}]}):
            result = self.run_check(scan=True)
        self.assertEqual('attention_required', result['status'])
        self.assertEqual([{'component': 'test', 'id': 'OSV-NEW-2'}],
                         result['review_summary']['unresolved'])

    def test_resolution_requires_current_exact_artifact_set_and_hashes(self):
        self.add_resolution_evidence('fix-evidence.json', 'fixed source build evidence')
        invalid = [
            self.resolution(artifacts={'example:library:1.0': '0' * 64}),
            self.resolution(artifacts={'example:library:1.0': self.artifact_hash,
                                       'example:extra:2.0': '1' * 64}),
            self.resolution(artifacts={}),
        ]
        for resolution in invalid:
            with self.subTest(artifacts=resolution['artifacts']):
                self.data['resolutions'] = [resolution]
                self.assertEqual('unavailable', self.run_check()['status'])

    def test_resolution_requires_hash_verified_evidence(self):
        self.data['resolutions'] = [self.resolution(evidence_files=['missing.json'])]
        result = self.run_check()
        self.assertEqual('unavailable', result['status'])
        self.assertIn('not hash-verified', result['error'])

    def test_duplicate_or_wrong_component_resolution_is_rejected(self):
        self.add_resolution_evidence('fix-evidence.json', 'fixed source build evidence')
        duplicate = self.resolution()
        self.data['resolutions'] = [duplicate, duplicate.copy()]
        self.assertIn('duplicate native resolution', self.run_check()['error'])
        self.data['resolutions'] = [self.resolution(component='missing')]
        self.assertIn('unknown native resolution component', self.run_check()['error'])

    def test_incompatible_resolution_classification_is_rejected(self):
        self.add_resolution_evidence('fix-evidence.json', 'fixed source build evidence')
        self.data['resolutions'] = [self.resolution(status='not_affected')]
        self.assertIn('incompatible native resolution', self.run_check()['error'])

    def test_duplicate_metadata_key_is_unavailable(self):
        self.inventory.write_text('{"schema_version":1,"schema_version":1}')
        result = checker.run(self.inventory,self.pins)
        self.assertEqual('unavailable',result['status'])


if __name__ == '__main__':
    unittest.main()
