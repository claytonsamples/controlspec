"""Verify the public package's real import boundary and source provenance."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_copied_source_bytes_match_manifest():
    manifest = json.loads((ROOT / 'SOURCE_MANIFEST.json').read_text())
    for item in manifest['files']:
        assert hashlib.sha256((ROOT / item['path']).read_bytes()).hexdigest() == item['sha256']


def test_reference_app_does_not_import_operational_stack():
    code = '''
import sys
from assurance.api.controlspec import create_default_controlspec_reference_app
app = create_default_controlspec_reference_app()
assert app.state.controlspec_service.catalog
for name in sys.modules:
    assert not name.startswith(('sqlalchemy', 'psycopg', 'alembic', 'assurance.persistence', 'assurance.api.app', 'assurance.api.postgres_state'))
'''
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_default_catalog_and_optional_profile_import_without_database():
    code = 'import assurance.controlspec.profiles.reference\n'
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
