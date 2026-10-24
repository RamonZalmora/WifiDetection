import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

from wpa2lab.app import create_app
from wpa2lab.crypto import LabData, generate, pmk, verify
from wpa2lab.engine import Engine, Store
from wpa2lab.wifi import NativeWifi, assessment, channel


def wait_job(engine, jid):
    engine.worker.join(timeout=10)
    assert not engine.worker.is_alive()
    return engine.get(jid)


def test_ieee_pmk_vector():
    # IEEE 802.11i/WPA PSK test vector: passphrase=password, SSID=IEEE.
    assert pmk('password', 'IEEE').hex() == 'f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e'


def test_proof_match_rejection_and_independent_derivation():
    data = generate('My laboratory', 'known-secret-123')
    assert verify(data, 'known-secret-123')
    assert verify(data, 'known-secret-123', independent=True)
    assert not verify(data, 'wrong-secret-123')
    assert not verify(data, 'short')
    altered = data.model_copy(update={'ssid': 'Other laboratory'})
    assert not verify(altered, 'known-secret-123')
    assert generate('My laboratory', 'known-secret-123').anonce != data.anonce


@pytest.mark.parametrize('ssid,password', [('x'*33, 'password'), ('', 'password'), ('SSID','short'), ('SSID','nonasciié')])
def test_generation_validation(ssid, password):
    with pytest.raises(ValueError):
        generate(ssid, password)


def test_engine_and_history_no_password(tmp_path):
    engine = Engine(Store(tmp_path))
    project = engine.project('Lab', generate('IEEE', 'password'), 'generated')
    job = engine.start(project['id'], ['wrong-password', 'password'], 100)
    result = wait_job(engine, job['id'])
    assert result['status'] == 'VERIFIED MATCH'
    assert result['password'] == 'password'
    assert result['tested'] == 2
    assert result['duration'] > 0 and result['attempts_per_second'] > 0
    assert 'password' not in engine.store.history()[0]
    assert b'wrong-password' not in engine.store.path.read_bytes()
    engine.close()


def test_bound_and_no_match(tmp_path):
    engine = Engine(Store(tmp_path))
    project = engine.project('Lab', generate('IEEE', 'password'), 'generated')
    job = engine.start(project['id'], ['incorrect', 'password'], 1)
    result = wait_job(engine, job['id'])
    assert result['status'] == 'NO MATCH FOUND'
    assert result['tested'] == result['total'] == 1
    engine.close()


def test_cancellation_and_single_worker(tmp_path, monkeypatch):
    from wpa2lab import engine as module
    entered, release = threading.Event(), threading.Event()

    def controlled_verify(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        return False

    monkeypatch.setattr(module, 'verify', controlled_verify)
    engine = Engine(Store(tmp_path))
    project = engine.project('Lab', generate('IEEE', 'password'), 'generated')
    job = engine.start(project['id'], ['incorrect'] * 10, 10)
    assert entered.wait(3)
    with pytest.raises(ValueError):
        engine.start(project['id'], ['incorrect'], 1)
    engine.cancel(job['id'])
    release.set()
    result = wait_job(engine, job['id'])
    assert result['status'] == 'CANCELLED'
    assert result['tested'] < result['total']
    engine.close()


class FixtureScanner:
    def scan(self):
        return {'timestamp': time.time(), 'status': 'ok', 'errors': [],
                'adapters': [{'name': 'TEST ONLY adapter', 'native_scan': True}],
                'networks': [{'ssid': 'TEST ONLY', 'authentication': 'WPA2-Personal'}]}


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path, token='test-session', scanner=FixtureScanner())
    with TestClient(app, base_url='http://127.0.0.1:8765', headers={'X-Lab-Token': 'test-session'}) as c:
        yield c


def project(client, **extra):
    response = client.post('/api/projects/generated', json={
        'name': 'Lab <script>alert(1)</script>', 'ssid': 'IEEE', 'password': 'password', 'authorized': True, **extra})
    assert response.status_code == 200, response.text
    assert 'password' not in response.json()
    return response.json()


def api_job(client, pid):
    response = client.post('/api/tests', json={'project_id': pid, 'candidates': ['incorrect', 'password'], 'limit': 2})
    assert response.status_code == 200
    jid = response.json()['id']
    client.app.state.engine.worker.join(timeout=10)
    assert not client.app.state.engine.worker.is_alive()
    return jid


def test_api_workflow_reports_and_import(client):
    assert client.get('/').status_code == 200
    assert client.get('/static/app.js').status_code == 200
    assert client.get('/health').json()['status'] == 'ok'
    p = project(client)
    data = client.get(f"/api/projects/{p['id']}/data").json()
    imported = client.post('/api/projects/import', json={'name': 'Imported', 'authorized': True, 'data': data})
    assert imported.status_code == 200
    jid = api_job(client, imported.json()['id'])
    assert client.get('/api/tests/' + jid).json()['status'] == 'VERIFIED MATCH'
    for format in ('html', 'json', 'csv'):
        report = client.post('/api/reports', json={'job_id': jid, 'format': format})
        assert report.status_code == 200
        assert 'Content-Disposition' in report.headers
        if format == 'json':
            assert 'password' not in report.json()
    assert client.post('/api/reports', json={'job_id': jid, 'format': 'json', 'include_password': True}).status_code == 400
    sensitive = client.post('/api/reports', json={'job_id': jid, 'format': 'json', 'include_password': True, 'confirm_sensitive': True})
    assert sensitive.json()['password'] == 'password'
    assert client.post('/api/session/clear', json={}).status_code == 200
    historical = client.post('/api/reports', json={'job_id': jid, 'format': 'json'})
    assert historical.status_code == 200 and 'password' not in historical.json()


def test_report_escape_and_formula_safety(client):
    p = project(client, name='=HYPERLINK("https://example.invalid")<script>')
    jid = api_job(client, p['id'])
    html = client.post('/api/reports', json={'job_id': jid, 'format': 'html'}).text
    assert '<script>' not in html and '&lt;script&gt;' in html
    csv = client.post('/api/reports', json={'job_id': jid, 'format': 'csv'}).text
    assert "'=HYPERLINK" in csv


def test_auth_origin_host_and_cross_site(client):
    assert client.get('/api/dashboard', headers={'X-Lab-Token': ''}).status_code == 401
    assert client.post('/api/scan', json={}, headers={'Origin': 'https://evil.example'}).status_code == 403
    assert client.get('/api/dashboard', headers={'Host': 'evil.example'}).status_code == 400
    assert client.get('/api/dashboard', headers={'Sec-Fetch-Site': 'cross-site'}).status_code == 403
    assert "frame-ancestors 'none'" in client.get('/').headers['Content-Security-Policy']


def test_invalid_data_and_password_not_echoed(client):
    response = client.post('/api/projects/generated', json={'name': 'Lab', 'ssid': 'IEEE', 'password': 'short', 'authorized': True})
    assert response.status_code == 422
    assert '"short"' not in response.text
    assert client.post('/api/projects/generated', json={'name': 'Lab', 'ssid': 'IEEE', 'password': 'password', 'authorized': False}).status_code == 422
    assert client.post('/api/projects/import', json={'name': 'Lab', 'authorized': True, 'data': {'format': 'pcap'}}).status_code == 422
    response = client.post('/api/projects/import', content='x' * 1_048_577)
    assert response.status_code == 413
    assert client.post('/api/tests', json={'project_id': 'missing', 'candidates': ['password']}).status_code == 404
    assert client.post('/api/tests', json={'project_id': 'missing', 'candidates': ['short']}).status_code == 422


def test_scanner_mock_and_rate_limit(client):
    scan = client.post('/api/scan', json={})
    assert scan.status_code == 200
    assert scan.json()['networks'][0]['authentication'] == 'WPA2-Personal'
    assert client.post('/api/scan', json={}).status_code == 429


def test_password_tools(client):
    assert client.post('/api/password/analyze', json={'password': 'password'}).json()['warnings']
    generated = client.post('/api/password/generate', json={}).json()['password']
    assert len(generated) == 24


def test_shutdown_callback(tmp_path):
    called = threading.Event()
    app = create_app(tmp_path, token='test', shutdown=called.set)
    with TestClient(app, base_url='http://127.0.0.1:8765', headers={'X-Lab-Token': 'test'}) as c:
        assert c.post('/api/shutdown').status_code == 200
        assert called.wait(2)


def test_frequency_and_security():
    assert channel(2412000) == ('2.4 GHz', 1)
    assert channel(2484000) == ('2.4 GHz', 14)
    assert channel(5180000) == ('5 GHz', 36)
    assert channel(5955000) == ('6 GHz', 1)
    assert assessment({'authentication': 'Open', 'encryption': 'None'})['observed_risks']
    assert not assessment({'authentication': 'WPA2-Personal', 'encryption': 'CCMP'})['observed_risks']


def test_non_windows_scanner_honest():
    import platform
    if platform.system() == 'Windows':
        pytest.skip('Linux unsupported-platform behavior only')
    result = NativeWifi().scan()
    assert result['status'] == 'unsupported'
    assert result['networks'] == result['adapters'] == []


@pytest.mark.parametrize('field,value', [
    ('format', 'hashcat-22000'), ('ap_mac', '000000000000'),
    ('station_mac', '010000000002'), ('snonce', '00' * 32),
    ('eapol', '00' * 98), ('mic', 'not-hex'),
])
def test_strict_eapol_import(field, value):
    record = generate('IEEE', 'password').model_dump()
    record[field] = value
    with pytest.raises(ValueError):
        LabData.model_validate(record)


def test_tampered_mic_and_packet_rejected():
    record = generate('IEEE', 'password').model_dump()
    record['mic'] = '00' * 16
    assert not verify(LabData.model_validate(record), 'password')
    packet = bytearray.fromhex(record['eapol'])
    packet[81] = 1
    record['eapol'] = packet.hex()
    with pytest.raises(ValueError):
        LabData.model_validate(record)
