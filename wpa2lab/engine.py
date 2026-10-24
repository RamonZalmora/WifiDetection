"""Bounded CPU jobs; SQLite history never stores candidate passwords or verifier keys."""
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from .crypto import METHOD, LabData, verify


class Store:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / 'history.sqlite3'
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS history (id TEXT PRIMARY KEY, record TEXT NOT NULL)')

    def connect(self):
        return sqlite3.connect(self.path)

    def save(self, record):
        safe = {key: value for key, value in record.items() if key != 'password'}
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO history VALUES (?, ?)', (record['id'], json.dumps(safe)))

    def history(self):
        with self.connect() as db:
            return [json.loads(row[0]) for row in db.execute('SELECT record FROM history ORDER BY rowid DESC LIMIT 200')]


class Engine:
    def __init__(self, store: Store):
        self.store = store
        self.projects = {}
        self.jobs = {}
        self.lock = threading.RLock()
        self.worker = None
        self.closed = False

    def project(self, name: str, data: LabData, source: str):
        with self.lock:
            if len(self.projects) >= 100:
                raise ValueError('Session project limit reached; restart to clear projects.')
            pid = str(uuid.uuid4())
            self.projects[pid] = {'id': pid, 'name': name, 'data': data, 'source': source}
            return self.project_public(pid)

    def project_public(self, pid):
        p = self.projects[pid]
        return {'id': pid, 'name': p['name'], 'ssid': p['data'].ssid, 'source': p['source'],
                'format': p['data'].format, 'status': 'READY', 'method': METHOD}

    def start(self, pid, candidates, limit):
        with self.lock:
            if self.closed:
                raise ValueError('Application is shutting down')
            if self.worker and self.worker.is_alive():
                raise ValueError('One experiment may run at a time')
            if pid not in self.projects:
                raise KeyError(pid)
            project = self.projects[pid]
            jid = str(uuid.uuid4())
            selected = candidates[:limit]
            job = {'id': jid, 'project_id': pid, 'project': project['name'], 'ssid': project['data'].ssid,
                   'source': project['source'], 'method': METHOD, 'status': 'TESTING',
                   'tested': 0, 'total': len(selected), 'supplied': len(candidates),
                   'started': time.time(), 'duration': 0.0, 'attempts_per_second': 0.0,
                   'eta_seconds': None, 'password': None, 'confidence': None, 'error': None}
            if len(self.jobs) >= 100:
                del self.jobs[next(iter(self.jobs))]
            cancel = threading.Event()
            self.jobs[jid] = (job, cancel)
            self.worker = threading.Thread(target=self._run, args=(job, cancel, project['data'], selected), daemon=True)
            self.worker.start()
            return dict(job)

    def _run(self, job, cancel, data, candidates):
        started = time.perf_counter()
        try:
            for candidate in candidates:
                if cancel.is_set():
                    with self.lock:
                        job['status'] = 'CANCELLED'
                    break
                matched = verify(data, candidate)
                independently_matched = verify(data, candidate, independent=True) if matched else False
                with self.lock:
                    job['tested'] += 1
                    elapsed = max(time.perf_counter() - started, 0.000001)
                    job['duration'] = elapsed
                    job['attempts_per_second'] = job['tested'] / elapsed
                    job['eta_seconds'] = (job['total'] - job['tested']) / job['attempts_per_second']
                    if cancel.is_set():
                        job['status'] = 'CANCELLED'
                        break
                    if matched:
                        if not independently_matched:
                            raise RuntimeError('Independent verification disagreed')
                        job.update(status='VERIFIED MATCH', password=candidate,
                                   confidence='Two independent derivation APIs matched the laboratory proof; no router connection verified.')
                        break
            else:
                with self.lock:
                    job['status'] = 'CANCELLED' if cancel.is_set() else 'NO MATCH FOUND'
        except Exception:
            with self.lock:
                job.update(status='ERROR', error='Verification failed; no success result is available.')
        finally:
            candidates.clear()
            with self.lock:
                job['duration'] = time.perf_counter() - started
                job['eta_seconds'] = None
                job['finished'] = time.time()
                if job['duration']:
                    job['attempts_per_second'] = job['tested'] / job['duration']
                try:
                    self.store.save(job)
                except sqlite3.Error:
                    job['error'] = 'History could not be saved. The experiment result remains available in this session.'

    def get(self, jid):
        with self.lock:
            return dict(self.jobs[jid][0])

    def cancel(self, jid):
        with self.lock:
            self.jobs[jid][1].set()
            return dict(self.jobs[jid][0])

    def clear_sensitive(self):
        with self.lock:
            if self.worker and self.worker.is_alive():
                raise ValueError('Cancel the active experiment before clearing the session')
            self.projects.clear()
            self.jobs.clear()

    def close(self):
        with self.lock:
            self.closed = True
            for _, cancel in self.jobs.values():
                cancel.set()
        if self.worker:
            self.worker.join(timeout=5)
        self.projects.clear()
        self.jobs.clear()
