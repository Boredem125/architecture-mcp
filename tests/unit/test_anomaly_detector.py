from __future__ import annotations

import time

from sandbox.anomaly.baseline import SessionBaseline
from sandbox.anomaly.rate_monitor import RateMonitor


class TestSessionBaseline:
    def test_baseline_not_established_initially(self):
        bl = SessionBaseline(window_requests=5, window_seconds=60)
        assert not bl.is_established()

    def test_baseline_established_by_count(self):
        bl = SessionBaseline(window_requests=3, window_seconds=9999)
        now = time.time()
        bl.update("READ", now, "/tmp/a")
        bl.update("READ", now + 1, "/tmp/b")
        bl.update("WRITE", now + 2, "/tmp/c")
        assert bl.is_established()

    def test_baseline_freeze(self):
        bl = SessionBaseline(window_requests=2, window_seconds=9999)
        now = time.time()
        bl.update("READ", now, "/tmp/a")
        bl.update("READ", now + 1, "/tmp/b")
        bl.freeze()
        assert bl.rate_mean >= 0
        assert "READ" in bl.action_distribution


class TestRateMonitor:
    def test_no_alert_at_baseline(self):
        rm = RateMonitor(alert_sigma=2.0, kill_sigma=4.0)
        rm.set_baseline(mean=5.0, std=1.0)
        now = time.time()
        for i in range(5):
            rm.record_request(now + i * 12)
        status = rm.check()
        assert not status.alert
        assert not status.kill

    def test_alert_on_spike(self):
        rm = RateMonitor(alert_sigma=2.0, kill_sigma=4.0)
        rm.set_baseline(mean=2.0, std=0.5)
        now = time.time()
        for i in range(20):
            rm.record_request(now + i * 0.5)
        status = rm.check()
        assert status.alert
