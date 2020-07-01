"""
Unit Tests for ids_tools.py
"""
from unittest import TestCase
import ids_tools


class TestMonitoring(TestCase):

    def __init__(self, config_file, log_file):
        super().__init__()
        self.monitor = ids_tools.Monitor(config_file, log_file)

    def test_tail(self):
        pass

    def test_handle_alert(self):
        pass

    def test_monitor_log(self):
        pass

    def test_email_alert(self):
        pass


class TestAnalysis(TestCase):

    def __init__(self, config):
        super().__init__()
        self.analysis = ids_tools.Analysis(config)

    def test_get_location(self):
        pass

    def test_get_reputation(self):
        pass


class TestAlerting(TestCase):

    def __init__(self, config):
        super().__init__()
        self.alerting = ids_tools.Alerting(config)

    def test_send_email(self):
        pass
