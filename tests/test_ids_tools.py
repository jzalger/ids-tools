"""
Unit Tests for ids_tools.py
"""
import tempfile
import ids_tools
from tests import test_events
from unittest import TestCase


class TestMonitoring(TestCase):

    def test_tail(self):
        monitor = ids_tools.Monitor(None, None)
        with tempfile.NamedTemporaryFile() as log_file:
            log_file.write(test_events.basic_alert_json)  # Prep the test log file
            log_lines = list()

            with open(log_file.name, 'r') as f:
                for line in monitor.tail(f, 1):
                    log_lines.append(line)

        read_data = "\n".join(log_lines)
        self.assertEqual(test_events.basic_alert_json, read_data)

    def test_handle_alert(self):
        pass

    def test_monitor_log(self):
        pass

    def test_email_alert(self):
        pass


class TestLogging(TestCase):

    def test_insert_alert(self):
        pass


class TestAnalysis(TestCase):

    def test_get_location(self):
        pass

    def test_get_reputation(self):
        pass


class TestAlerting(TestCase):

    def test_send_email(self):
        pass
