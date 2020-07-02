"""
Unit Tests for ids_tools.py
"""
import tempfile
import ids_tools
from tests import test_events
from unittest import TestCase, skip


class TestMonitoring(TestCase):

    @skip("Stuck in infinite loop")
    def test_tail(self):
        monitor = ids_tools.Monitor(None, None)
        with tempfile.NamedTemporaryFile(mode="w") as log_file:
            log_file.write(test_events.basic_alert_json)  # Prep the test log
            log_lines = list()

            #FIXME: How to test a function with a while True?
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

    @skip("Not fully implemented")
    def test_get_location(self):
        config = {"city_db_path": "tests/MaxMind-DB/test-data/GeoIP2-City-Test.mmdb"}
        analyzer = ids_tools.Analysis(config)

    def test_get_reputation(self):
        pass


class TestAlerting(TestCase):

    def test_send_email(self):
        pass
