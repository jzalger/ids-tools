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

    def test_get_location(self):
        config = {"city_db_path": "tests/MaxMind-DB/test-data/GeoIP2-City-Test.mmdb",
                  "local_range": "192.168.",
                  "default_location": dict(country="Canada", city="Banff", geohash="1234abc")}
        analyzer = ids_tools.Analysis(config)

        # Test correct management of unavailable IPs
        self.assertDictEqual(analyzer.get_location("1.1.1.1"), dict(country="", city="", geohash=""))

        # Test correct return type of known IP
        self.assertDictEqual(analyzer.get_location('2.125.160.216'), dict(country="United Kingdom", city="Boxford", geohash="gcpn7scc8ghq"))

        # Test value in local range
        self.assertDictEqual(analyzer.get_location("192.168.1.1"), config["default_location"])

    def test_get_reputation(self):
        pass

    def test_query_reputation(self):
        # should return data as a dict, or None if call not successful
        pass

class TestAlerting(TestCase):

    def test_send_email(self):
        pass
