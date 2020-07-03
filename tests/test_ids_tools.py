"""
Unit Tests for ids_tools.py
"""
import tempfile
import ids_tools
from tests import test_events, test_reputations
from unittest import TestCase, skip, mock


class TestMonitoring(TestCase):

    @skip("Stuck in infinite loop")
    def test_tail(self):
        monitor = ids_tools.Monitor(None, None)
        with tempfile.NamedTemporaryFile(mode="w") as log_file:
            log_file.write(test_events.basic_alert_json)  # Prep the test log
            log_lines = list()

            # FIXME: How to test a function with a while True?
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

    def setUp(self) -> None:
        self.config = {"city_db_path": "tests/MaxMind-DB/test-data/GeoIP2-City-Test.mmdb",
                       "local_range": "192.168.",
                       "suspect_countries": ["Latvia"],
                       "default_location": dict(country="Canada", city="Banff", geohash="1234abc")}
        self.analyzer = ids_tools.Analysis(self.config)

    def test_get_location(self):
        # Test correct management of unavailable IPs
        self.assertDictEqual(self.analyzer.get_location("1.1.1.1"), dict(country="", city="", geohash=""))

        # Test correct return type of known IP
        self.assertDictEqual(self.analyzer.get_location('2.125.160.216'),
                             dict(country="United Kingdom", city="Boxford", geohash="gcpn7scc8ghq"))

        # Test value in local range
        self.assertDictEqual(self.analyzer.get_location("192.168.1.1"), self.config["default_location"])

    def test_get_reputation(self):
        # Test a clean domain (add clean domain sample)
        self.assertFalse(self.analyzer._analyze_domain_reputation(test_reputations.clean_domain_response_dict))

        # Test a domain with blacklist hits
        self.assertTrue(self.analyzer._analyze_domain_reputation(test_reputations.blacklist_domain_response_dict))

        # Test a domain with strange anonymity ties
        self.assertTrue(self.analyzer._analyze_domain_reputation(test_reputations.anon_domain_response_dict))

        # Test suspect country sample
        self.assertTrue(self.analyzer._analyze_domain_reputation(test_reputations.suspect_country_domain_response_dict))

    def test_analyze_domain_reputation(self):
        # Test a clean domain (add clean domain sample)
        self.assertFalse(self.analyzer._analyze_domain_reputation(test_reputations.clean_domain_response_dict))

        # Test a domain with blacklist hits
        self.assertTrue(self.analyzer._analyze_domain_reputation(test_reputations.blacklist_domain_response_dict))

        # Test a domain with strange anonymity ties (add sample)
        self.assertTrue(self.analyzer._analyze_domain_reputation(test_reputations.anon_domain_response_dict))

        # Test suspect country sample
        self.assertTrue(self.analyzer._analyze_domain_reputation(test_reputations.suspect_country_domain_response_dict))

    def test_query_reputation(self):
        # Define a mock function for the request
        def mocked_reputation_query(*args, **kwargs):

            class MockResponse:
                def __init__(self, data, status):
                    self.data = data
                    self.status_code = status

                def json(self):
                    return self.data

            if "8.7.6.5" in kwargs["url"]:
                # Test an invalid response
                return MockResponse({"success": False}, 200)
            elif "5.4.3.2" in kwargs["url"]:
                # Test server fail
                return MockResponse({}, 500)
            elif "122.226.181.165" in kwargs["url"]:
                # Test valid IP reputation response
                return MockResponse(test_reputations.clean_ip_response_dict, 200)
            elif "google.com" in kwargs["url"]:
                # Test valid domain response
                return MockResponse(test_reputations.clean_domain_response_dict, 200)

        # Setup the testcase with mocked request function
        with mock.patch('requests.get', side_effect=mocked_reputation_query):
            apivoid_config = {"enabled": True, "key": "abc123",
                              "url": {"ip": "https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key=%s&ip=%s",
                                      "domain": "https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/?key=%s&host=%s"}}
            config = dict(apivoid=apivoid_config, city_db_path="tests/MaxMind-DB/test-data/GeoIP2-City-Test.mmdb")
            analyzer = ids_tools.Analysis(config)

            # Test nominal IP case
            self.assertDictEqual(analyzer._query_reputation("122.226.181.165", query_type="ip"),
                                 test_reputations.clean_ip_response_dict)

            # Test domain query
            self.assertDictEqual(analyzer._query_reputation("google.com", query_type="domain"),
                                 test_reputations.clean_domain_response_dict)

            # Test param not string
            with self.assertRaises(AssertionError):
                analyzer._query_reputation(1)

            # Test invalid response
            self.assertIsNone(analyzer._query_reputation("5.4.3.2", query_type="ip"))
            self.assertIsNone(analyzer._query_reputation("8.7.6.5", query_type="ip"))


class TestAlerting(TestCase):

    def test_send_email(self):
        pass
