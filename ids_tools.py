"""
ids_tools.py
J. Zalger, 2020
"""
import sys
import ssl
import time
import json
import smtplib
import requests
import requests_cache
import yaml
import geohash
import psycopg2
import geoip2.database
import geoip2.errors
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from templates import alert_template, email_template

requests_cache.install_cache(expire_after=43200)
ssl_context = ssl.create_default_context()


####################################################################################
class Monitor:
    def __init__(self, config, logfile):
        self.config = config
        self.logfile = logfile
        self.handlers = {"alert": self.handle_alert, "stats": self.handle_stats,
                         "ssh": self.handle_ssh, "anomaly": self.handle_anomaly,
                         "tftp": self.handle_tftp, "ftp": self.handle_ftp}

    @staticmethod
    def tail(f, poll_frequency):
        while True:
            where = f.tell()
            line = f.readline()
            if not line or line == "\n":
                time.sleep(poll_frequency)
                f.seek(where)
            else:
                yield line

    def handle_ssh(self, event: dict):
        pass

    def handle_tftp(self, event: dict):
        pass

    def handle_ftp(self, event: dict):
        pass

    def handle_anomaly(self, event: dict):
        pass

    def handle_stats(self, event: dict):
        pass

    def handle_alert(self, event: dict):
        """Manages parsing, logging, enrichments, and alerting of alerts"""
        # Attempt to geolocate the source and destination IPs
        analysis = Analysis(self.config)
        location = {"dest_location": analysis.get_location(event["dest_ip"]),
                    "src_location": analysis.get_location(event["src_ip"])}

        # Assess the reputation of external IPs or domains
        reputation = dict(reputation="unknown", data=None)
        if event["app_proto"] == "dns":
            domain = event["dns"]["query"][0]["rrname"]
            if "http://" in domain:
                domain = domain.split('//')[-1].split('/')[0]
            reputation = analysis.get_reputation(domain, query_type="domain")
        elif self.config["local_range"] not in event["src_ip"]:
            reputation = analysis.get_reputation(event["src_ip"], query_type="ip")
        elif self.config["local_range"] not in event["dest_ip"]:
            reputation = analysis.get_reputation(event["dest_ip"], query_type="ip")
        else:
            pass

        # Log To Database
        logging = Logging(self.config)
        logging.insert_alert(event, location, reputation)

        # Trigger Alerting (ie email)
        severity = event["alert"]["severity"]
        if severity in self.config["mail"]["alert_severity"] and (
                reputation == "unknown" or reputation == "poor") or reputation == "poor":
            self.email_alert(event, extra=reputation)

    def email_alert(self, event, extra=None):
        """Screen the msg based on severity prior to sending an alert email"""
        alert_args = event["alert"]
        alert_args["timestamp"] = event["timestamp"]
        alert_args["src_ip"] = event["src_ip"]
        alert_args["dest_ip"] = event["dest_ip"]
        alert_msg = alert_template.substitute(alert_args)
        msg_args = {"To": self.config["mail"]["alert_user"],
                    "Subject": "Severity %s IDS event" % event["alert"]["severity"],
                    "preamble": "IDS event detected by suricata",
                    "msg_args": {"msg_body": alert_msg, "extra": [extra, event]}
                    }
        alerting = Alerting(self.config)
        alerting.send_mail(msg_args, self.config)

    def monitor_log(self):
        with open(self.logfile, 'r') as f:
            for line in self.tail(f, self.config["poll_frequency"]):
                try:
                    event = json.loads(line)  # type: dict
                    event_type = event["event_type"]
                    handler = self.handlers[event_type]
                    handler(event)
                except:
                    pass


###########################################################################################
class Logging:

    def __init__(self, config):
        self.config = config
        self.db_con = psycopg2.connect(database=self.config["postgres"]["db_name"],
                                       user=self.config["postgres"]["user"],
                                       password=self.config["postgres"]["password"],
                                       host=self.config["postgres"]["host"],
                                       port=self.config["postgres"]["port"])

    def insert_alert(self, data, location, extra):
        """
        Inserts data into the database backend, as JSON blobs
        data, location, and extra args should be python dictionaries
        """
        insert = "insert into alerts(data, location, extra) values(%s, %s, %s);"
        cursor = self.db_con.cursor()
        cursor.execute(insert, (json.dumps(data), json.dumps(location), json.dumps(extra)))
        self.db_con.commit()
        cursor.close()


##########################################################################################
class Alerting:

    def __init__(self, config):
        self.config = config

    @staticmethod
    def send_mail(args, config):
        with smtplib.SMTP_SSL(host=config["mail"]["host"], port=config["mail"]["port"],
                              context=ssl_context) as mail_server:
            mail_server.login(config["mail"]["user"], config["mail"]["password"])
            main_msg = MIMEMultipart()
            main_msg['Subject'] = args["Subject"]
            main_msg['To'] = args["To"]
            main_msg['From'] = config["mail"]["user"]
            main_msg.preamble = args["preamble"]
            msg_body = MIMEText(email_template.substitute(args["msg_args"]), 'html')
            main_msg.attach(msg_body)
            mail_server.send_message(main_msg, config["mail"]["user"], args["To"])


##########################################################################################
class Analysis:

    def __init__(self, config):
        self.config = config
        self.geoip_city = geoip2.database.Reader(self.config["city_db_path"])
        self.reputation_handlers = {"ip": self._analyze_ip_reputation,
                                    "domain": self._analyze_domain_reputation}

    def get_location(self, ip):
        if self.config["local_range"] in ip:
            return self.config["default_location"]
        try:
            query = self.geoip_city.city(ip)
            ghash = geohash.encode(query.location.latitude, query.location.longitude)
            return dict(country=query.country.name, city=query.city.name, geohash=ghash)
        except geoip2.errors.AddressNotFoundError:
            return dict(country="", city="", geohash="")

    def get_reputation(self, param, query_type="ip"):
        data = self._query_reputation(param, query_type=query_type)
        if data is None:
            return dict(reputation="unknown", data=None)

        analyzer = self.reputation_handlers[query_type]
        analysis = analyzer(data)

        if analysis is True:
            return dict(reputation="poor", data=data)
        else:
            return dict(reputation="neutral", data=data)

    def _query_reputation(self, param, query_type="ip"):
        """
        Queries the reputation from apivoid.
        param should be a string (ip, domain name, etc)
        report_type = ip | domain
        """
        assert isinstance(param, str), "query reputation parameter must be string"
        
        cfg = self.config["apivoid"]
        url = cfg["url"][query_type] % (cfg["key"], param)
        r = requests.get(url=url)
        if r.status_code != 200:
            return None
        data = r.json()
        if data["success"]:
            return data
        else:
            return None

    def _analyze_domain_reputation(self, data: dict):
        """
        Assess domain reputation to make hostility decision.
        Based on the apivoid service
        """
        abnormal_domain = False
        suspect_country = False
        blacklists = data["data"]["report"]["blacklists"]["detections"]
        if True in [cat for cat in data["data"]["report"]["category"]]:
            abnormal_domain = True
        if data["data"]["report"]["server"]["country_name"] in self.config["suspect_countries"]:
            suspect_country = True
        if blacklists > 0 or abnormal_domain or suspect_country:
            return True
        else:
            return False

    @staticmethod
    def _analyze_ip_reputation(data: dict):
        """
        Assess an IP reputation response and make a hostility decision
        Based on using the apivoid service.
        """
        # Check blacklists and known anonymization hosts
        blacklists = data["data"]["report"]["blacklists"]["detections"]
        is_anon = False
        if True in [anon_type for anon_type in data["data"]["report"]["anonymity"]]:
            is_anon = True
        if blacklists > 0 or is_anon:
            return True
        else:
            return False


def main(args):
    config_file = args[2]
    logfile = args[1]
    config = yaml.safe_load(open(config_file, "r"))
    eve_monitor = Monitor(config, logfile)
    eve_monitor.monitor_log()


if __name__ == "__main__":
    args_ = sys.argv
    if len(args_) < 2:
        print("Usage: ids_tools.py log_filename config.yaml")
        sys.exit()
    main(args_)
