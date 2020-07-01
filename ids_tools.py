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
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from templates import alert_template, email_template

requests_cache.install_cache(expire_after=43200)
ssl_context = ssl.create_default_context()


####################################################################################
class Monitor:
    def __init__(self, config_file, logfile):
        self.config = yaml.safe_load(open(config_file, "r"))
        self.logfile = logfile
        self.handlers = {"alert": self.handle_alert, "stats": self.handle_stats}
        self.alerting = Alerting(self.config)
        self.analysis = Analysis(self.config)
        self.logging = Logging(self.config)

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

    def handle_anomaly(self, event: dict):
        pass

    def handle_stats(self, event: dict):
        pass

    def handle_alert(self, event: dict):
        """Manages parsing, logging, enrichments, and alerting of alerts"""
        try:
            # Enrich the alert from other sources
            location = {"dest_location": self.analysis.get_location(event["dest_ip"]),
                        "src_location": self.analysis.get_location(event["src_ip"])}

            # If alert related to questionable WAN traffic, assess IP reputation
            # TODO: add a mapping between categories to analysis handlers.
            severity = event["alert"]["severity"]
            reputation = dict(reputation="unknown", data=None)

            if "dns" in event.keys():
                domain = event["dns"]["query"][0]["rrname"]
                if "http" in domain:
                    domain = domain.split('//')[-1].split('/')[0]
                reputation = self.analysis.get_reputation(domain, query_type="domain")
            elif self.config["local_range"] not in event["src_ip"]:
                reputation = self.analysis.get_reputation(event["src_ip"], query_type="ip")
            elif self.config["local_range"] not in event["dest_ip"]:
                reputation = self.analysis.get_reputation(event["dest_ip"], query_type="ip")
            else:
                pass

            # Log To Database
            self.logging.insert_alert(event, location, reputation)

            # Trigger Alerting (ie email)
            if severity in self.config["mail"]["alert_severity"] and (
                    reputation == "unknown" or reputation == "poor") or reputation == "poor":
                # TODO: Add further screening based on reputation analysis
                self.email_alert(event, extra=reputation)

        except Exception as e:
            print("error handling alert")
            print(e)

    def email_alert(self, event, extra=None):
        """Screen the msg based on severity prior to sending an alert email"""
        try:
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
            self.alerting.send_mail(msg_args, self.config)
        except Exception as e:
            print("Error Emailing Alert")
            print(e)
            print(event)

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

    def get_location(self, ip):
        if self.config["local_range"] in ip:
            return self.config["default_location"]
        try:
            query = self.geoip_city.city(ip)
            ghash = geohash.encode(query.location.latitude, query.location.longitude)
            return dict(country=query.country.name, city=query.city.name, geohash=ghash)
        except:
            return dict(country="", city="", geohash="")

    def get_reputation(self, param, query_type="ip"):
        data = self._query_reputation(param, query_type=query_type)
        if data is None:
            return dict(reputation="unknown", data=None)

        # TODO: Shift this to a function mapping
        if query_type == "ip":
            analysis = self._analyze_ip_reputation(data)
        elif query_type == "domain":
            analysis = self._analyze_domain_reputation(data)
        else:
            raise ValueError

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
        try:
            cfg = self.config["apivoid"]
            url = cfg["url"][query_type] % (cfg["key"], param)
            r = requests.get(url=url)
            data = r.json()
            if data["success"]:
                return data
            else:
                return None
        except Exception as e:
            print("Error querying reputation")
            print(e)

    def _analyze_domain_reputation(self, data):
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

    def _analyze_ip_reputation(self, data):
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
    eve_monitor = Monitor(config_file, logfile)
    eve_monitor.monitor_log()


if __name__ == "__main__":
    args_ = sys.argv
    if len(args_) < 2:
        print("Usage: ids_tools.py log_filename config.yaml")
        sys.exit()
    main(args_)
