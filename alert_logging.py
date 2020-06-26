"""
alert_logging.py
"""
import sys
import ssl
import time
import json
import smtplib
import yaml
import geohash
import psycopg2
import geoip2.database
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from templates import alert_template, email_template


ssl_context = ssl.create_default_context()


def send_mail(args):
    with smtplib.SMTP_SSL(host=config["mail"]["host"], port=config["mail"]["port"], context=ssl_context) as mail_server:
        mail_server.login(config["mail"]["user"], config["mail"]["password"])
        main_msg = MIMEMultipart()
        main_msg['Subject'] = args["Subject"]
        main_msg['To'] = args["To"]
        main_msg['From'] = config["mail"]["user"]
        main_msg.preamble = args["preamble"]
        msg_body = MIMEText(email_template.substitute(args["msg_args"]), 'html')
        main_msg.attach(msg_body)
        mail_server.send_message(main_msg, config["mail"]["user"], args["To"])

        
def tail(f, poll_frequency):
    while True:
        where = f.tell()
        line = f.readline()
        if not line or line == "\n":
            time.sleep(poll_frequency)
            f.seek(where)
        else:
            yield line


class Monitor(object):

    def __init__(self, config_file, logfile):
        self.config = yaml.safe_load(open(config_file, "r"))
        self.geoip_city = geoip2.database.Reader(config["city_db_path"]) 
        self.logfile = logfile
        self.handlers = {"alert": self.handle_alert, "stats": self.handle_stats}
        self.db_con = psycopg2.connect(database=self.config["postgres"]["db_name"],
                                       user=self.config["postgres"]["user"],
                                       password=self.config["postgres"]["password"],
                                       host=self.config["postgres"]["host"],
                                       port=self.config["postgres"]["port"])
        
    def get_location(self, ip):
        if config["local_range"] in ip:
            return config["default_location"]
        try:
            query = geoip_city.city(ip)
            ghash = geohash.encode(query.location.latitude, query.location.longitude)
            return dict(country=query.country.name, city=query.city.name, geohash=ghash)
        except:
            return dict(country="", city="", geohash="")

    def handle_stats(self, event):
        pass

    def handle_alert(self, event):
        """Manages parsing, logging, enrichments, and alerting of alerts"""
        # Location enrichment
        dest_location = self.get_location(event["dest_ip"])
        src_location = self.get_location(event["src_ip"])
        
        severity = event["alert"]["severity"]
        if severity in config["mail"]["alert_severity"]:
            self.email_alert(event)
        

    def insert_alert(self, data, location, extra):
        """
        Inserts data into the database backend, as JSON blobs
        data, location, and extra args should be python dictionaries
        """
        insert = "insert into alerts(data, location, extras) values(%s);"
        cursor = self.db_con.cursor()
        cursor.execute(insert, (json.dumps(data), json.dumps(location), json.dumps(extra)))
        self.db_con.commit()
        cursor.close()
        
    def email_alert(self, event):
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
                        "msg_args": {"msg_body": alert_msg}
                        }
            send_mail(msg_args)
        except Exception as e:
            print("Error Emailing Alert")
            print(e)
            print(event)

    def monitor_log(self):
        with open(self.logfile, 'r') as f:
            for line in tail(f, self.config["poll_frequency"]):
                try:
                    event = json.loads(line)
                    event_type = event["event_type"]
                    handler = self.handlers[event_type]
                    handler(event)
                except Exception as e:
                    print("Error monitoring log")
                    print(e)
                    print(event)


def main(args):
    config_file = args[2]
    logfile = args[1]
    eve_monitor = Monitor(config_file, logfile)
    eve_monitor.monitor_log()

  
if __name__ == "__main__":
    args_ = sys.argv
    if len(args_) < 2:
        print("Usage: alert_logging.py log_filename config.yaml")
        sys.exit()
    main(args_)
