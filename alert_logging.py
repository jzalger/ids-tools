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
import geoip2.database
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from influxdb import InfluxDBClient
from templates import alert_template, email_template

config = dict()
POLL_FREQ = 30  # Frequency in seconds
geoip_city = None
ssl_context = ssl.create_default_context()
alert_severity = [1, 2]


def send_mail(args):
    try:
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
    except Exception as e:
        print("Email Error")
        print(e)

        
def tail(f):
    while True:
        where = f.tell()
        line = f.readline()
        if not line or line == "\n":
            time.sleep(POLL_FREQ)
            f.seek(where)
        else:
            yield line

def get_location(ip):
    if config["local_range"] in ip:
        return config["default_location"]
    try:
        query = geoip_city.city(ip)
        ghash = geohash.encode(query.location.latitude, query.location.longitude)
        return dict(country=query.country.name, city=query.city.name, geohash=ghash)
    except:
        # FIXME: reference actual AddressNotFoundError.
        # print("address not found for %s" % ip)
        return dict(country="", city="", geohash="")


def log_alert(new_data):
    # Try and geolocate source and dest IP
    src_ip = new_data["src_ip"]
    dest_ip = new_data["dest_ip"]
    src_location = get_location(src_ip)
    dest_location = get_location(dest_ip)
    
    try:
        # TODO: move this parsing into a more generalized schema based function, add all fields 
        point = {"measurement": "alert",
                "time": new_data["timestamp"],
                "tags": {"event_type": new_data["event_type"],
                         "severity": new_data["alert"]["severity"],
                         "src_country": src_location["country"],
                         "dest_country": dest_location["country"],
                         "src_geohash": src_location["geohash"],
                         "dest_geohash": dest_location["geohash"]
                  },
                  "proto": new_data["proto"],
                  "fields": {"signature_id": new_data["alert"]["signature_id"],
                             "signature": new_data["alert"]["signature"],
                             "category": new_data["alert"]["category"],
                             "src_ip": src_ip,
                             "dest_ip": dest_ip,
                             "src_city": src_location["city"],
                             "dest_city": dest_location["city"]
                             }
                  }
        if "src_port" in new_data.keys():
            point["fields"]["src_port"] = new_data["src_port"]
            point["fields"]["dest_port"] = new_data["dest_port"]
    except Exception as e:
        print("Error parsing eve log")
        print(e)
        print(new_data)
        return

    try:
        client = InfluxDBClient(config["influx"]["host"], config["influx"]["port"], config["influx"]["user"], config["influx"]["password"], config["influx"]["db_name"])
        client.write_points([point])
    except Exception as e:
        print("Error writing to influxdb")
        print(e)
        print(new_data)


def email_alert(msg):
    """Screen the msg based on severity prior to sending an alert email"""
    try:
        severity = msg["alert"]["severity"]
        if severity in alert_severity:
            alert_args = msg["alert"]
            alert_args["timestamp"] = msg["timestamp"]
            alert_args["src_ip"] = msg["src_ip"]
            alert_args["dest_ip"] = msg["dest_ip"]
            alert_msg = alert_template.substitute(alert_args)
            msg_args = {"To": config["mail"]["alert_user"],
                        "Subject": "Severity %s IDS event" % severity,
                        "preamble": "IDS event detected by suricata",
                        "msg_args": {"msg_body": alert_msg}
                        }
            send_mail(msg_args)
    except Exception as e:
        print("Error Emailing Alert")
        print(e)
        print(msg)

def main(args):
    global config, geoip_city
    config = yaml.safe_load(open(args[2], "r"))
    geoip_city = geoip2.database.Reader(config["city_db_path"])
    with open(args[1], 'r') as f:
        for line in tail(f):
            try:
                msg = json.loads(line)
                if msg["event_type"] == "alert":
                    log_alert(msg)
                    if config["email"]["enabled"]:
                        email_alert(msg)
            except Exception as e:
                #FIXME: better handling here - stats msgs seem to break it
                print("Error in parsing json message")
                print(e)
                print(msg)


if __name__ == "__main__":
    args_ = sys.argv
    if len(args_) < 2:
        print("Usage: alert_logging.py log_filename config.yaml")
        sys.exit()
    main(args_)
