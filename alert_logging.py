import sys
import ssl
import time
import json
import smtplib
import geohash
import geoip2.database
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from influxdb import InfluxDBClient
from templates import alert_template
from secrets import influx_db_name, influx_host, influx_port, influx_user, influx_password, mail_host, mail_port, mail_password, mail_user, alert_user, city_db_path, default_location

poll_frequency = 30  # Frequency in seconds
local_range = "192.168."
geoip_city = geoip2.database.Reader(city_db_path)
ssl_context = ssl.create_default_context()


def send_mail(msg, args):
    with smtplib.SMTP_SSL(host=mail_host, port=mail_port, context=ssl_context) as mail_server:
        mail_server.login(mail_user, mail_password)
        main_msg = MIMEMultipart()
        main_msg['Subject'] = "IDS Alert"
        main_msg['To'] = alert_user
        main_msg['From'] = mail_user
        main_msg.preamble = "IDS alert triggered by suricata."
        msg_body = MIMEText(msg.substitute(args))
        main_msg.attach(msg_body)
        mail_server.sendmail(mail_user, alert_user, main_msg)

def tail(f):
    while True:
        where = f.tell()
        line = f.readline()
        if not line or line == "\n":
            time.sleep(poll_frequency)
            f.seek(where)
        else:
            yield line

def get_location(ip):
    if local_range in ip:
        return default_location
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
        client = InfluxDBClient(influx_host, influx_port, influx_user, influx_password, influx_db_name)
        client.write_points([point])
    except Exception as e:
        print("Error writing to influxdb")
        print(e)
        print(new_data)


def main(args):
    with open(args[1], 'r') as f:
        for line in tail(f):
            try:
                msg = json.loads(line)
                if msg["event_type"] == "alert":
                    log_alert(msg)
            except Exception as e:
                #FIXME: better handling here - stats msgs seem to break it
                pass
                print("Error in parsing json message")
                print(e)
                print(msg)


if __name__ == "__main__":
    args_ = sys.argv
    if len(args_) < 2:
        print("Usage: alert_logging.py filename")
        sys.exit()
    main(args_)
