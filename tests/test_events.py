"""
Contains sample Eve JSON events for unit testing.
"""
import json

basic_alert_json = """{
  "timestamp": "2009-11-24T21:27:09.534255",
  "event_type": "alert",
  "src_ip": "192.168.2.7",
  "src_port": 1041,
  "dest_ip": "x.x.250.50",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2001999,
    "rev": 9,
    "signature": "ET MALWARE BTGrab.com Spyware Downloading Ads",
    "category": "A Network Trojan was detected",
    "severity": 1
  }
}"""
basic_alert_dict = json.loads(basic_alert_json)

alert_with_dns_json = """{
  "timestamp": "2020-06-30T22:12:55.421670-0400",
  "flow_id": 711091716321062,
  "in_iface": "eth0",
  "event_type": "alert",
  "vlan": [
    1
  ],
  "src_ip": "192.168.x.x",
  "src_port": 49809,
  "dest_ip": "192.168.x.x",
  "dest_port": 53,
  "proto": "UDP",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2023883,
    "rev": 3,
    "signature": "ET DNS Query to a *.top domain - Likely Hostile",
    "category": "Potentially Bad Traffic",
    "severity": 2,
    "metadata": {
      "updated_at": [
        "2019_09_28"
      ],
      "created_at": [
        "2017_02_07"
      ],
      "signature_severity": [
        "Major"
      ],
      "deployment": [
        "Perimeter"
      ],
      "attack_target": [
        "Client_Endpoint"
      ],
      "affected_product": [
        "Windows_XP_Vista_7_8_10_Server_32_64_Bit"
      ]
    }
  },
  "dns": {
    "query": [
      {
        "type": "query",
        "id": 52550,
        "rrname": "hzv1.sysnet.top",
        "rrtype": "A",
        "tx_id": 0
      }
    ]
  },
  "app_proto": "dns",
  "flow": {
    "pkts_toserver": 1,
    "pkts_toclient": 0,
    "bytes_toserver": 75,
    "bytes_toclient": 0,
    "start": "2020-06-30T22:12:55.421670-0400"
  }
}"""
alert_with_dns_dict = json.loads(alert_with_dns_json)
