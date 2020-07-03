"""
JSON reputation responses for testing
References from apivoid.com API documentation examples.
"""
import json

# IP Reputation Responses
clean_ip_response = """
{
   "data":{
      "report":{
         "ip":"122.226.181.165",
         "blacklists":{
            "engines":{
               "9":{
                  "engine":"Anti-Attacks BL",
                  "detected":false,
                  "reference":"https:\/\/www.anti-attacks.com\/",
                  "elapsed":"0.00"
               }
            },
            "detections":0,
            "engines_count":1,
            "detection_rate":"0%",
            "scantime":"0.60"
         },
         "information":{
            "reverse_dns":"",
            "continent_code":"AS",
            "continent_name":"Asia",
            "country_code":"CN",
            "country_name":"China",
            "region_name":"Zhejiang",
            "city_name":"Jiaojiang",
            "latitude":28.680280685424805,
            "longitude":121.44277954101562,
            "isp":"ChinaNet Zhejiang Province Network"
         },
         "anonymity":{
            "is_proxy":false,
            "is_webproxy":false,
            "is_vpn":false,
            "is_hosting":false,
            "is_tor":false
         }
      }
   },
   "credits_remained":24.66,
   "estimated_queries":"308",
   "elapsed_time":"2.72",
   "success":true
}
"""
clean_ip_response_dict = json.loads(clean_ip_response)

blacklist_ip_response = """
{
   "data":{
      "report":{
         "ip":"122.226.181.165",
         "blacklists":{
            "engines":{
               "9":{
                  "engine":"Anti-Attacks BL",
                  "detected":true,
                  "reference":"https:\/\/www.anti-attacks.com\/",
                  "elapsed":"0.00"
               }
            },
            "detections":1,
            "engines_count":1,
            "detection_rate":"100%",
            "scantime":"0.60"
         },
         "information":{
            "reverse_dns":"",
            "continent_code":"AS",
            "continent_name":"Asia",
            "country_code":"CN",
            "country_name":"China",
            "region_name":"Zhejiang",
            "city_name":"Jiaojiang",
            "latitude":28.680280685424805,
            "longitude":121.44277954101562,
            "isp":"ChinaNet Zhejiang Province Network"
         },
         "anonymity":{
            "is_proxy":false,
            "is_webproxy":false,
            "is_vpn":false,
            "is_hosting":false,
            "is_tor":false
         }
      }
   },
   "credits_remained":24.66,
   "estimated_queries":"308",
   "elapsed_time":"2.72",
   "success":true
}
"""
blacklist_ip_response_dict = json.loads(blacklist_ip_response)

anon_ip_response = """
{
   "data":{
      "report":{
         "ip":"122.226.181.165",
         "blacklists":{
            "engines":{
               "9":{
                  "engine":"Anti-Attacks BL",
                  "detected":true,
                  "reference":"https:\/\/www.anti-attacks.com\/",
                  "elapsed":"0.00"
               }
            },
            "detections":1,
            "engines_count":1,
            "detection_rate":"100%",
            "scantime":"0.60"
         },
         "information":{
            "reverse_dns":"",
            "continent_code":"AS",
            "continent_name":"Asia",
            "country_code":"CN",
            "country_name":"China",
            "region_name":"Zhejiang",
            "city_name":"Jiaojiang",
            "latitude":28.680280685424805,
            "longitude":121.44277954101562,
            "isp":"ChinaNet Zhejiang Province Network"
         },
         "anonymity":{
            "is_proxy":false,
            "is_webproxy":false,
            "is_vpn":false,
            "is_hosting":false,
            "is_tor":true
         }
      }
   },
   "credits_remained":24.66,
   "estimated_queries":"308",
   "elapsed_time":"2.72",
   "success":true
}
"""
anon_ip_response_dict = json.loads(anon_ip_response)


# Domain Reputation Responses
clean_domain_response = """
{
   "data":{
      "report":{
         "host":"google.com",
         "domain_length":10,
         "most_abused_tld":false,
         "alexa_top_10k":false,
         "alexa_top_100k":false,
         "alexa_top_250k":false,
         "blacklists":{
            "engines":{
               "4":{
                  "engine":"AntiSocial Blacklist",
                  "detected": false,
                  "reference":"https:\/\/theantisocialengineer.com\/",
                  "confidence":"high",
                  "elapsed":"0.00"
               }
            },
            "detections":0,
            "engines_count":1,
            "detection_rate":"0%",
            "scantime":"0.03"
         },
         "category":{
            "is_free_hosting":false,
            "is_anonymizer":false,
            "is_url_shortener":false,
            "is_free_dynamic_dns":false
         },
         "server":{
            "ip":"108.177.12.113",
            "reverse_dns":"ua-in-f113.1e100.net",
            "continent_code":"NA",
            "continent_name":"North America",
            "country_code":"US",
            "country_name":"United States of America",
            "region_name":"California",
            "city_name":"Mountain View",
            "latitude":37.40599060058594,
            "longitude":-122.0785140991211,
            "isp":"Google LLC"
         }
      }
   },
   "credits_remained":101003.71,
   "estimated_queries":"1,262,546",
   "elapsed_time":"0.07",
   "success":true
}
"""
clean_domain_response_dict = json.loads(clean_domain_response)


blacklist_domain_response = """
{
   "data":{
      "report":{
         "host":"google.com",
         "domain_length":10,
         "most_abused_tld":false,
         "alexa_top_10k":true,
         "alexa_top_100k":true,
         "alexa_top_250k":true,
         "blacklists":{
            "engines":{
               "4":{
                  "engine":"AntiSocial Blacklist",
                  "detected": true,
                  "reference":"https:\/\/theantisocialengineer.com\/",
                  "confidence":"high",
                  "elapsed":"0.00"
               }
            },
            "detections":1,
            "engines_count":1,
            "detection_rate":"100%",
            "scantime":"0.03"
         },
         "category":{
            "is_free_hosting":false,
            "is_anonymizer":false,
            "is_url_shortener":false,
            "is_free_dynamic_dns":false
         },
         "server":{
            "ip":"108.177.12.113",
            "reverse_dns":"ua-in-f113.1e100.net",
            "continent_code":"NA",
            "continent_name":"North America",
            "country_code":"US",
            "country_name":"United States of America",
            "region_name":"California",
            "city_name":"Mountain View",
            "latitude":37.40599060058594,
            "longitude":-122.0785140991211,
            "isp":"Google LLC"
         }
      }
   },
   "credits_remained":101003.71,
   "estimated_queries":"1,262,546",
   "elapsed_time":"0.07",
   "success":true
}
"""
blacklist_domain_response_dict = json.loads(blacklist_domain_response)

anon_domain_response = """
{
   "data":{
      "report":{
         "host":"google.com",
         "domain_length":10,
         "most_abused_tld":false,
         "alexa_top_10k":true,
         "alexa_top_100k":true,
         "alexa_top_250k":true,
         "blacklists":{
            "engines":{
               "4":{
                  "engine":"AntiSocial Blacklist",
                  "detected": true,
                  "reference":"https:\/\/theantisocialengineer.com\/",
                  "confidence":"high",
                  "elapsed":"0.00"
               }
            },
            "detections":1,
            "engines_count":1,
            "detection_rate":"100%",
            "scantime":"0.03"
         },
         "category":{
            "is_free_hosting":false,
            "is_anonymizer":true,
            "is_url_shortener":false,
            "is_free_dynamic_dns":false
         },
         "server":{
            "ip":"108.177.12.113",
            "reverse_dns":"ua-in-f113.1e100.net",
            "continent_code":"NA",
            "continent_name":"North America",
            "country_code":"US",
            "country_name":"United States of America",
            "region_name":"California",
            "city_name":"Mountain View",
            "latitude":37.40599060058594,
            "longitude":-122.0785140991211,
            "isp":"Google LLC"
         }
      }
   },
   "credits_remained":101003.71,
   "estimated_queries":"1,262,546",
   "elapsed_time":"0.07",
   "success":true
}
"""
anon_domain_response_dict = json.loads(anon_domain_response)

suspect_country_domain_response = """
{
   "data":{
      "report":{
         "host":"google.com",
         "domain_length":10,
         "most_abused_tld":false,
         "alexa_top_10k":true,
         "alexa_top_100k":true,
         "alexa_top_250k":true,
         "blacklists":{
            "engines":{
               "4":{
                  "engine":"AntiSocial Blacklist",
                  "detected": true,
                  "reference":"https:\/\/theantisocialengineer.com\/",
                  "confidence":"high",
                  "elapsed":"0.00"
               }
            },
            "detections":1,
            "engines_count":1,
            "detection_rate":"100%",
            "scantime":"0.03"
         },
         "category":{
            "is_free_hosting":false,
            "is_anonymizer":true,
            "is_url_shortener":false,
            "is_free_dynamic_dns":false
         },
         "server":{
            "ip":"108.177.12.113",
            "reverse_dns":"ua-in-f113.1e100.net",
            "continent_code":"NA",
            "continent_name":"Europe",
            "country_code":"LV",
            "country_name":"Latvia",
            "region_name":"",
            "city_name":"Riga",
            "latitude":37.40599060058594,
            "longitude":-122.0785140991211,
            "isp":"Google LLC"
         }
      }
   },
   "credits_remained":101003.71,
   "estimated_queries":"1,262,546",
   "elapsed_time":"0.07",
   "success":true
}
"""
suspect_country_domain_response_dict = json.loads(suspect_country_domain_response)
