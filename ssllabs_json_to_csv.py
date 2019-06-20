#!/usr/bin/python

import pandas as pd
from pandas.io.json import json_normalize
import time

filename = "C:\\Users\\Sumit Shrivastava\\Downloads\\ssllabs-scan_1.4.0_win64\\output.json"
json_data = pd.read_json(filename)

csv_data = "Sr. No., Host, Grade, Has Warnings, Certificate Expiry, Forward Secracy, Heartbeat Ext, BEAST, DROWN, Heartbleed, FREAK, OpenSSL CCS, OpenSSL LuckyMinus20, POODLE, POODLE TLS, TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0, SSL 3.0, SSL 2.0\n"

def get_time(epoch_time=""):
    fmt = "%d-%m-%Y %H:%M:%S"
    epoch = epoch_time
    return time.strftime(fmt, time.gmtime(epoch/1000.))


def toYN(value = ""):
    if value == "false" or value == 0:
        return "No"
    else:
        return "Yes"

total_count = len(json_data["host"])

for i in range(0, len(json_data["host"])):
    print "\rProcessing", str(i+1), "of", total_count,
    if json_data["status"][i] == "READY":
        host = json_data["host"][i]
        output = json_data["endpoints"][i][0]
        grade = output["grade"]
        hasWarnings = "No"
        cert_exp = get_time(output["details"]["cert"]["notAfter"])
        if output["details"]["forwardSecrecy"] > 0:
            forward_secracy = "Yes"
        else:
            forward_secracy = "No"
        heartbeat = toYN(output["details"]["heartbeat"])
        beast = toYN(output["details"]["vulnBeast"])
        drwon = toYN(output["details"]["drownVulnerable"])
        heartbleed = toYN(output["details"]["heartbleed"])
        freak = toYN(output["details"]["freak"])
        openssl_ccs = toYN(output["details"]["openSslCcs"])
        lm20 = toYN(output["details"]["openSSLLuckyMinus20"])
        poodle = toYN(output["details"]["poodle"])
        poodle_tls = toYN(output["details"]["poodleTls"])
        protocols = output["details"]["protocols"]
        ssl2 = "No"
        ssl3 = "No"
        tls10 = "No"
        tls11 = "No"
        tls12 = "No"
        tls13 = "No"
        for protocol in protocols:
            if protocol["name"] == "TLS":
                if protocol["version"] == "1.0":
                    tls10 = "Yes"
                if protocol["version"] == "1.1":
                    tls11 = "Yes"
                if protocol["version"] == "1.2":
                    tls12 = "Yes"
                if protocol["version"] == "1.3":
                    tls13 = "Yes"
            if protocol["name"] == "SSL":
                if protocol["version"] == "2.0":
                    ssl2 = "Yes"
                if protocol["version"] == "3.0":
                    ssl3 = "Yes"
        csv_data += str(i+1) + "," + host + "," + grade + "," +  hasWarnings + "," + cert_exp + "," + forward_secracy + "," + heartbeat + "," + beast + "," + drwon + "," + heartbleed + "," + freak + "," + openssl_ccs + "," + lm20 + "," + poodle + "," + poodle_tls + "," + tls13 + "," + tls12 + "," + tls11 + "," + tls10 + "," + ssl3 + "," + ssl2 + "\n"
        status = "READY"

    else:
        host = json_data["host"][i]
        hasWarnings = json_data["status"][i]
        cert_exp = ""
        grade = ""
        forward_secracy = ""
        heartbeat = ""
        beast = ""
        drwon = ""
        heartbleed = ""
        freak = ""
        openssl_ccs = ""
        lm20 = ""
        poodle = ""
        poodle_tls = ""
        protocols = ""
        ssl2 = ""
        ssl3 = ""
        tls10 = ""
        tls11 = ""
        tls12 = ""
        tls13 = ""
        csv_data += str(i+1) + "," + host + "," + grade + "," +  hasWarnings + "," + cert_exp + "," + forward_secracy + "," + heartbeat + "," + beast + "," + drwon + "," + heartbleed + "," + freak + "," + openssl_ccs + "," + lm20 + "," + poodle + "," + poodle_tls + "," + tls13 + "," + tls12 + "," + tls11 + "," + tls10 + "," + ssl3 + "," + ssl2 + "\n"


print "\nAll records processed. Writing to CSV."
# Write to CSV File
output_csv_file = open("output.csv", "w")
output_csv_file.write(csv_data)
output_csv_file.close()
print "Data written to 'output.csv'"