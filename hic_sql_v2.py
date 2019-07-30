#!/usr/bin/python3

import csv, re, optparse, sys, sqlite3, os
from datetime import datetime
from sqlite3 import Error

class HIC:

    input_file = ""
    db_file = ""
    csv_re = re.compile(r"\.csv")
    hic_re = re.compile(r"^Host\sIntegrity\scheck\spassed")
    computer_list = []
    total_hosts = 0

    def __init__(self, input_file):
        # Fetch the input file
        self.input_file = input_file

        # Create DB file
        self.db_file = self.csv_re.sub(".db", self.input_file)

        # Check if the file already exists
        # Cleaning up the remains of previous script, this will usually happen if the script is not terminated properly
        if os.path.exists(self.db_file):
            os.remove(self.db_file)

        # Parse CSV file and add to the database
        # Initialize the database
        conn = sqlite3.connect(self.db_file)
        cursor_create_table = conn.cursor()
        sql_query = "create table hic(timestamp BIGINT, hostname, desc, dlp, sep, pgp, sccm, dot3svc, bckpsvc, laps, cp, winevt, gp_client, remote_reg, bluecoat, windefender, win_telemetry, llmnr, netbios);"
        cursor_create_table.execute(sql_query)
        conn.commit()
        sql_query = "create table analysis(timestamp BIGINT, hostname, dlp, sep, pgp, sccm, dot3svc, bckpsvc, laps, cp, winevt, gp_client, remote_reg, bluecoat, windefender, win_telemetry, llmnr, netbios);"
        cursor_create_table.execute(sql_query)
        conn.commit()
        conn.close()

        # Read the CSV and insert the data in the database
        with open(self.input_file, "r") as csv_file:
            reader = csv.DictReader(csv_file)
            line_count = 0
            conn = sqlite3.connect(self.db_file)
            cursor_insert = conn.cursor()
            for row in reader:
                date = self.__getdate__(row["Event Time"])
                epoch = int((date - datetime(1970, 1, 1)).total_seconds())
                print("[*] Processing sequence {}".format(line_count + 1), end = "\r")
                hostname = row["Host Name"]
                dlp = row["DLP"] if "DLP" in row.keys() else "NA"
                sep = row["SEP"] if "SEP" in row.keys() else "NA"
                pgp = row["PGP Tray"] if "PGP Tray" in row.keys() else "NA"
                sccm = row["SCCM"] if "SCCM" in row.keys() else "NA"
                dot3svc = row["dot3svc"] if "dot3svc" in row.keys() else "NA"
                bckpsvc = row["A BCKPSVC"] if "A BCKPSVC" in row.keys() else "NA"
                laps = row["LAPS Check"] if "LAPS Check" in row.keys() else "NA"
                cp = row["ClearPass Check"] if "ClearPass Check" in row.keys() else "NA"
                winevt = row["Windows EventLog"] if "Windows EventLog" in row.keys() else "NA"
                gp_client = row["Group Policy Client"] if "Group Policy Client" in row.keys() else "NA"
                remote_reg = row["RemoteRegistry Check"] if "RemoteRegistry Check" in row.keys() else "NA"
                bluecoat = row["Blue Coat Unified Agent"] if "Blue Coat Unified Agent" in row.keys() else "NA"
                windefender = row["WinDefender - Win10 only"] if "WinDefender - Win10 only" in row.keys() else "NA"
                win_telemetry = row["Windows 10 Telemetry Check"] if "Windows 10 Telemetry Check" in row.keys() else "NA"
                llmnr = row["LLMNR Multicast Disabled check"] if "LLMNR Multicast Disabled check" in row.keys() else "NA"
                netbios = row["NetBIOS"] if "NetBIOS Check" in row.keys() else "NA"
                desc = row["Compliance Description"]
                
                sql_query = "INSERT INTO hic VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
                values = (epoch, hostname, desc, dlp, sep, pgp, sccm, dot3svc, bckpsvc, laps, cp, winevt, gp_client, remote_reg, bluecoat, windefender, win_telemetry, llmnr, netbios)
                try:
                    cursor_insert.execute(sql_query, values)
                    conn.commit()
                except Error as e:
                    print ("[-] Error inserting values. {}".format(e))
                line_count += 1
            conn.close()
            if line_count > 20000:
                print("[*] Phewww!!! That was exhaustive. Processed {} lines of data.".format(line_count))
            else:
                print("[*] That was pretty easy! Processed {} lines of data.".format(line_count))
            
            conn = sqlite3.connect(self.db_file)
            cursor_select = conn.cursor()
            sql_query = "SELECT DISTINCT hostname FROM hic;"
            results = cursor_select.execute(sql_query)
            for result in results:
                hostname = result[0]
                self.computer_list.append(hostname)
            conn.close()
            self.total_hosts = len(self.computer_list)


    def __getdate__(self, date_string = ""):
        try:
            date = datetime.strptime(date_string.split(" ")[0], "%m/%d/%Y")
        except ValueError:
            try:
                date = datetime.strptime(date_string.split(" ")[0], "%d/%m/%Y")
            except ValueError:
                print("[-] Error parsing the date value -  {}".format(date_string))
                date = datetime(1970, 1, 1)
        return date


    def analyze(self):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        current = 0
        for host in self.computer_list:
            self.__printprogress__(current + 1, self.total_hosts)
            sql_query = "SELECT DISTINCT timestamp FROM hic WHERE hostname = '{}';".format(host)
            timestamps = cursor.execute(sql_query)
            latest = 0
            for timestamp in timestamps:
                if (timestamp[0] > latest):
                    latest = timestamp[0]
            sql_query = "SELECT * FROM hic WHERE hostname = '{}' AND timestamp = {};".format(host, latest)
            results = cursor.execute(sql_query)
            hic = 0
            dlp = 0
            sep = 0
            pgp = 0
            sccm = 0
            dot3svc = 0
            bckpsvc = 0
            laps = 0
            cp = 0
            winevt = 0
            gp_client = 0
            remote_reg = 0
            bluecoat = 0
            windefender = 0
            win_telemetry = 0
            llmnr = 0
            netbios = 0
            last_row = None
            for row in results:
                hic += 1 if self.hic_re.match(row[2]) else 0
                dlp += 1 if row[2] == "DLP Check Failed" else 0
                sep += 1 if row[2] == "SEP Check Failed" else 0
                pgp += 1 if row[2] == "PGP Check Failed" else 0
                sccm += 1 if row[2] == "SCCM Check Failed" else 0
                dot3svc += 1 if row[2] == "Dot3svc check failed" else 0
                bckpsvc += 1 if row[2] == "BCKPSVC check failed" else 0
                laps += 1 if row[2] == "LAPS failed" else 0
                cp += 1 if row[2] == "ClearPass Check Failed" else 0
                winevt += 1 if row[2] == "Windows Event Logging failed" else 0
                gp_client += 1 if row[2] == "Group Poilicy client (gpsvc) failed" else 0
                remote_reg += 1 if row[2] == "Remote Registry should be disabled - Check failed" else 0
                bluecoat += 1 if row[2] == "BlueCoat Unified Agent (Home Proxy) failed" else 0
                windefender += 1 if row[2] == "WD ATP failed" else 0
                win_telemetry += 1 if row[2] == "Win10 Telemetry proxy configuration check failed" else 0
                llmnr += 1 if row[2] == "LLMNR not Disabled – failed" else 0
                netbios += 1 if row[2] == "NetBios should be disabled - check failed" else 0
                last_row = row

            dlp = "fail" if dlp == hic else "pass"
            sep = "fail" if sep == hic else "pass"
            pgp = "fail" if pgp == hic else "pass"
            sccm = "fail" if sccm == hic else "pass"
            dot3svc = "fail" if dot3svc == hic else "pass"
            bckpsvc = "fail" if bckpsvc == hic else "pass"
            laps = "fail" if laps == hic else "pass"
            cp = "fail" if cp == hic else "pass"
            winevt = "fail" if winevt == hic else "pass"
            gp_client = "fail" if gp_client == hic else "pass"
            remote_reg = "fail" if remote_reg == hic else "pass"
            bluecoat = "fail" if bluecoat == hic else "pass"
            windefender = "fail" if windefender == hic else "pass"
            win_telemetry = "fail" if win_telemetry == hic else "pass"
            llmnr = "fail" if llmnr == hic else "pass"
            netbios = "fail" if netbios == hic else "pass"

            dlp = "NA" if last_row[3] == "NA" else dlp
            sep = "NA" if last_row[4] == "NA" else sep
            pgp = "NA" if last_row[5] == "NA" else pgp
            sccm = "NA" if last_row[6] == "NA" else sccm
            dot3svc = "NA" if last_row[7] == "NA" else dot3svc
            bckpsvc = "NA" if last_row[8] == "NA" else bckpsvc
            laps = "NA" if last_row[9] == "NA" else laps
            cp = "NA" if last_row[10] == "NA" else cp
            winevt = "NA" if last_row[11] == "NA" else winevt
            gp_client = "NA" if last_row[12] == "NA" else gp_client
            remote_reg = "NA" if last_row[13] == "NA" else remote_reg
            bluecoat = "NA" if last_row[14] == "NA" else bluecoat
            windefender = "NA" if last_row[15] == "NA" else windefender
            win_telemetry = "NA" if last_row[16] == "NA" else win_telemetry
            llmnr = "NA" if last_row[17] == "NA" else llmnr
            netbios = "NA" if last_row[18] == "NA" else netbios

            sql_query = "INSERT INTO analysis VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
            values = (latest, host, dlp, sep, pgp, sccm, dot3svc, bckpsvc, laps, cp, winevt, gp_client, remote_reg, bluecoat, windefender, win_telemetry, llmnr, netbios)

            try:
                cursor.execute(sql_query, values)
                conn.commit()
            except Error as e:
                print("[-] An error occured. {}".format(e))
            
            current += 1

        conn.close()
        print(" "*102, end = '\r')
        print("[*] Analysis complete.")


    def __printprogress__(self, completed, total):
        if completed < total and total != 0:
            per = int (completed * 100 / total)
            blanks = 100 - per
            print("[{}{}]".format("#"*per, " "*blanks), end='\r')
        else:
            print("[{}]".format("#"*100), end='\r')


    def toHTML(self):
        html_filename = self.csv_re.sub(".html", self.input_file)
        html_data = """<!DOCTYPE html><html><head><title>Host Integrity Check Analysis</title>
            <style type='text/css'>
                .low {
                    color: red;
                }
                .medium{
                    color: orange;
                }
                .high {
                    color: green;
                }
                .na {
                    color: blue;
                    font-weight: bold;
                }
                th, td {
                    border: 1px solid black;
                    padding: 5px;
                }
                th {
                    background-color: black;
                    color: white
                }
            </style>
        </head>
        <body>
        <h1>Host Integrity Check</h1><hr />
        """

        conn = sqlite3.connect(self.db_file)
        cursor_select = conn.cursor()

        sql_query = "SELECT * FROM analysis;"

        cursor_select.execute(sql_query)
        results = cursor_select.fetchall()

        sep = 0
        dlp = 0
        pgp = 0
        sccm = 0
        dot3svc = 0
        bckpsvc = 0
        laps = 0
        cp = 0
        winevt = 0
        gp_client = 0
        remote_reg = 0
        bluecoat = 0
        windefender = 0
        win_telemetry = 0
        llmnr = 0
        netbios = 0

        for row in results:
            if row[2] == "pass" and dlp != "NA":
                dlp += 1
            if row[2] == "NA":
                dlp = "NA"
            if row[3] == "pass" and sep != "NA":
                sep += 1
            if row[3] == "NA":
                sep = "NA"
            if row[4] == "pass" and pgp != "NA":
                pgp += 1
            if row[4] == "NA":
                pgp = "NA"
            if row[5] == "pass" and sccm != "NA":
                sccm += 1
            if row[5] == "NA":
                sccm = "NA"
            if row[6] == "pass" and dot3svc != "NA":
                dot3svc += 1
            if row[6] == "NA":
                dot3svc = "NA"
            if row[7] == "pass" and bckpsvc != "NA":
                bckpsvc += 1
            if row[7] == "NA":
                bckpsvc = "NA"
            if row[8] == "pass" and laps != "NA":
                laps += 1
            if row[8] == "NA":
                laps = "NA"
            if row[9] == "pass" and cp != "NA":
                cp += 1
            if row[9] == "NA":
                cp = "NA"
            if row[10] == "pass" and winevt != "NA":
                winevt += 1
            if row[10] == "NA":
                winevt = "NA"
            if row[11] == "pass" and gp_client != "NA":
                gp_client += 1
            if row[11] == "NA":
                gp_client = "NA"
            if row[12] == "pass" and remote_reg != "NA":
                remote_reg += 1
            if row[12] == "NA":
                remote_reg = "NA"
            if row[13] == "pass" and bluecoat != "NA":
                bluecoat += 1
            if row[13] == "NA":
                bluecoat = "NA"
            if row[14] == "pass" and windefender != "NA":
                windefender += 1
            if row[14] == "NA":
                windefender = "NA"
            if row[15] == "pass" and win_telemetry != "NA":
                win_telemetry += 1
            if row[15] == "NA":
                win_telemetry = "NA"
            if row[16] == "pass" and llmnr != "NA":
                llmnr += 1
            if row[16] == "NA":
                llmnr = "NA"
            if row[17] == "pass" and netbios != "NA":
                netbios += 1
            if row[17] == "NA":
                netbios = "NA"
        conn.close()

        sep_per = float(int((sep * 100 / self.total_hosts)*100)/100) if sep != "NA" else "NA"
        dlp_per = float(int((dlp * 100 / self.total_hosts)*100)/100) if dlp != "NA" else "NA"
        pgp_per = float(int((pgp * 100 / self.total_hosts)*100)/100) if pgp != "NA" else "NA"
        sccm_per = float(int((sccm * 100 / self.total_hosts)*100)/100) if sccm != "NA" else "NA"
        dot3svc_per = float(int((dot3svc * 100 / self.total_hosts)*100)/100) if dot3svc != "NA" else "NA"
        bckpsvc_per = float(int((bckpsvc * 100 / self.total_hosts)*100)/100) if bckpsvc != "NA" else "NA"
        laps_per = float(int((laps * 100 / self.total_hosts)*100)/100) if laps != "NA" else "NA"
        cp_per = float(int((cp * 100 / self.total_hosts)*100)/100) if cp != "NA" else "NA"
        winevt_per = float(int((winevt * 100 / self.total_hosts)*100)/100) if winevt != "NA" else "NA"
        gp_client_per = float(int((gp_client * 100 / self.total_hosts)*100)/100) if gp_client != "NA" else "NA"
        remote_reg_per = float(int((remote_reg * 100 / self.total_hosts)*100)/100) if remote_reg != "NA" else "NA"
        bluecoat_per = float(int((bluecoat * 100 / self.total_hosts)*100)/100) if bluecoat != "NA" else "NA"
        windefender_per = float(int((windefender * 100 / self.total_hosts)*100)/100) if windefender != "NA" else "NA"
        win_telemetry_per = float(int((win_telemetry * 100 / self.total_hosts)*100)/100) if win_telemetry != "NA" else "NA"
        llmnr_per = float(int((llmnr * 100 / self.total_hosts)*100)/100) if llmnr != "NA" else "NA"
        netbios_per = float(int((netbios * 100 / self.total_hosts)*100)/100) if netbios != "NA" else "NA"

        html_data += "<table><tr><th>" + str(self.total_hosts) + " endponit(s)</th><th> % Coverage </th></tr>"
        html_data += "<tr><td>SEP Agent</td><td>"
        if sep_per != "NA":
            if sep_per >= 90.0:
                html_data += "<span class='high'>" + str(sep_per) + "%</span>"
            elif sep_per >=80.0 and sep_per < 90.0:
                html_data += "<span class='medium'>" + str(sep_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(sep_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(sep_per) + "</span>"
        
        html_data += "</td></tr><tr><td>DLP Agent</td><td>"
        if dlp_per != "NA":
            if dlp_per >= 90.0:
                html_data += "<span class='high'>" + str(dlp_per) + "%</span>"
            elif dlp_per >=80.0 and dlp_per < 90.0:
                html_data += "<span class='medium'>" + str(dlp_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(dlp_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(dlp_per) + "</span>"

        html_data += "</td></tr><tr><td>PGP Enabled</td><td>" #BCKPSVC -> Active Defense Agent, LAPS -> LAPS Installed, WinDefender -> Windows Defender Enabled
        if pgp_per != "NA":
            if pgp_per >= 90.0:
                html_data += "<span class='high'>" + str(pgp_per) + "%</span>"
            elif pgp_per >=80.0 and pgp_per < 90.0:
                html_data += "<span class='medium'>" + str(pgp_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(pgp_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(pgp_per) + "</span>"

        html_data += "</td></tr><tr><td>SCCM</td><td>"
        if sccm_per != "NA":
            if sccm_per >= 90.0:
                html_data += "<span class='high'>" + str(sccm_per) + "%</span>"
            elif sccm_per >=80.0 and sccm_per < 90.0:
                html_data += "<span class='medium'>" + str(sccm_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(sccm_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(sccm_per) + "</span>"

        html_data += "</td></tr><tr><td>DOT 3 SVC</td><td>"
        if dot3svc_per != "NA":
            if dot3svc_per >= 90.0:
                html_data += "<span class='high'>" + str(dot3svc_per) + "%</span>"
            elif dot3svc_per >=80.0 and dot3svc_per < 90.0:
                html_data += "<span class='medium'>" + str(dot3svc_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(dot3svc_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(dot3svc_per) + "</span>"

        html_data += "</td></tr><tr><td>Active Defense Agent</td><td>"
        if bckpsvc_per != "NA":
            if bckpsvc_per >= 90.0:
                html_data += "<span class='high'>" + str(bckpsvc_per) + "%</span>"
            elif bckpsvc_per >=80.0 and bckpsvc_per < 90.0:
                html_data += "<span class='medium'>" + str(bckpsvc_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(bckpsvc_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(bckpsvc_per) + "</span>"

        html_data += "</td></tr><tr><td>LAPS Installed</td><td>"
        if laps_per != "NA":
            if laps_per >= 90.0:
                html_data += "<span class='high'>" + str(laps_per) + "%</span>"
            elif laps_per >=80.0 and laps_per < 90.0:
                html_data += "<span class='medium'>" + str(laps_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(laps_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(laps_per) + "</span>"

        html_data += "</td></tr><tr><td>ClearPass Agent</td><td>"
        if cp_per != "NA":
            if cp_per >= 90.0:
                html_data += "<span class='high'>" + str(cp_per) + "%</span>"
            elif cp_per >=80.0 and cp_per < 90.0:
                html_data += "<span class='medium'>" + str(cp_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(cp_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(cp_per) + "</span>"

        html_data += "</td></tr><tr><td>Windows Event Logging</td><td>"
        if winevt_per != "NA":
            if winevt_per >= 90.0:
                html_data += "<span class='high'>" + str(winevt_per) + "%</span>"
            elif winevt_per >=80.0 and winevt_per < 90.0:
                html_data += "<span class='medium'>" + str(winevt_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(winevt_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(winevt_per) + "</span>"

        html_data += "</td></tr><tr><td>Group Policy Client</td><td>"
        if gp_client_per != "NA":
            if gp_client_per >= 90.0:
                html_data += "<span class='high'>" + str(gp_client_per) + "%</span>"
            elif gp_client_per >=80.0 and gp_client_per < 90.0:
                html_data += "<span class='medium'>" + str(gp_client_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(gp_client_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(gp_client_per) + "</span>"

        html_data += "</td></tr><tr><td>Remote Registry Disabled</td><td>"
        if remote_reg_per != "NA":
            if remote_reg_per >= 90.0:
                html_data += "<span class='high'>" + str(remote_reg_per) + "%</span>"
            elif remote_reg_per >=80.0 and remote_reg_per < 90.0:
                html_data += "<span class='medium'>" + str(remote_reg_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(remote_reg_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(remote_reg_per) + "</span>"

        html_data += "</td></tr><tr><td>Bluecoat Agent</td><td>"
        if bluecoat_per != "NA":
            if bluecoat_per >= 90.0:
                html_data += "<span class='high'>" + str(bluecoat_per) + "%</span>"
            elif bluecoat_per >=80.0 and bluecoat_per < 90.0:
                html_data += "<span class='medium'>" + str(bluecoat_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(bluecoat_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(bluecoat_per) + "</span>"

        html_data += "</td></tr><tr><td>Windwos Defender Enabled (Windows 10)</td><td>"
        if windefender_per != "NA":
            if windefender_per >= 90.0:
                html_data += "<span class='high'>" + str(windefender_per) + "%</span>"
            elif windefender_per >=80.0 and windefender_per < 90.0:
                html_data += "<span class='medium'>" + str(windefender_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(windefender_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(windefender_per) + "</span>"

        html_data += "</td></tr><tr><td>Windows 10 Telemetry Enabled</td><td>"
        if win_telemetry_per != "NA":
            if win_telemetry_per >= 90.0:
                html_data += "<span class='high'>" + str(win_telemetry_per) + "%</span>"
            elif win_telemetry_per >=80.0 and win_telemetry_per < 90.0:
                html_data += "<span class='medium'>" + str(win_telemetry_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(win_telemetry_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(win_telemetry_per) + "</span>"

        html_data += "</td></tr><tr><td>LLMNR Multicast Disabled</td><td>"
        if llmnr_per != "NA":
            if llmnr_per >= 90.0:
                html_data += "<span class='high'>" + str(llmnr_per) + "%</span>"
            elif llmnr_per >=80.0 and llmnr_per < 90.0:
                html_data += "<span class='medium'>" + str(llmnr_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(llmnr_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(llmnr_per) + "</span>"

        html_data += "</td></tr><tr><td>NetBIOS Disabled</td><td>"
        if netbios_per != "NA":
            if netbios_per >= 90.0:
                html_data += "<span class='high'>" + str(netbios_per) + "%</span>"
            elif netbios_per >=80.0 and netbios_per < 90.0:
                html_data += "<span class='medium'>" + str(netbios_per) + "%</span>"
            else:
                html_data += "<span class='low'>" + str(netbios_per) + "%</span>"
        else:
            html_data += "<span class='na'>" + str(netbios_per) + "</span>"

        html_data += "</td></tr></table>"
        print("[*] BDW, total number of endpoints is {}".format(self.total_hosts))
        html_data += "</body></html>"

        html_file = open(html_filename, "w")
        html_file.write(html_data)
        html_file.close()

        print("[*] Output written to '{}'".format(html_filename))

        #Clean up datebase code
        os.remove(self.db_file)
        

def main():
    parser = optparse.OptionParser(str(sys.argv[0]) + " can be used to parse the Host Integrity Check CSV output to HTML.\n")
    parser.add_option("-c", "--csv", dest="csv_file", help="CSV output file for Host Integrity Check.")

    (options, argv) = parser.parse_args()

    if not options.csv_file:
        parser.print_help()
        sys.exit(1)

    hic = HIC(options.csv_file)
    hic.analyze()
    hic.toHTML()

if __name__  == "__main__":
    main()