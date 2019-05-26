#!/usr/bin/python

import re, sys, optparse, csv

def generate_table(list_data = []):
    html_data = "<table><tr><th>IP Address</th><th>Port</th><th>DNS Name</th></tr>"
    counter = 1
    for data in list_data:
        (ip_address, port, dns_name) = data
        html_data+= "<tr><td>" + ip_address + "</td><td>" + port + "</td><td>" + dns_name + "</td></tr>"
    html_data += "</table>"
    return html_data


def sort_ascending(issue_dict = {}):
    sorted_list = []
    for issue_name in issue_dict.keys():
        sorted_list.append({"id": issue_dict[issue_name]["issue_id"], "cvss": issue_dict[issue_name]["cvss"]})

    #Sort IDs
    for i in range(0, len(sorted_list) - 2):
        for j in range(i + 1, len(sorted_list) - 1):
            if sorted_list[j]["cvss"] > sorted_list[i]["cvss"]:
                temp = sorted_list[i]
                sorted_list[i] = sorted_list[j]
                sorted_list[j] = temp

    details_dict = {}

    critical = 0
    critical_list = []
    high = 0
    high_list = []
    medium = 0
    medium_list = []
    low = 0
    low_list = []
    info = 0
    info_list = []

    for element in sorted_list:
        cvss_score = element["cvss"]

        if cvss_score >= 9.0:
            critical += 1
            critical_list.append(element)
        elif cvss_score < 9.0 and cvss_score >= 7.0:
            high += 1
            high_list.append(element)
        elif cvss_score < 7.0 and cvss_score >= 4.0:
            medium += 1
            medium_list.append(element)
        elif cvss_score < 4.0 and cvss_score > 0.0:
            low += 1
            low_list.append(element)
        else:
            info += 1
            info_list.append(element)

    details_dict["critical"] = {"count": critical, "issues": critical_list}
    details_dict["high"] = {"count": high, "issues": high_list}
    details_dict["medium"] = {"count": medium, "issues": medium_list}
    details_dict["low"] = {"count": low, "issues": low_list}
    details_dict["info"] = {"count": info, "issues": info_list}

    return details_dict



def color_code_cvss(severity = ""):
    critical_re = re.compile(r"Critical")
    hihg_re = re.compile(r"High")
    medium_re = re.compile(r"Medium")
    low_re = re.compile(r"Low")
    info_re = re.compile(r"None")

    color_code_cvss = severity

    if critical_re.search(severity):
        color_code_cvss = "<span class='critical'>" + severity + "</span>"

    if hihg_re.search(severity):
        color_code_cvss = "<span class='high'>" + severity + "</span>"

    if medium_re.search(severity):
        color_code_cvss = "<span class='medium'>" + severity + "</span>"

    if low_re.search(severity):
        color_code_cvss = "<span class='low'>" + severity + "</span>"

    if info_re.search(severity):
        color_code_cvss = "<span class='none'>" + severity + "</span>"

    return color_code_cvss



def parse_csv(csv_filename=""):
    issue_dict = {}

    with open(csv_filename, 'r') as csv_file:
        reader = csv.DictReader(csv_file)
        line_count = 0
        issue_id = 0
        for row in reader:
            print "Parsing ", str(line_count + 1), "\r",
            if line_count > 1:
                issue_name = row["Vulnerability"]
                #issue_name = space_re.sub("_", issue_name)
                ip_address = row["IP"]
                dns_name = row["DNS Name"]
                port_num = row["Port"]
                description = row["Description"]
                remediation = row["Remediation"]
                mitigation = row["Mitigation"]
                cvss_score = float(row["CVSS Base Score"])
                
                try:
                    affected_system = (ip_address, port_num, dns_name)
                    if not affected_system in issue_dict[issue_name]["affected_systems"]:
                        issue_dict[issue_name]["affected_systems"].append(affected_system)
                except KeyError:
                    if cvss_score >= 9.0:
                        severity = "Critical (" + str(cvss_score) + ")"
                    elif cvss_score < 9.0 and cvss_score >= 7.0:
                        severity = "High (" + str(cvss_score) + ")"
                    elif cvss_score < 7.0 and cvss_score >= 4.0:
                        severity = "Medium (" + str(cvss_score) + ")"
                    elif cvss_score < 4.0 and cvss_score > 0.0:
                        severity = "Low (" + str(cvss_score) + ")"
                    else:
                        severity = "None (" + str(cvss_score) + ")"
                    issue_dict[issue_name] = {
                        "description":description,
                        "recommendation":remediation + " " + mitigation,
                        "affected_systems": [(ip_address, port_num, dns_name)],
                        "severity": severity,
                        "cvss":cvss_score,
                        "issue_id": issue_id
                    }                 
                    issue_id += 1  
            
            line_count += 1
    
    print "\nTotal issues found:", len(issue_dict.keys())
    return issue_dict


def write_to_html(issue_dict = {}, output_filename="output.html"):
    space_re = re.compile(r"\s")
    html_re = re.compile(r"\.html")
    title_value = html_re.sub('', output_filename)

    stylesheet = """
        h3, p, td, th {
            font-family: Calibri
        }

        table {
            border-collapse: collapse;
        }

        td {
            border: 1px groove #002060;
            padding: 5px;
        }

        th {
            border: 1px groove #002060;
            background: #002060;
            color: white;
            text-align: center;
            padding: 3px;
        }

        .critical {
            color: #c00000;
            font-weight: bold;
        }

        .high {
            color: red;
            font-weight: bold;
        }

        .medium {
            color: #ffc000;
            font-weight: bold;
        }

        .low {
            color: #00b050;
            font-weight: bold;
        }

        .none {
            color: cyan;
            font-weight: bold;
        }

        a:visited {
            color: blue;
        }

    """
    
    html_data = "<!DOCTYPE html><html><head><title>" + title_value + "</title><style>" + stylesheet + "</style></head><body><h1>Technical Report</h1><hr /><p>"
    
    details = sort_ascending(issue_dict=issue_dict)
    critical_count = details["critical"]["count"]
    high_count = details["high"]["count"]
    medium_count = details["medium"]["count"]
    low_count = details["low"]["count"]
    info_count = details["info"]["count"]

    html_data += "<h2>Tabular Summary</h2><table><tr><th>Severity</th><th>Count</th></tr>"
    html_data += "<tr><td><span class='critical'>Critical</span></td><td>" + str(critical_count) + "</td></tr>"
    html_data += "<tr><td><span class='high'>High</span></td><td>" + str(high_count) + "</td></tr>"
    html_data += "<tr><td><span class='medium'>Medium</span></td><td>" + str(medium_count) + "</td></tr>"
    html_data += "<tr><td><span class='low'>Low</span></td><td>" + str(low_count) + "</td></tr>"
    html_data += "<tr><td><span class='none'>Informational</span></td><td>" + str(info_count) + "</td></tr>"
    html_data += "</table>"

    critical_list = details["critical"]["issues"]
    high_list = details["high"]["issues"]
    medium_list = details["medium"]["issues"]
    low_list = details["low"]["issues"]
    info_list = details["info"]["issues"]


    html_data += "<h2 id='toc'>Table of Contents</h2><ol>"

    critical_anchors = []
    if critical_count > 0:
        for issue in critical_list:
            for (issue_name, issue_details) in issue_dict.items():
                if issue["id"] == issue_details["issue_id"]:
                    issue_name_id = space_re.sub("_", issue_name)
                    critical_anchors.append((issue_name, "#" + issue_name_id))
        
        html_data += "<br><div class='critical'>Critical</div>"

        for anchor in critical_anchors:
            (issue_name, issue_name_id) = anchor
            html_data+= "<li><a href='" + issue_name_id + "'>" + issue_name + "</a></li>"

    if high_count > 0:
        high_anchors = []
        for issue in high_list:
            for (issue_name, issue_details) in issue_dict.items():
                if issue["id"] == issue_details["issue_id"]:
                    issue_name_id = space_re.sub("_", issue_name)
                    high_anchors.append((issue_name, "#" + issue_name_id))
        
        html_data += "<br><div class='high'>High</div>"

        for anchor in high_anchors:
            (issue_name, issue_name_id) = anchor
            html_data+= "<li><a href='" + issue_name_id + "'>" + issue_name + "</a></li>"

    if medium_count > 0:
        medium_anchors = []
        for issue in medium_list:
            for (issue_name, issue_details) in issue_dict.items():
                if issue["id"] == issue_details["issue_id"]:
                    issue_name_id = space_re.sub("_", issue_name)
                    medium_anchors.append((issue_name, "#" + issue_name_id))
        
        html_data += "<br><div class='medium'>Medium</div>"

        for anchor in medium_anchors:
            (issue_name, issue_name_id) = anchor
            html_data+= "<li><a href='" + issue_name_id + "'>" + issue_name + "</a></li>"

    if low_count > 0:
        low_anchors = []
        for issue in low_list:
            for (issue_name, issue_details) in issue_dict.items():
                if issue["id"] == issue_details["issue_id"]:
                    issue_name_id = space_re.sub("_", issue_name)
                    low_anchors.append((issue_name, "#" + issue_name_id))
        
        html_data += "<br><div class='low'>Low</div>"

        for anchor in low_anchors:
            (issue_name, issue_name_id) = anchor
            html_data+= "<li><a href='" + issue_name_id + "'>" + issue_name + "</a></li>"

    if info_count > 0:
        info_anchors = []
        for issue in info_list:
            for (issue_name, issue_details) in issue_dict.items():
                if issue["id"] == issue_details["issue_id"]:
                    issue_name_id = space_re.sub("_", issue_name)
                    info_anchors.append((issue_name, "#" + issue_name_id))
        
        html_data += "<br><div class='none'>Informational</div>"

        for anchor in info_anchors:
            (issue_name, issue_name_id) = anchor
            html_data+= "<li><a href='" + issue_name_id + "'>" + issue_name + "</a></li>"
        
    html_data += "</ol><h2>Technical Observations</h2>"


    counter = 1

    if critical_count > 0:
        for issue in critical_list:
            for issue_name in issue_dict.keys():
                if issue["id"] == issue_dict[issue_name]["issue_id"]:
                    html_data += "<div id='" + str(space_re.sub("_", issue_name)) +  "'><h2 style='color:#002060'>" + str(counter) + ". " + issue_name + "</h2>"
                    html_data += "<h3>Severity</h3>"
                    html_data += "<p align='justify'>" + color_code_cvss(issue_dict[issue_name]["severity"]) + "</p>"
                    html_data += "<h3>Affected Systems</h3>"
                    affected_systems = issue_dict[issue_name]["affected_systems"]
                    html_data += generate_table(affected_systems)
                    html_data += "<h3>Description</h3>"
                    html_data += "<p align='justify'>" + issue_dict[issue_name]["description"] + "</p>"
                    html_data += "<h3>Recommendation</h3>"
                    html_data += "<p align='justify'>" + issue_dict[issue_name]["recommendation"] + "</p>"
                    html_data += "</div><p align='right'><a href='#toc'>Top</a></p><hr><br>"
                    counter += 1

    if high_count > 0:
        for issue in high_list:
            for issue_name in issue_dict.keys():
                if issue["id"] == issue_dict[issue_name]["issue_id"]:
                    html_data += "<div id='" + str(space_re.sub("_", issue_name)) +  "'><h2 style='color:#002060'>" + str(counter) + ". " + issue_name + "</h2>"
                    html_data += "<h3>Severity</h3>"
                    html_data += "<p align='justify'>" + color_code_cvss(issue_dict[issue_name]["severity"]) + "</p>"
                    html_data += "<h3>Affected Systems</h3>"
                    affected_systems = issue_dict[issue_name]["affected_systems"]
                    html_data += generate_table(affected_systems)
                    html_data += "<h3>Description</h3>"
                    html_data += "<p align='justify'>" + issue_dict[issue_name]["description"] + "</p>"
                    html_data += "<h3>Recommendation</h3>"
                    html_data += "<p align='justify'>" + issue_dict[issue_name]["recommendation"] + "</p>"
                    html_data += "</div><p align='right'><a href='#toc'>Top</a></p><hr><br>"
                    counter += 1

    if medium_count > 0:
        for issue in medium_list:
            for issue_name in issue_dict.keys():
                if issue["id"] == issue_dict[issue_name]["issue_id"]:
                    html_data += "<div id='" + str(space_re.sub("_", issue_name)) +  "'><h2 style='color:#002060'>" + str(counter) + ". " + issue_name + "</h2>"
                    html_data += "<h3>Severity</h3>"
                    html_data += "<p align='justify'>" + color_code_cvss(issue_dict[issue_name]["severity"]) + "</p>"
                    html_data += "<h3>Affected Systems</h3>"
                    affected_systems = issue_dict[issue_name]["affected_systems"]
                    html_data += generate_table(affected_systems)
                    html_data += "<h3>Description</h3>"
                    html_data += "<p align='justify'>" + issue_dict[issue_name]["description"] + "</p>"
                    html_data += "<h3>Recommendation</h3>"
                    html_data += "<p align='justify'>" + issue_dict[issue_name]["recommendation"] + "</p>"
                    html_data += "</div><p align='right'><a href='#toc'>Top</a></p><hr><br>"
                    counter += 1

    if low_count > 0:
        for issue in low_list:
            for issue_name in issue_dict.keys():
                if issue["id"] == issue_dict[issue_name]["issue_id"]:
                    html_data += "<div id='" + str(space_re.sub("_", issue_name)) +  "'><h2 style='color:#002060'>" + str(counter) + ". " + issue_name + "</h2>"
                    html_data += "<h3>Severity</h3>"
                    html_data += "<p align='justify'>" + color_code_cvss(issue_dict[issue_name]["severity"]) + "</p>"
                    html_data += "<h3>Affected Systems</h3>"
                    affected_systems = issue_dict[issue_name]["affected_systems"]
                    html_data += generate_table(affected_systems)
                    html_data += "<h3>Description</h3>"
                    html_data += "<p align='justify'>" + issue_dict[issue_name]["description"] + "</p>"
                    html_data += "<h3>Recommendation</h3>"
                    html_data += "<p align='justify'>" + issue_dict[issue_name]["recommendation"] + "</p>"
                    html_data += "</div><p align='right'><a href='#toc'>Top</a></p><hr><br>"
                    counter += 1

    if info_count > 0:
        for issue in info_list:
            for issue_name in issue_dict.keys():
                if issue["id"] == issue_dict[issue_name]["issue_id"]:
                    html_data += "<div id='" + str(space_re.sub("_", issue_name)) +  "'><h2 style='color:#002060'>" + str(counter) + ". " + issue_name + "</h2>"
                    html_data += "<h3>Severity</h3>"
                    html_data += "<p align='justify'>" + color_code_cvss(issue_dict[issue_name]["severity"]) + "</p>"
                    html_data += "<h3>Affected Systems</h3>"
                    affected_systems = issue_dict[issue_name]["affected_systems"]
                    html_data += generate_table(affected_systems)
                    html_data += "<h3>Description</h3>"
                    html_data += "<p align='justify'>" + issue_dict[issue_name]["description"] + "</p>"
                    html_data += "<h3>Recommendation</h3>"
                    html_data += "<p align='justify'>" + issue_dict[issue_name]["recommendation"] + "</p>"
                    html_data += "</div><p align='right'><a href='#toc'>Top</a></p><hr><br>"
                    counter += 1


    html_data += "</body></html>"

    output_file = open(output_filename, "w")
    output_file.write(html_data)
    output_file.close()
    print "[+] Output written to '%s'" %(output_filename)




def main():
    parser = optparse.OptionParser("Script to convert nessus CSV to finding based text file")
    parser.add_option("-c", "--csv", dest="csv_filename", help="CSV File for parsing")

    (options, args) = parser.parse_args()

    if not options.csv_filename:
        print "[-] -c Option is required."
        parser.print_help()
        sys.exit(1)

    csv_re = re.compile(r"\.csv")
    output_filename = csv_re.sub(".html", options.csv_filename)

    write_to_html(parse_csv(options.csv_filename), output_filename)

if __name__ == "__main__":
    main()
