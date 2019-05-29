#!/usr/bin/python

import optparse, re, sys, csv


class TripWire:

    def __init__(self, csv_filename = ""):
        self.csv_filename = csv_filename
        self.__parse_csv__()
        
    def __parse_csv__(self):
        self.issue_dict = {}
        scan_details_dict = {}
        issue_details_dict = {}
        summary_dict = {}
        
        with open(self.csv_filename, 'r') as csv_file:
            reader = csv.DictReader(csv_file)
            line_count = 0

            for row in reader:
                line_count += 1

                if line_count > 2:
                    status = row["RuleState"]
                    if status == "Failed":
                        check_name = str(row["RuleName"])
                        description = str(row["TestDescription"])
                        expected_output = str(row["TestExpected"])
                        actual_output = str(row["TestActual"])
                        issue_details_dict[check_name] = {
                            "description": description,
                            "exptected_output":expected_output,
                            "actual_output":actual_output,
                            "status":status
                        }

                        summary_dict[check_name] = {
                            "description":description,
                            "status":status
                        }
                    else:
                        check_name = str(row["RuleName"])
                        description = str(row["TestDescription"])

                        summary_dict[check_name] = {
                            "description":description,
                            "status":status
                        }
                
                if line_count == 2:
                    scan_details_dict["Host"] = row["IP"]
                    scan_details_dict["percent_compliant"] = row["PercentCompliant"]
                    scan_details_dict["policy_name"] = row["PolicyName"]
                    scan_details_dict["policy_type"] = row["PolicyType"]

                    self.issue_dict["details"] = scan_details_dict

                    status = row["RuleState"]
                    if status == "Failed":
                        check_name = str(row["RuleName"])
                        description = str(row["TestDescription"])
                        expected_output = str(row["TestExpected"])
                        actual_output = str(row["TestActual"])
                        issue_details_dict[check_name] = {
                            "description": description,
                            "exptected_output":expected_output,
                            "actual_output":actual_output,
                            "status":status
                        }

                        summary_dict[check_name] = {
                            "description":description,
                            "status":status
                        }
                    else:
                        check_name = str(row["RuleName"])
                        description = str(row["TestDescription"])

                        summary_dict[check_name] = {
                            "description":description,
                            "status":status
                        }

        self.issue_dict["summary"] = summary_dict
        self.issue_dict["issues"] = issue_details_dict


    def __str__(self):
        return str(self.issue_dict)

    def write_to_html(self):
        csv_re = re.compile(r'\.csv')
        output_filename = csv_re.sub('.html', self.csv_filename)
        title = csv_re.sub("", self.csv_filename)

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
                text-align: left;
                padding: 3px;
            }

            a:visited {
                color: blue;
            }

            .code {
                background: #cccccc;
                width: 98%;
                border: 1px solid black;
                padding: 10px;
            }

            .fail {
                color: red;
            }

            .pass {
                color: #00b050;
            }

            .desc {
                white-space: pre-wrap; /*CS3*/
                white-space: -moz-pre-wrap; /*Firefox*/
                white-space: -pre-wrap; /*Opera <7*/
                white-space: -o-pre-wrap; /*Opera 7*/
                word-wrap; break-word; /*IE*/
            }
        """

        scan_details = self.issue_dict["details"]
        scan_summary = self.issue_dict["summary"]
        issues = self.issue_dict["issues"]

        html_data = "<!DOCTYPE html><html><head><title>" + title + "</title><style type='text/css'>" + stylesheet + "</style></head><body><h1>Tripwire Compliance Scan Report<h1><hr>"
        html_data += "<h2>Scan Details</h2><table><tr><th>Host</th><td>" + scan_details["Host"] + "</td></tr>"
        html_data += "<tr><th>Percent Compliant</th><td>" + scan_details["percent_compliant"] + " %</td></tr>"
        html_data += "<tr><th>Policy Name</th><td>" + scan_details["policy_name"] + "</td></tr>"
        html_data += "<tr><th>Policy Type</th><td>" + scan_details["policy_type"] + "</td></tr></table>"

        space_re = re.compile(r"\s")

        html_data += "<h2 id='toc'>Table of Contents</h2><ol>"
        for issue_name in issues.keys():
            html_data += "<li><a href='#" + space_re.sub("_", issue_name) + "'>" + issue_name + "</a></li>"
        html_data += "<li><a href='#summary'>Audit Checklist</a></li></ol>"

        html_data += "<h2>Technical Report</h2>"
        new_line_re = re.compile(r"\\n")
        values_re = re.compile(r"\'\,\'")
        srno = 1
        for issue_name in issues.keys():
            description = new_line_re.sub("<br>", issues[issue_name]["description"])
            expected_output = new_line_re.sub("<br>", issues[issue_name]["exptected_output"])
            actual_output = new_line_re.sub("<br>", issues[issue_name]["actual_output"])
            status = issues[issue_name]["status"]

            html_data += "<h2 id='" + space_re.sub("_", issue_name) + ">" + str(srno) + ". " + issue_name + "</h2>"
            html_data += "<h3>Status</h3><b>" + status + "</b>"
            html_data += "<h3>Description</h3><p align='justify'>" + values_re.sub("' , '", description) + "<p>"
            html_data += "<h3>Expected Output</h3><p class='code'><code>" + values_re.sub("' , '", expected_output) + "</code></p>"
            html_data += "<h3>Actual Output</h3><p class='code'><code>" + values_re.sub("' , '", actual_output) + "</code></p>"
            html_data += "<p align='right'><a href='#top'>Top</a></p><hr>"
            srno += 1

        html_data += "<h2 id='summary'>" + str(srno) + ". Audit Checklist</h2><table class='summary_table'><tr><th>Sr. No.</th><th>Test Name</th><th><div class='desc'>Description</div></th><th>Status</th></tr>"
        srno = 1
        
        for issue_name in scan_summary.keys():
            description = new_line_re.sub("<br>", scan_summary[issue_name]["description"])
            status = scan_summary[issue_name]["status"]
            html_data += "<tr><td align='right'>" + str(srno) + "</td><td>" + issue_name + "</td><td><div class='desc'>" + values_re.sub("' , '", description) + "</div></td>"
            #html_data += "<tr><td align='right'>" + str(srno) + "</td><td>" + issue_name + "</td><td>" + description + "</td>"
            if status == "Failed":
                html_data += "<td class='fail'>" + status + "</td></tr>"
            else:
                html_data += "<td class='pass'>" + status + "</td></tr>"
            srno += 1

        html_data += "</table><p align='right'><a href='#top'>Top</a></p></body></html>"

        html_file = open(output_filename, "w")
        html_file.write(html_data)
        html_file.close()

        
                
def main():
    parser = optparse.OptionParser("Script to convert nessus CSV to finding based text file")
    parser.add_option("-c", "--csv", dest="csv_filename", help="CSV File for parsing")

    (options, args) = parser.parse_args()

    if not options.csv_filename:
        print ("[-] -c Option is required.")
        parser.print_help()
        sys.exit(1)

    csv_re = re.compile(r"\.csv")
    output_filename = csv_re.sub(".html", options.csv_filename)

    tp = TripWire(options.csv_filename)
    tp.write_to_html()

    #write_to_html(parse_csv(options.csv_filename), output_filename)

if __name__ == "__main__":
    main()