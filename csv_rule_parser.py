#!/usr/bin/python

import csv, sys, re, optparse

class rule:

    type = ""
    rulenum = ""
    name = ""
    tag = ""
    frm = ""
    src = ""
    user = ""
    hip_profile = ""
    to = ""
    dest = ""
    app = ""
    service = ""
    action = ""
    profile = ""
    options = ""
    comment = ""
    enable = ""
    log = ""
    rule = ""

    def __init__(self, row = {}):
        for key in row.keys():
            if key == None:
                ruleset = row[key]
                self.type = ruleset[0]
                self.rulenum = ruleset[1]
                self.name = ruleset[2]
                self.tag = ruleset[3]
                self.frm = ruleset[4]
                self.src = ruleset[5]
                self.user = ruleset[6]
                self.hip_profile = ruleset[7]
                self.to = ruleset[8]
                self.dest = ruleset[9]
                self.app = ruleset[10]
                self.service = ruleset[11]
                self.action = ruleset[12]
                self.profile = ruleset[13]
                self.options = ruleset[14]
                self.comment = ruleset[15]
                self.enable = ruleset[16]
                self.log = ruleset[17]
                self.rule = ruleset[18]

    def __str__(self):
        return "\"" + self.type + "\",\"" + self.rulenum + "\",\"" + self.name + "\",\"" + self.tag + "\",\"" + self.frm + "\",\"" + self.src + "\",\"" + self.user + "\",\"" + self.hip_profile + "\",\"" + self.to + "\",\"" + self.dest + "\",\"" + self.app + "\",\"" + self.service + "\",\"" + self.action + "\",\"" + self.profile + "\",\"" + self.options + "\",\"" + self.comment + "\",\"" + self.enable + "\",\"" + self.log + "\",\"" + self.rule + "\""

    def headers(self):
        return "TYPE,RULENUM,NAME,TAG,FROM,SOURCE,USER,HIP PROFILE,TO,DESTINATION,APPLICATION,SERVICE,ACTION,PROFILE,OPTIONS,COMMENT,ENABLE,LOG,RULE"


class parseRules:

    csv_filename = ""
    csv_data = ""

    def __init__(self, csv_filename):
        self.csv_filename = csv_filename
        csv_file = open(csv_filename, mode='r')
        self.csv_data = csv.DictReader(csv_file)

    def parse(self):
        line_count = 0
        ruleset_list = []
        for row in self.csv_data:
            if line_count == 0:
                pass
            ruleset_list.append(rule(row))
        return ruleset_list

    def printRows(self, count=1):
        line_count = 0
        for row in self.csv_data:
            if line_count >= count:
                break
            print row
            line_count += 1


def filter(ruleset = [], filter = ""):
    filter_list = []
    re_list = []
    comma_re = re.compile(r",")
    if comma_re.search(filter):
        filter_list = filter.split(",")
    else:
        filter_list.append(filter)

    for ip in filter_list:
        temp_re = re.compile(r"("+ip.replace('.', '\.')+")")
        re_list.append(temp_re)

    extracted_ruleset = []

    for rule in ruleset:
        for ip_re in re_list:
            if ip_re.search(rule.src) or ip_re.search(rule.dest):
                if rule not in extracted_ruleset:
                    extracted_ruleset.append(rule)

    return extracted_ruleset


def write_to_csv(csv_filename="", filtered_ruleset = []):
    output_filename = csv_filename[:-4:] + "_filtered.csv"
    output_file = open(output_filename, mode='w')
    csv_data = filtered_ruleset[0].headers() + "\n"
    for rule in filtered_ruleset:
        csv_data += str(rule) + "\n"
    output_file.write(csv_data)
    output_file.close()
    print "[+] Output successfully written to '%s'"%(output_filename)


def main():
    option_parser = optparse.OptionParser()
    option_parser.add_option("-c", "--csv", dest="csv_filename", help="Ruleset extracted in CSV format")
    option_parser.add_option("-f", "--filter", dest="filter", help="IP based filter. Multiple IP addresses separated by comma.")
    options, args = option_parser.parse_args()
    if options.csv_filename:
        print "[+] Parsing the rules from the CSV"
        csv_parser = parseRules(options.csv_filename)
        if options.filter:
            print "[+] Filtering the rules based on the criteria"
            filtered_ruleset = filter(csv_parser.parse(), options.filter)
        else:
            print "[!] No filter applied"
            filtered_ruleset = csv_parser.parse()
        print "[+] Extracted %d rules"%(len(filtered_ruleset))
        if len(filtered_ruleset) > 0:
            print "[+] Writing to the output file"
            write_to_csv(options.csv_filename, filtered_ruleset)
    else:
        print "[-] CSV filename required"
        option_parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()