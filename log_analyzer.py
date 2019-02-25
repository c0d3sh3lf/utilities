import re, sys, os

if len(sys.argv) < 2:
    print "[!] Provide log directory"
    sys.exit(1)

double_quote_re = re.compile(r"\"")    

class configuration:

    configurations = []

    comment_re = re.compile("^\#")
    title_re = re.compile("^\[([\w\s_\-]*)\]")
    re_re = re.compile("^re\s?\=\s?([\(\)\[\]\s\w\\\/\!\@\#\$\%\^\&\*\{\}\,\d\.\?\+\=\-\_\:\"\'\;\>\<\|\\`\~]*)")
    desc_re = re.compile("^desc\s?\=\s?([A-Za-z0-9\_\-\s\,\\\/\@\#\$\*\(\)]*)")

    def __init__(self, conf_filename = "log_analyzer.conf"):
        conf_file = open(conf_filename, 'r')
        saved_confs = conf_file.readlines()
        conf_file.close()

        title_flag = False
        re_flag = False
        desc_flag = False

        configurations = []
    
        for line in saved_confs:

            if self.comment_re.match(line):
                pass
            
            temp_conf = {}
            title_match = self.title_re.search(line)
            if title_match:
                title = str(title_match.group(1)).strip()
                title_flag = True

            re_match = self.re_re.search(line)
            if re_match:
                re_pattern = str(re_match.group(1)).strip()
                regex = re.compile(re_pattern)
                re_flag = True

            desc_match = self.desc_re.search(line)
            if desc_match:
                desc = str(desc_match.group(1)).strip()
                desc_flag = True

            if title_flag and re_flag and desc_flag:
                temp_conf["title"] = title
                temp_conf["pattern"] = regex
                temp_conf["desc"] = desc
                configurations.append(temp_conf)
                title_flag = False
                re_flag = False
                desc_flag = False

        self.configurations = configurations

    def getConfigurations(self):
        return self.configurations
    

def percentage(part, whole):
    return 100 * float(part) / float(whole)

def clean_log(log):
    return double_quote_re.sub("'", log)

def analyze_logs(filename, config):
             
    configs = config.getConfigurations()

    log_file = open(filename, "r")
    logs = log_file.readlines()
    log_file.close()

    output_list = []
    
    log_counter = 0
    total_logs = len(logs)
    for log in logs:
        log_counter += 1

        for conf in configs:
            value = conf["pattern"].search(log)
            if value:
                temp_list = {"issue":conf["desc"] + " in log", "log_line_no": str(log_counter), "log": log.strip(), "vulnerable_value":str(value.group(0))}
                output_list.append(temp_list)
        
        output_line = "\r[+] " + str(filename) + " - " + str(round(percentage(log_counter, total_logs), 2)) + "% Completed"
        sys.stdout.write(output_line)
        
    return output_list


def main():

	final_dict = {}
	config = configuration()
	file_list = os.listdir(str(sys.argv[1]))
	for filename in file_list:
	    absolute_filename = os.path.join(str(sys.argv[1]), filename)
	    print "[+] Analyzing %s" % (absolute_filename)
	    final_dict[filename] = analyze_logs(absolute_filename, config)
	    print ""

	print "[+] Preparing data for CSV file"
	csv_data = "Sr. No.,Log Filename,Issue,Line Number,Value Found,Log,Risk Impact\n"

	sr_no = 1
	csv_file = open("output.csv", "w")

	total_issue_count = 0
	for filename in final_dict.keys():
	    total_issue_count += len(final_dict[filename])

	print ""

	for filename in final_dict.keys():
	    issue_list = final_dict[filename]
	    for issue_details in issue_list:
	        issue_name = issue_details["issue"]
	        log_line_number = issue_details["log_line_no"]
	        vuln_value = issue_details["vulnerable_value"]
	        log_line = issue_details["log"]
	        csv_data += str(sr_no) + ",\"" + str(filename) + "\",\"" + issue_name + "\",\"" + log_line_number + "\",\"" + vuln_value + "\",\"" + clean_log(log_line) + "\",\"\"\n"
	        percent = percentage(sr_no, total_issue_count)
	        if percent < 5.0:
	            sys.stdout.write("\r[--------------------] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 5.0 and percent < 10.0:
	            sys.stdout.write("\r[##------------------] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 10.0 and percent < 15.0:
	            sys.stdout.write("\r[###-----------------] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 15.0 and percent < 20.0:
	            sys.stdout.write("\r[####----------------] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 20.0 and percent < 25.0:
	            sys.stdout.write("\r[#####---------------] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 25.0 and percent < 30.0:
	            sys.stdout.write("\r[######--------------] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 30.0 and percent < 35.0:
	            sys.stdout.write("\r[#######-------------] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 35.0 and percent < 40.0:
	            sys.stdout.write("\r[########------------] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 40.0 and percent < 45.0:
	            sys.stdout.write("\r[#########-----------] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 45.0 and percent < 50.0:
	            sys.stdout.write("\r[##########----------] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 50.0 and percent < 55.0:
	            sys.stdout.write("\r[###########---------] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 55.0 and percent < 60.0:
	            sys.stdout.write("\r[############--------] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 60.0 and percent < 65.0:
	            sys.stdout.write("\r[#############-------] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 65.0 and percent < 70.0:
	            sys.stdout.write("\r[##############------] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 70.0 and percent < 75.0:
	            sys.stdout.write("\r[###############-----] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 75.0 and percent < 80.0:
	            sys.stdout.write("\r[################----] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 80.0 and percent < 85.0:
	            sys.stdout.write("\r[#################---] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 85.0 and percent < 90.0:
	            sys.stdout.write("\r[##################--] [" + str(round(percent, 2)) + " %]")
	        elif percent >= 90.0 and percent < 95.0:
	            sys.stdout.write("\r[###################-] [" + str(round(percent, 2)) + " %]")
	        else:
	            sys.stdout.write("\r[####################] [" + str(round(percent, 2)) + " %]")
	        sr_no += 1

	print "\n"
	print "[+] Writind data to csv file"
	csv_file.write(csv_data)
	csv_file.close()

	print "[+] %d issues written to 'output.csv'" % (sr_no - 1)


if __name__ == "__main__":
	main()