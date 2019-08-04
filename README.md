# utilities
Small utilities for formatting

* api_header_check.py - Checks for necessary headers in OpenAPI implementation using server response stored in the file
* csv_rule_parser.py - Filters Ruleset based on IP addresses for F5 firewalls
* cve_extract.conf - Configuration File for cve_extract.py
* cve_extract.py - Script to get the CVE details for the listed technologies in configuration file for past 3 months (can be changed in the script).
* get_ip_from_domain.py - Script to get the IP addresses for list of domain names
* git_search.py - Searches github based on keywords and generates output in HTML
* hic_sql_v2.py - Performs analysis of SEP Host Integrity Check CSV output and generates a HTML report
* ip_zero_remover.py - Removes prefixed 0 in IP address formats
* ms17_010_checker.py - Checks for vulnerable systems on given ranges for MS17-010. Requires responder to be installed on the system
* log_analyzer.conf - Configuration for 'log_analyzer.py'
* log_analyzer.py - Python script to analyze logs for presence of unwanted data. Data Regex can be defined in 'log_analyzer.conf'
* network_sniffer.py - Script to monitor basic protocols travelling between the source and destination over a network
* nmap_live_host.py - Discovers live hosts from Nmap XML output
* nmap_to_csv.py - Converts nmap xml to csv format
* nmap_to_json.py - Converts nmap xml to json format
* nmap_to_sqlite.py - Stores nmap xml into SQLite3 DB format
* sha256_file.py - Calculates SHA256 hash of all files present in a parent folder and its subfolder
* ssllabs_json_to_csv.py - Converts the json output of ssllabs-scan to csv file
* sslscan_parse_output.py - Output parser for SSLScan Output (Requires SSL Scan to be installed / present in the working directory)
* tripwire_compliance_csv_parser.py - Output parser for Tripwire Compliance CSV report. Output in HTML format
* tripwire_csv_parser.py - Output parser for Tripwire VA CSV files. Output in HTML format
* udp_host_discovery.py - Host discovery script using UDP protocol
