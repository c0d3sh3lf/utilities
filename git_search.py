#/usr/bin/python3

import requests, optparse, time, os, re, sys
from termcolor import colored

space_re = re.compile(r'\s')


class ApiError(Exception):
    # API Exception Class

    def __init__(self, message=""):
        self.error_message = message

    def __str__(self):
        print(self.error_message)


def print_colored(message = "", color="white"):
    try:
        if os.environ["name"] == "nt":
            print(message)
        else:
            print(colored(message, color))
    except KeyError:
        print(colored(message, color))


def search_git(keyword=""):
    url_enc_keyword = space_re.sub("+", keyword)
    search_url = "https://api.github.com/search/repositories?q=" + url_enc_keyword
    headers = {"Accept": "application/vnd.github.mercy-preview+json"}
    print_colored("[+] Looking for '%s'"%(keyword), "green")
    resp = requests.get(search_url, headers=headers)

    if resp.status_code != 200:
        raise ApiError('GET /search/repositories/ {}'.format(resp.status_code))

    response_data = resp.json()
    total_count = response_data['total_count']
    if total_count > 0:
        items = response_data['items']
        print_colored("ID\t\tNAME\t\tURL\t\tDESCRIPTION", "blue")
        for item in items:
            item_id = str(item["id"])
            full_name = str(item["full_name"])
            html_url = str(item["html_url"])
            description = str(item["description"])
            print_data = item_id + "\t\t" + full_name + "\t" + html_url + "\t" + description
            print_colored(print_data, "blue")

    else:
        print_colored("[-] No results found", "red")

    return response_data


def write_output_to_html(output_data = {}):
    stylesheet = """
        h, p, td, th {
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
        a:visited {
            color: blue;
        }
    """
    html_data = "<DOCTYPE html><html><head><title>Git Search Output</title><style type='text/css'>" + stylesheet + "</style></head><body><h1>Git Search Output</h1><hr>"

    for keyword in output_data.keys():
        html_data += "<h2>" + keyword + "</h2>"
        keyword_results = output_data[keyword]["items"]
        result_count = output_data[keyword]["total_count"]
        if result_count > 0:
            html_data += "<table><tr><th>Sr. No.</th><th>ID</th><th>Name</th><th>URL</th><th>Description</th></tr>"
            srno = 1
            for result in keyword_results:
                html_data += "<tr><td align='right'>" + str(srno) + ". </td><td>" + str(result["id"]) + "</td><td>" + str(result["full_name"]) + "</td><td><a href='" + str(result["html_url"]) + "' target='new'>" + str(result["html_url"]) + "</a></td><td>" + str(result["description"]) + "</td></tr>"
                srno += 1
            html_data += "</table>"
        else:
            html_data += "<p>No results found</p>"

    html_data += "</body></html>"
    output_file = open("git_search_output.html", "w")
    output_file.write(html_data)
    output_file.close()

    print_colored("[+] Output written to 'git_search_output.html", "green")


def main():
    parser = optparse.OptionParser('Tool to search on github')
    parser.add_option("-k", "--keywords", dest="keywords", help="Keywords separated by commas")
    parser.add_option("-i", "--input-file", dest="inputfile", help="Keyword file with each keyword in a new line")

    (options, args) = parser.parse_args()

    if options.keywords or options.inputfile:
        keywords_flag = True
    else:
        print_colored("[-] Need keywords. Use either -k or -i to provide keywords", "red")
        parser.print_help()
        sys.exit(1)

    print_colored("[!] Using rate limit of 10 request per minute.", "yellow")

    output_dict = {}

    if keywords_flag:
        if options.keywords:
            keywords = str(options.keywords).split(",")
            counter = 1
            for keyword in keywords:
                if counter % 10 != 0:
                    keyword_results = search_git(keyword)
                    output_dict[keyword] = keyword_results
                else:
                    print_colored("[!] Rate limit reached. Holding on for a minute.", "yellow")
                    time.sleep(60)
                    print_colored("[!] Resuming the search", "yellow")
                counter += 1
        else:
            inputfile = open(options.inputfile, "r")
            keywords = inputfile.readlines()
            inputfile.close()
            counter = 1
            for keyword in keywords:
                if counter % 10 != 0:
                    keyword_results = search_git(keyword)
                    output_dict[keyword] = keyword_results
                else:
                    print_colored("[!] Rate limit reached. Holding on for a minute.", "yellow")
                    time.sleep(60)
                    print_colored("[!] Resuming the search", "yellow")
                counter += 1

        write_output_to_html(output_dict)


if __name__ == "__main__":
    main()
