#!/usr/bin/python3

import random, optparse
from datetime import date

def gen_eid(start_year, end_year):
    year_comp = random.randint(start_year, end_year)
    middle_comp = random.randint(1000000, 9999999)
    last_digit = random.randint(1, 2)
    eid_formatted = f"784-{year_comp}-{middle_comp}-{last_digit}"
    eid = f"784{year_comp}{middle_comp}{last_digit}"
    return (eid_formatted, eid)


def main():
    parser = optparse.OptionParser(f"Script to generate random Emirates ID number.\n{__file__} -c 10 -o eids -s 1970 -e 2022\n\n* All arguments are optional and have default values.\n")
    parser.add_option("-c", "--count", default=100, dest="eid_count", help="Number of EIDs to generate")
    parser.add_option("-o", "--output", default="eids", dest="output_filename", help="Output file name (without extension possibly)")
    parser.add_option("-s", "--start-year", default=1970, dest="start_year", help="Start year for Emirates ID. Default 1970.")
    parser.add_option("-e", "--end-year", default=date.today().year, dest="end_year", help="End year for Emirates ID. Default is current year.")

    (options, args) = parser.parse_args()

    output_data = []
    output_data_formatted = []

    for i in range(0, int(options.eid_count)):
        (eid_formatted, eid) = gen_eid(options.start_year, options.end_year)
        output_data.append(eid)
        output_data_formatted.append(eid_formatted)

    output_str = "\n".join(output_data)
    output_formatted_str = "\n".join(output_data_formatted)

    filename_list = str(options.output_filename).split(".")
    if len(filename_list) > 1:
        filename_list = filename_list[:-1]

    filename = ".".join(filename_list)

    with open(f"{filename}.txt", "w") as f1:
        f1.write(output_str)

    with open(f"{filename}_formatted.txt", "w") as f2:
        f2.write(output_formatted_str)

    print(f"[+] {options.eid_count} Emirates ID number(s) written to files - '{filename}.txt' and '{filename}_formatted.txt'")


if __name__ == "__main__":
    main()