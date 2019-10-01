#!/usr/bin/python3

import optparse, xlrd, sys, re, xlwt
from datetime import datetime, timedelta

header_row_re = re.compile("^Computer\sName$")
blank_row_re = re.compile("^$")
xlsx_re = re.compile("\.xlsx")
server_re = re.compile("Server")
atm_re = re.compile("ATM")


def parse_excel(xls_filename = ""):
    loc = (xls_filename)

    # Start reading the excel sheet
    wb = xlrd.open_workbook(loc)
    sheet = wb.sheet_by_index(0)

    data = []

    # Extract only table from the sheet

    for i in range(0, sheet.nrows):
        row = []
        for j in range(0, sheet.ncols):
            value = str.replace(str(sheet.cell_value(i, j)), "\xa0", "").strip()
            row.append(value)
        data.append(row)

    excess_filtered_data = []
    include = False

    for i in range(0, len(data)):
        row = data[i]
        if header_row_re.match(row[0]):
            include = True

        if include:
            excess_filtered_data.append(row)
            #print(len(row))

    # Remove unwanted columns

    cols_to_remove = ['', 'IPS Signatures', 'SONAR Content', 'Download Protection Content']
    

    for col in cols_to_remove:
        clean_cols_data = []
        print("[+] Popping out '{}'".format(col), end = "\r")
        header = excess_filtered_data[0]
        indices = [i for i, x in enumerate(header) if x == col]
        if len(indices) > 1:
            indices.sort(reverse = True)
        else:
            indices = indices[0]
        for row in excess_filtered_data:
            if type(indices) == type([]):
                for index in indices:
                    row.pop(index)
            else:
                row.pop(indices)
            clean_cols_data.append(row)
        excess_filtered_data = clean_cols_data
    
    index_of_av = excess_filtered_data[0].index('Antivirus Content')

    print("[+] Column cleaning completed.{}".format(" "*40))
    print("[+] Initiating row cleaning ...", end = "\r")

    cleaned_data = []

    cleaned_data.append(excess_filtered_data[0])

    # Remove results older than 7 days

    latest_date = ""
    for i in range(1, len(excess_filtered_data)):
        row = excess_filtered_data[i]
        if blank_row_re.match(row[0]):
            pass
        else:
            if row[index_of_av] == "Out-of-date":
                next_row = excess_filtered_data[i + 1]
                row[index_of_av] = next_row[index_of_av]
            cleaned_data.append(row)
            latest_date = row[4]

    print("[+] Row cleaning completed.{}".format(" "*40))

    delta = timedelta(days=7)
    date = datetime.strptime(latest_date, "%d/%m/%Y %H:%M:%S")
    cutoff_date = date - delta
    cutoff_epoch = int((cutoff_date - datetime(1970, 1, 1)).total_seconds())

    final_data = [cleaned_data[0]]

    for i in range(1, len(cleaned_data)):
        row = cleaned_data[i]
        try:
            row_date = datetime.strptime(row[4], "%d/%m/%Y %H:%M:%S")
        except:
            row_date = datetime(1970, 1, 1)
        row_date_epoch = int((row_date - datetime(1970, 1, 1)).total_seconds())

        if row_date_epoch >= cutoff_epoch:
            final_data.append(row)

    # Add AV Signature status in the end
    final_data[0].append("AV Status")
    av_update_index = final_data[0].index("Antivirus Content")

    for row in range(1, len(final_data)):
        av_update = final_data[row][av_update_index]
        av_update_date = av_update.split(" ")[0]

        av_update_epoch = int((datetime.strptime(av_update_date, "%m/%d/%y") - datetime(1970, 1, 1)).total_seconds())

        if av_update_epoch >= cutoff_epoch:
            final_data[row].append("Updated")
        else:
            final_data[row].append("Out-of-Date")


    # Sort the data into Servers, ATMs and Endpoints group

    servers = [final_data[0]]
    atms = [final_data[0]]
    endpoints = [final_data[0]]

    os_index = final_data[0].index("Operating System")
    group_index = final_data[0].index("Group")

    for row in range(1, len(final_data)):
        if server_re.search(final_data[row][os_index]):
            servers.append(final_data[row])
        elif atm_re.search(final_data[row][group_index]):
            atms.append(final_data[row])
        else:
            endpoints.append(final_data[row])

    # Write date to output file
    output_filename = xlsx_re.sub("_cleaned.xls", xls_filename)

    clean_wb = xlwt.Workbook()

    # Add all data into sheet
    all_data = clean_wb.add_sheet('Cleaned Output')

    for row in range(0, len(final_data)):
        for col, value in enumerate(final_data[row]):
            all_data.write(row, col, value)

    # Add servers data into sheet
    servers_sheet = clean_wb.add_sheet('Servers')

    for row in range(0, len(servers)):
        for col, value in enumerate(servers[row]):
            servers_sheet.write(row, col, value)

    # Add ATMs data into sheet
    atms_sheet = clean_wb.add_sheet('ATMs')

    for row in range(0, len(atms)):
        for col, value in enumerate(atms[row]):
            atms_sheet.write(row, col, value)

    # Add Endpoints data into sheet
    endpoints_sheet = clean_wb.add_sheet('Endpoints')

    for row in range(0, len(endpoints)):
        for col, value in enumerate(endpoints[row]):
            endpoints_sheet.write(row, col, value)

    # Write output to the file
    clean_wb.save(output_filename)
    print("[+] Output written to {}".format(output_filename))


def main():
    parser = optparse.OptionParser()
    parser.add_option("-x", "--xls", dest="xls_filename", help="Excel File from AV.")
    
    (options, args) = parser.parse_args()

    if not options.xls_filename:
        print("[-] Excel filename required")
        parser.print_help()
        sys.exit(1)

    parse_excel(options.xls_filename)

if __name__ == "__main__":
    main()