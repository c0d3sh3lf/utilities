#!/usr/bin/python3

# The input list can be downloaded from http://cve.mitre.org/data/downloads/allitems-cvrf-year-2019.xml
# pycvesearch can be downloaded from https://github.com/cve-search/PyCVESearch
# Once downloaded navigate to the PyCVESearch folder and run "pip install ." command to install the library.

import optparse, sys, re, unicodedata, sqlite3
from xml.dom.minidom import *
from datetime import datetime
from dateutil import relativedelta
from pycvesearch import CVESearch


def readConf(conf_filename="cve_extract.conf"):
    conf_file = open(conf_filename, 'r')
    configurations = conf_file.readlines()
    conf_file.close()

    comment_re = re.compile("^#")
    conf_re = re.compile("^\w")

    confs = {}

    for configuration in configurations:
        if (not comment_re.match(configuration)) and (conf_re.match(configuration)):
            desc, cpe = configuration.split("=")
            desc = desc.strip()
            cpe = cpe.strip()
            cpe, cpe_version, part, vendor, product, version = cpe.split(":")
            confs[desc] = {
                "product":product,
                "vendor":vendor,
                "version":version
            }
    return confs


def parseXML(xml_filename=""):
    xml_re = re.compile("\.xml")
    comma_re = re.compile(",")
    db_filename = xml_re.sub('.db', xml_filename)

    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()
    create_query = "CREATE TABLE IF NOT EXISTS cve_details (title, published, cve_desc, cvss DOUBLE);"
    cursor.execute(create_query)
    create_query = "CREATE TABLE IF NOT EXISTS reference (ref_url, ref_desc, cve_id);"
    cursor.execute(create_query)
    create_query = "CREATE TABLE IF NOT EXISTS affected_systems (vendor, product, ver, cve_id);"
    cursor.execute(create_query)
    truncate_query = "DELETE FROM cve_details;"
    cursor.execute(truncate_query)
    truncate_query = "DELETE FROM reference;"
    cursor.execute(truncate_query)
    truncate_query = "DELETE FROM affected_systems;"
    cursor.execute(truncate_query)
    conn.commit()
    conn.close()

    try:
        root_node = parse(xml_filename)
        cve_dict = {}
        cve = CVESearch()
        epoch = datetime(1970, 1, 1)
        benchtime = (datetime.now() - relativedelta.relativedelta(months=3))
        benchtimestamp = int((benchtime - epoch).total_seconds())
        vulnerabilities = root_node.getElementsByTagName("Vulnerability")
        for vulnerability in vulnerabilities:
            title = vulnerability.getElementsByTagName("Title")[0].firstChild.nodeValue
            notes = vulnerability.getElementsByTagName("Notes")
            for note in notes:
                stored_notes = note.getElementsByTagName("Note")
                desc = ""
                published = 0
                for stored_note in stored_notes:
                    type = stored_note.getAttribute("Type")
                    if type == "Description":
                        desc = stored_note.firstChild.nodeValue
                    if type == "Other":
                        note_title = stored_note.getAttribute("Title")
                        if note_title == "Published":
                            published_time = stored_note.firstChild.nodeValue
                            published = int((datetime.strptime(published_time, "%Y-%m-%d")-epoch).total_seconds())
            if published >= benchtimestamp:
                ref_list = []
                try:
                    references = vulnerability.getElementsByTagName("References")
                    stored_references = references[0].getElementsByTagName("Reference")
                    for reference in stored_references:
                        url = reference.getElementsByTagName("URL")[0].firstChild.nodeValue
                        ref_desc = reference.getElementsByTagName("Description")[0].firstChild.nodeValue
                        ref_list.append({"url":url, "desc":ref_desc})
                except Exception as e:
                    print(e.with_traceback, end='\r', flush=True)
                conn = sqlite3.connect(db_filename)
                cursor = conn.cursor()
                insert_query = "INSERT INTO cve_details VALUES (?, ?, ?, ?);"
                insert_values = (title, published, desc, 0.0)
                cursor.execute(insert_query, insert_values)
                stored_id = cursor.lastrowid
                insert_query = "INSERT INTO reference VALUES (?, ?, ?);"
                for reference in ref_list:
                    insert_values = (reference["url"], reference["desc"], stored_id)
                    cursor.execute(insert_query, insert_values)
                    conn.commit()
                conn.close()
                try:
                    result = cve.id(title)
                    affected_systems = result["vulnerable_configuration"]
                    conn = sqlite3.connect(db_filename)
                    cursor = conn.cursor()
                    insert_query = "INSERT INTO affected_systems VALUES (?, ?, ?, ?);"
                    for affected_system in affected_systems:
                        cpe = affected_system["id"]
                        cpe_values = cpe.split(":")
                        vendor = cpe_values[3]
                        product = cpe_values[4]
                        try:
                            version = cpe_values[5]
                        except:
                            version = ""
                        insert_values = (vendor, product, version, stored_id)
                        cursor.execute(insert_query, insert_values)
                        conn.commit()
                    cvss = float(result["cvss"])
                    update_query = "UPDATE cve_details SET cvss=:cvss WHERE rowid = :rowid;"
                    update_values = {"cvss":cvss, "rowid":stored_id}
                    cursor.execute(update_query, update_values)
                    conn.commit()
                    conn.close()
                except Exception as e:
                    print(e, end='\r', flush=True)
                    result = {}
                print("[*] Parsing data for {}".format(title), end='\r', flush=True)

        output_filename = xml_re.sub(".csv", xml_filename)
        csv_data = "Sr. No, Title, Description, Published, Severity, Affected System, References\n"
        srno = 1
        confs = readConf()
        
        conn = sqlite3.connect(db_filename)
        cursor_product = conn.cursor()

        for desc in confs.keys():
            product = confs[desc]["product"]
            vendor = confs[desc]["vendor"]
            version = confs[desc]["version"]
            sql_query = "SELECT * FROM affected_systems WHERE product=:product AND vendor=:vendor;"
            values = {"product":product, "vendor":vendor}
            results = cursor_product.execute(sql_query, values)
            
            cursor_cve = conn.cursor()
            cursor_ref = conn.cursor()
            for row in results:
                (as_vendor, as_product, as_version, cve_id) = row
                sql_query = "SELECT * FROM cve_details WHERE rowid=:rowid ORDER BY cvss DESC;"
                values = {"rowid":cve_id}
                cve_results = cursor_cve.execute(sql_query, values)
                for cve_details in cve_results:
                    title = cve_details[0]
                    published = datetime.utcfromtimestamp(cve_details[1]).strftime('%Y-%m-%d')
                    cve_desc = unicodedata.normalize('NFKD', cve_details[2]).encode('ascii', 'ignore').decode('ascii')
                    cve_desc = comma_re.sub(";", cve_desc)
                    cvss = cve_details[3]
                    references = ""
                    sql_query = "SELECT * FROM reference WHERE cve_id=:rowid;"
                    refs = cursor_ref.execute(sql_query, values)
                    for ref in refs:
                        references += "{} ({});".format(ref[1], ref[0])
                    csv_data += "{}, {}, \"{}\", {}, {}, {}, {}\n".format(srno, title, cve_desc, published, cvss, desc, references)
                    srno += 1

        conn.close()
        
        csv_file = open(output_filename, "w")
        csv_file.write(csv_data)
        csv_file.close()
        print("[*] Output written to {}".format(output_filename))
    except Exception as e:
        print("[-] Unable to parse XML file. {}".format(e))


def main():
    parser = optparse.OptionParser()
    parser.add_option("-x", "--xml", dest="xml_filename", help="CVE Mitre XML file")

    (options, args) = parser.parse_args()

    if not options.xml_filename:
        print("[-] XML file required.")
        parser.print_help()
        sys.exit(1)
    
    parseXML(options.xml_filename)
    

if __name__ == "__main__":
    main()