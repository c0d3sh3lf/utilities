#!/usr/bin/python3

from selenium import webdriver
import optparse, re, sys, os

def capture_screen(url, output_filename, log_filename):
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument('--ignore-certificate-errors')
    chrome_options.add_argument('--test-type')
    #chrome_options.binary_location = "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
    driver = webdriver.Chrome(chrome_options=chrome_options)

    driver.get(url)
    driver.save_screenshot(output_filename)

    print ("[+] Screenshot for '%s' stored in '%s'"%(url, output_filename))
    log_file = open(log_filename, "a")
    log_file.write(url + " -> " + output_filename + "\n")
    log_file.close()

    driver.close()
    

def main():
    parser = optparse.OptionParser()
    parser.add_option("-f", "--filename", dest="url_file", help="file with list of urls.")
    parser.add_option("-o", "--output-folder", dest="out_folder", help="folder to store the output.")

    (options, args) = parser.parse_args()

    out_folder_flag = False

    if not options.url_file:
        print("[-] URL file required.")
        parser.print_help()
        sys.exit(1)

    if options.out_folder:
        out_folder_flag = True
    

    url_list_file = open(options.url_file, "r")
    url_list = url_list_file.readlines()

    counter = 1
    for url in url_list:
        if out_folder_flag:
            output_filename = os.path.join(options.out_folder, str(counter) + ".png")
            log_filename = os.path.join(options.out_folder, "output_log.txt")
        else:
            output_filename = str(counter) + ".png"
            log_filename = "output_log.txt"
        capture_screen(url, output_filename, log_filename)
        counter += 1
    

if __name__ == "__main__":
    main()