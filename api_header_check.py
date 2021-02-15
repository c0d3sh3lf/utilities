#!/usr/bin/python
import re, sys, platform

hsts_re = re.compile(r"^Strict\-Transport\-Security")
content_type_re = re.compile(r"^X\-Content\-Type\-Options\:\snosniff")
x_frame_options_re = re.compile(r"^X\-Frame\-Options\:\s(DENY|deny)")
csp_re = re.compile(r"^Content\-Security-Policy\:\sdefault\-src\s\'self\'")
server_re = re.compile(r"^Server\:")
asp_re = re.compile(r"^X\-AspNet\-Version\:")
xpoweredby_re = re.compile(r"X\-Powered\-By\:")
cache_control_re = re.compile(r"^Cache\-(C|c)ontrol\:\sno\-cache")

hsts = False
content_type = False
x_frame_options = False
csp = False
server = False
asp = False
xpoweredby = False
cache_control = False

input_file = open(str(sys.argv[1]), "r")
response = input_file.readlines()
input_file.close()

for line in response:
    if hsts_re.match(line) and not hsts:
        hsts = True

    if content_type_re.match(line) and not content_type:
        content_type = True

    if x_frame_options_re.match(line) and not x_frame_options:
        x_frame_options = True

    if csp_re.match(line) and not csp:
        csp = True

    if server_re.match(line):
        server = True

    if asp_re.match(line):
        asp = True

    if xpoweredby_re.match(line):
        xpoweredby = True

    if cache_control_re.match(line) and not cache_control:
        cache_control = True


output = ""
current_os = platform.system()

# Output colors
FONT_RED = "\033[91m"
FONT_GREEN = "\033[92m"
FONT_END = " \033[0m"

if not hsts:
    output = "[-] HSTS not enabled" if current_os == 'Windows'  else FONT_RED + "[-] HSTS not enabled" + FONT_END
else:
    output =  "[+] HSTS - Success" if current_os == "Windows" else FONT_GREEN + "[+] HSTS - Success" + FONT_END
print output
    
if not content_type:
    output = "[-] Content-Type-Options not enabled" if current_os == 'Windows' else FONT_RED + "[-] Content-Type-Options not enabled" + FONT_END
else:
    output = "[+] Content-Type-Options - Success" if current_os == 'Windows' else FONT_GREEN + "[+] Content-Type-Options - Success" + FONT_END
print output

if not x_frame_options:
    output = "[-] X-Frame-Options not enabled" if current_os == 'Windows' else FONT_RED + "[-] X-Frame-Options not enabled" + FONT_END
else:
    output = "[+] X-Frame-Options - Success" if current_os == 'Windows' else FONT_GREEN + "[+] X-Frame-Options - Success" + FONT_END
print output

if not csp:
    output = "[-] CSP not enabled" if current_os == 'Windows' else FONT_RED + "[-] CSP not enabled" + FONT_END
else:
    output = "[+] CSP - Success" if current_os == 'Windows' else FONT_GREEN + "[+] CSP - Success" + FONT_END
print output
    
if not cache_control:
    output =  "[-] Cache-Control not implemented properly" if current_os == 'Windows' else FONT_RED + "[-] Cache-Control not implemented properly" + FONT_END
else:
    output = "[+] Cache-Control - Success" if current_os == 'Windows' else FONT_GREEN + "[+] Cache-Control - Success" + FONT_END
print output
    
if server or asp or xpoweredby:
    output = "[-] Fingerprinting headers enabled" if current_os == 'Windows' else FONT_RED + "[-] Fingerprinting headers enabled" + FONT_END
else:
    output = "[+] Fingerprinting Headers - Success" if current_os == 'Windows' else FONT_GREEN + "[+] Fingerprinting Headers - Success" + FONT_END
print output
print ""
