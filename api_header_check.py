import re, sys

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

    if cache_control.match(line) and not cache_control:
        cache_control = True



if not hsts:
    print "[-] HSTS not enabled"
else:
    print "[+] HSTS - Success"
    
if not content_type:
    print "[-] Content-Type-Options not enabled"
else:
    print "[+] Content-Type-Options - Success"

if not x_frame_options:
    print "[-] X-Frame-Options not enabled"
else:
    print "[+] X-Frame-Options - Success"

if not csp:
    print "[-] CSP not enabled"
else:
    print "[+] CSP - Success"
    
if not cache_control:
    print "[-] Cache-Control not implemented properly"
else:
    print "[+] Cache-Control - Success"
    
if server or asp or xpoweredby:
    print "[-] Fingerprinting headers enabled"
else:
    print "[+] Fingerprinting Headers - Success"