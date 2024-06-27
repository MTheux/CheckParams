import re
import urllib.parse as ul
from sys import stdin, stdout, argv, exit

try:
    encoded = ul.quote(''.join(argv[1:]), safe='')
except IndexError:
    encoded = ul.quote("FUZZ", safe='')

pattern = re.compile(r"=[^?\|&]*")
try:
    for url in stdin:
        domain = url.rstrip()
        print(pattern.sub('=' + encoded, domain), flush=True)
except KeyboardInterrupt:
    exit(0)
except Exception as e:
    print(f"Error: {e}", file=stderr)
    exit(127)