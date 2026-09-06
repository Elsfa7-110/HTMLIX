# HTMLIX
tool designed to scan URLs for html injection

python3 htmlix.py -u "https://example.com/search?q=test" -p payloads.txt

python3 htmlix.py -U urls.txt -p payloads.txt -m POST -t 20 -o results.json

python3 htmlix.py -U urls.txt -p payloads.txt -t 20

Useful flags: -H "Cookie: session=..." for auth, --delay 0.5 to be gentle on the target, -k to skip TLS verification, --timeout. It exits with code 1 if anything vulnerable is found, so it drops into CI easily.
