# VirusTotal Hash Scanner

A CLI scanner which scans through a text file with a list of hashes (MD5 or SHA256) and generates a report using the data provided by querying VirusTotal's public API for the scan report of the hashes.

The report is in a table format with the hash value (MD5 or SHA256), malicious check, number of engines detected, and scan date.

# Instructions

1) Ensure you have dependencies installed (See "Dependencies" section)
2) Open a terminal and `cd` to the project folder (Ie. Where virustotal_hash_scanner.py is located)
3) Run `python virustotal_report.py -k <API_KEY> -i <PATH_TO_INPUT_TEXT_FILE>.txt>`
   - To obtain a VirusTotal API key, go to https://developers.virustotal.com/v2.0/reference/getting-started
   - The input text file is the list of MDA5 or SHA256 hashes to scan through
4) The report will be outputted to a text file named `<INPUT_TEXT_FILE_NAME>_result_<CURRENT_TIME>.txt`

# Dependencies

1) requests
    - pip install requests
2) argparse
    - pip install argparse
3) os
    - pip install os
4) time
    - pip install time
5) json
    - pip install json

# Notes

1) If the response code is 0 (Ie. Item does not exist in VirusTotal's dataset), the "Malicious?" will return "Unknown"
2) If the response code is 0 (Ie. Item does not exist in VirusTotal's dataset) or the scan date was not found, the "Scan Date" field will return "N/A"
