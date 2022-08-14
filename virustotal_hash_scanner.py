import requests
import argparse
import os
import time
import json


'''
Check that the input text file is valid.
'''
def check_input_file(input_file):
    if os.path.isfile(input_file):
        return input_file
    else:
        print("The specified input file is invalid or could not be found.")
        exit()


'''
Check if the API key is of valid length.
'''
def check_api_key(key):
    if len(key) == 64:
        return key
    else:
        print("The specified VirusTotal API Key is invalid.")
        exit()


'''
Create arguments for command line.
'''
def create_arguments():
    parser = argparse.ArgumentParser(
        description="Query VirusTotal's public API with a list of hashes (MD5 or SHA256) and generate a report for "
                    "these hashes.")
    parser.add_argument("-i", "--input", type=check_input_file, required=True,
                        help="path of input file (Ex. /folder1/folder2/sample_hash_input.txt)")
    parser.add_argument("-k", "--key", type=check_api_key, required=True,
                        help="API key given from VirusTotal")
    return parser.parse_args()


'''
Create output text file with formatted headings.
'''
def create_output_file(input_file):
    current_time = time.strftime("%Y%m%d-%H%M%S")
    output_file_name = input_file[0:-4] + "_result_" + current_time + ".txt"
    file = open(output_file_name, "w+")

    # Hash value heading needs spacing to ensure that if hash is 64 characters (SHA-256), the table is still lined up
    hash_value_heading = "Hash Value (MD5 or SHA-256)"
    hash_value_heading_spacing = " " * (64 - len(hash_value_heading))
    formatted_hash_value_heading = hash_value_heading + hash_value_heading_spacing

    # Need to account for names longer than the heading
    malicious_check_heading = "Malicious?"

    engine_number_heading = "Number of Engines Detected"
    scan_date_heading = "Scan Date          "

    headings = formatted_hash_value_heading + " | " + malicious_check_heading + " | " + \
               engine_number_heading + " | " + scan_date_heading + "\n"
    seperator = "-" * len(headings) + "\n"

    file.write(headings + seperator)
    file.close()

    return output_file_name


'''
Creates the report with the hash value, malicious or not, number of engines detected, and scan date using 
VirusTotal's public API.
'''
def create_report(url, api_key, hash, output_file):
    params = {"apikey": api_key, "resource": hash}
    response = requests.get(url, params=params)
    # Converts JSON to a dictionary
    response_json = json.loads(response.content)
    response_code = int(response_json["response_code"])

    hash_spacing = " " * (64 - len(hash))
    formatted_hash = hash + hash_spacing

    # Ensure that the item exists in VirusTotal's dataset. Response code of 1 means item exists.
    malicious_check = "Unknown"
    if response_code == 1:
        if response_json["positives"] >= 3:
            malicious_check = "Yes"
        else:
            malicious_check = "No"
    malicious_check_spacing = " " * (10 - len(malicious_check))
    formatted_malicious_check = malicious_check + malicious_check_spacing

    number_of_engines = "0"
    if response_code == 1:
        number_of_engines = str(response_json["positives"])
    number_of_engines_spacing = " " * (26 - len(number_of_engines))
    formatted_number_of_engines = number_of_engines + number_of_engines_spacing

    scan_date = "N/A"
    if response_code == 1:
        scan_date = str(response_json["scan_date"])

    row = formatted_hash + " | " + formatted_malicious_check + " | " + \
          formatted_number_of_engines + " | " + scan_date + "\n"
    file = open(output_file, "a")
    file.write(row)
    file.close()


'''
Driver for VirusTotal API scan and report creation.
'''
def Main():
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    hash_counter = 1
    args = create_arguments()

    output_file = create_output_file(args.input)

    with open(args.input) as input_file:
        for line in input_file.readlines():
            print("Scanning hash #" + str(hash_counter))
            time.sleep(16)
            create_report(url, args.key, line.rstrip(), output_file)
            hash_counter += 1
    print("Process finished - report has been created!")


if __name__ == "__main__":
    Main()
