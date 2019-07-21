from enum import Enum
from hashlib import sha256
from time import sleep

import sys
import requests as r

from conf.keys import VIRUS_TOTAL_API_KEY

BASE_URL = "https://www.virustotal.com/vtapi/v2"


class ResponseCode(Enum):
    SCANNING = -2
    NOT_IN_DB = 0
    AVAILABLE = 1


def scan_file(file_path):
    """
    Scan the selected file in VirusTotal, returning details of an existing scan if one exists, otherwise requesting
    a new scan and returning results when that is complete. Requesting a new scan may take some time to complete, and
    due to rate limits the results are checked every 20 seconds until completion.

    :param file_path: The path of the file to scan
    :return: Results of the file scan in JSON format
    """

    # SHA256 encode the file to check if it's already been scanned
    with open(file_path, 'rb') as f:
        sha256sum = sha256(f.read()).hexdigest()
    print(f"[x] Checking if {file_path} has already been scanned")
    print(f"[x] SHA256: {sha256sum}")
    json = _get_existing_report(sha256sum)
    if json is not None:
        return json

    # If not, request a new scan
    print(f"[x] {file_path} was not found, requesting a new scan")
    return _scan_new_file(file_path)


def _get_existing_report(code):
    """
    Checks VirusTotal for an existing scan result, through either a hash of the file being scanned or a scan_id given
    when a scan has been requested.

    :param code: The hash/scan_id of the file/request
    :return: Results of the file scan in JSON format
    """
    url = f"{BASE_URL}/file/report"
    payload = {'apikey': VIRUS_TOTAL_API_KEY, 'resource': code}
    resp = r.get(url, params=payload)

    # Account for timeouts - only 4 request may be made a minute
    # Wait until the upload has completed scanning if it is doing so
    resp = _wait_for_scan(resp, url, payload)

    # If any other error has occurred raise an exception
    if resp.status_code != r.codes.ok:
        raise r.exceptions.HTTPError(f"Error getting report on {code} - {resp.reason}")

    # Check the json response - return None if the item doesn't exist
    json = resp.json()
    if ResponseCode(json['response_code']) == ResponseCode.NOT_IN_DB:
        return None

    # Otherwise we're all good
    return resp.json()


def _wait_for_scan(resp, url, payload):
    """
    Waits for a scan to complete by periodically polling the specified URL. There are generally two reasons why a scan
    has not completed - either we've hit the rate limit or the file is still being scanned. This function prints
    occasionally to let the user know it's working.

    :param resp: The initial response from the URL
    :param payload: The requests payload to send to the URL
    :param url: The base URL to send subsequent requests to
    :return: The response from the server as a requests Response object
    """
    i = 0
    while resp.status_code == r.codes.no_content \
            or (resp.status_code == r.codes.ok
                and ResponseCode(resp.json()["response_code"]) == ResponseCode.SCANNING):

        # Notify the user as to why we are waiting
        sys.stdout.write(_get_waiting_message(resp.status_code, i))

        # Give it some time before trying again
        sleep(5)
        i += 1
        if i % 4 == 0:
            resp = r.get(url, params=payload)

    # Print the final message
    if i != 0:
        sys.stdout.write(f"{_get_waiting_message(resp.status_code, i)} Done!\n")

    return resp


def _scan_new_file(file_path):
    """
    Requests VirusTotal to scan a new file.

    :param file_path: The path of the file to scan
    :return: Results of the file scan in JSON format
    """
    url = f"{BASE_URL}/file/scan"
    payload = {'apikey': VIRUS_TOTAL_API_KEY}
    file = {'file': open(file_path, 'rb')}
    resp = r.post(url, files=file, data=payload)

    # Take into consideration any rate limits:
    while resp.status_code == r.codes.no_content:
        sleep(20)
        resp = r.post(url, files=file, data=payload)

    # Otherwise get the scan ID and wait for scanning to complete
    json = resp.json()

    scan_id = json['scan_id']
    scan_json = _get_existing_report(scan_id)
    return scan_json


def _get_waiting_message(status_code, i):
    """
    Populates a waiting message to display to the user.

    :param status_code: The status code of the response from the server
    :param i: The number of times the message has been called
    :return: A string message to display to the user
    """
    message = 'Scanning file...' \
        if status_code != r.codes.no_content \
        else 'Rate limit exceeded...'

    return f"\r[x] {message}{'.' * (i % 10)}"
