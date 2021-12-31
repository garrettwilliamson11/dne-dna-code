import requests
import json
from requests.auth import HTTPBasicAuth
import os
import sys



# Get the absolute path for the directory where this file is located "here"
here = os.path.abspath(os.path.dirname(__file__))

# Get the absolute path for the project / repository root
project_root = os.path.abspath(os.path.join(here, "../.."))

# Extend the system path to include the project root and import the env files
sys.path.insert(0, project_root)

DNAC_URL = "sandboxdnac.cisco.com"
DNAC_USER = "devnetuser"
DNAC_PASS = "Cisco123!"


def get_auth_token():
    """
    Building out Auth request. Using requests.post to make a call to the Auth Endpoint
    """
    url = 'https://{}/dna/system/api/v1/auth/token'.format(DNAC_URL)                      # Endpoint URL
    hdr = {'content-type' : 'application/json'}                                           # Define request header
    resp = requests.post(url, auth=HTTPBasicAuth(DNAC_USER, DNAC_PASS), headers=hdr)      # Make the POST Request
    token = resp.json()['Token']                                                          # Retrieve the Token
    return token    # Create a return statement to send the token back for later use


def auth_and_select_cmd():
    global ios_cmd
    global device_hostname
    """
    Building out function to retrieve list of devices. Using requests.get to make a call to the network device Endpoint
    """
    token = get_auth_token() # Get Token
    url = "https://{}/api/v1/network-device/1/4".format(DNAC_URL)
    hdr = {'x-auth-token': token, 'content-type' : 'application/json'}
    resp = requests.get(url, headers=hdr)  # Make the Get Request
    device_list = resp.json()
    hostname_keywrd = input("Enter Hostname Keyword: ")
    ios_cmd = input("Enter Command for Selected Nodes: ")
    print("{0:25}{1:25}".format("hostname", "id"))
    for device in device_list['response']:
        if hostname_keywrd in device['hostname']:
            print("{0:25}{1:25}".format(device['hostname'], device['id']))
            device_id = device['id']
            device_hostname = device['hostname']
            initiate_cmd_runner(token,device_id,ios_cmd,device_hostname)



def initiate_cmd_runner(token,device_id,ios_cmd,device_hostname):
    print(f"executing ios command --> {ios_cmd} on {device_hostname}")
    param = {
        "name": "Show Command",
        "commands": [ios_cmd],
        "deviceUuids": [device_id]
    }
    url = "https://{}/api/v1/network-device-poller/cli/read-request".format(DNAC_URL)
    header = {'content-type': 'application/json', 'x-auth-token': token}
    response = requests.post(url, data=json.dumps(param), headers=header)
    task_id = response.json()['response']['taskId']
    print("Command runner Initiated! Task ID --> ", task_id)
    print("Retrieving Path Trace Results.... ")
    get_task_info(task_id, token)


def get_task_info(task_id, token):
    url = "https://{}/api/v1/task/{}".format(DNAC_URL, task_id)
    hdr = {'x-auth-token': token, 'content-type' : 'application/json'}
    task_result = requests.get(url, headers=hdr)
    file_id = task_result.json()['response']['progress']
    if "fileId" in file_id:
        unwanted_chars = '{"}'
        for char in unwanted_chars:
            file_id = file_id.replace(char, '')
        file_id = file_id.split(':')
        file_id = file_id[1]
        print("File ID --> ", file_id)
    else:  # keep checking for task completion
        get_task_info(task_id, token)
    get_cmd_output(token, file_id)


def get_cmd_output(token,file_id):
    url = "https://{}/api/v1/file/{}".format(DNAC_URL, file_id)
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    cmd_result = requests.get(url, headers=hdr)
    output_txt = json.dumps(cmd_result.json(), indent=4, sort_keys=True)
    with open(f'{device_hostname}_{ios_cmd}.txt'.replace(' ','').replace('|',''),'a') as output_file:
        output_file.write(f'{device_hostname} --> {ios_cmd}\n\n----------------------\n')
        output_file.write(output_txt)


if __name__ == "__main__":
    auth_and_select_cmd()
