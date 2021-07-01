#!/usr/bin/python
"""Module docstring."""
import ssl
import requests
import urllib3
import json
import getpass
import time
from requests.auth import HTTPBasicAuth

ssl._create_default_https_context = ssl._create_unverified_context

urllib3.disable_warnings()

del_default_ips = ["ip-block/ip-0.0.0.0-prefix-0-protocol-ssh", "ip-block/ip-0.0.0.0-prefix-0-protocol-snmp", "ip-block/ip-0.0.0.0-prefix-0-protocol-https", "ipv6-block/ipv6-::-prefix-0-protocol-ssh", "ipv6-block/ipv6-::-prefix-0-protocol-https", "ipv6-block/ipv6-::-prefix-0-protocol-snmp"]
baseacces_ips = ["ip-block/ip-1.1.1.0-prefix-24-protocol-ssh", "ip-block/ip-1.1.1.0-prefix-24-protocol-https"]
base_dns = ["1.1.1.1", "1.2.2.2"]
base_ntp = ["1.1.1.1", "1.2.2.2"]
base_asa = "asa-Image.SPA.csp"
base_fxos = "fxos-version.SPA"


def auth_token(def_uname, def_passwd, serv_ip):
    """POSTs to REST API Agent to retrieve AUTH Token.
    Returns:
        [str] -- [Post returns JSON, which is converted to str and returned.]
    """
    apipath = "/api/login"
    url = serv_ip + apipath
    headers = {
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
        'USERNAME': def_uname,
        'PASSWORD': def_passwd}
    auth_response = requests.post(url, verify=False, stream=True, headers=headers)
    statuscode = auth_response.status_code
    auth_json = auth_response.json()
    auth_token = auth_json['token']
    if statuscode == 200:
        return auth_token
    else:
        auth_response.raise_for_status()

def cfg_portchannel(auth_token, serv_ip):
    """Downloads specified Firmware.
    Returns:
        [str] -- [Post returns JSON, which is converted to str and returned.]
    """
    apipath = "/api/ports/pc/"
    url = serv_ip + apipath
    headers = {
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
        'TOKEN': auth_token}
    pc_add = {
        "fabricEthLanPc": [{
            "adminDuplex": "fullDuplex",
            "adminSpeed": "1gbps",
            "dn": "ports/pc/1",
            "ssaPortType": "mgmt",
            "adminState": "enabled",
            "fabricEthLanPcEp": [{
                    "slotId": "1",
                    "portId": "1"},
                    {
                    "slotId": "1",
                    "portId": "2"}]},
            {
            "adminDuplex": "fullDuplex",
            "adminSpeed": "40gbps",
            "dn": "ports/pc/2",
            "ssaPortType": "data",
            "adminState": "enabled",
            "fabricEthLanPcEp": [{
                    "slotId": "1",
                    "portId": "7"},
                    {
                    "slotId": "1",
                    "portId": "8"}],}]}
    response = requests.post(url, verify=False, stream=True, headers=headers, json=pc_add)
    statuscode = response.status_code
    if statuscode == 200:
        return response.json()
    elif statuscode == 400:
        print("\nPort-Channel Configuration Error: \n{}".format(response.text[32:]))
    elif statuscode == 404:
        print("\nPort-Channel Configuration Error: \n{}".format(response.text))
    else:
        response.raise_for_status()

def install_logicaldevice(logical_name, mgmt_ip, gateway, mask, auth_token, serv_ip):
    """Downloads specified Firmware.
    Returns:
        [str] -- [Post returns JSON, which is converted to str and returned.]
    """
    apipath = "/api/ld"
    url = serv_ip + apipath
    headers = {
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
        'TOKEN': auth_token}
    logical_add = {
        "smLogicalDevice": [{
            "name": logical_name,
            "dn": "ld/{}".format(logical_name),
            "ldMode": "standalone",
            "slotId": "1",
            "smExternalPortLink": [{
                    "appName": "asa",
                    "name": "PC1_asa",
                    "portName": "Port-channel1"},
                    {
                    "appName": "asa",
                    "name": "PC2_asa",
                    "portName": "Port-channel2"}],
            "smMgmtBootstrap": [{
                    "appName": "asa",
                    "smIP": [
                        {
                            "gateway": gateway,
                            "ip": mgmt_ip,
                            "mask": mask,
                            "mgmtSubType": "default",
                            "slotId": "1"}],
                }
            ],
            "templateName": "asa"}]}
    response = requests.post(url, verify=False, stream=True, headers=headers, json=logical_add)
    statuscode = response.status_code
    if statuscode == 200:
        return response.json()
    elif statuscode == 400:
        print("\nLogical Device Configuration Error: \n{}".format(response.text[32:]))
    elif statuscode == 404:
        print("\nLogical Device Configuration Error: \n{}".format(response.text))
    else:
        response.raise_for_status()

def upld_asa_firmware(scp_uname, scp_passwd, firmware, auth_token, serv_ip):
    """Downloads specified Firmware.
    Returns:
        [str] -- [Post returns JSON, which is converted to str and returned.]
    """
    apipath = "/api/sys/app-catalogue/"
    url = serv_ip + apipath
    headers = {
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
        'TOKEN': auth_token}
    firmware_add = {
        "applicationDownloader": [{
            "protocol": "scp",
            "port": "22",
            "dn": "sys/app-catalogue/dnld-{}".format(firmware),
            "pwd": scp_passwd,
            "user": scp_uname,
            "remotePath": "/var/tmp",
            "server": "<server_IP or URL>"}]}
    response = requests.post(url, verify=False, stream=True, headers=headers, json=firmware_add)
    statuscode = response.status_code
    if statuscode == 200:
        return response.json()
    elif statuscode == 400:
        print("\nASA Firmware Upload Configuration Error: \n{}".format(response.text[32:]))
    elif statuscode == 404:
        print("\nASA Firmware Upload Configuration Error: \n{}".format(response.text))
    else:
        response.raise_for_status()

def upld_fxos_firmware(scp_uname, scp_passwd, firmware, auth_token, serv_ip):
    """Downloads specified Firmware.
    Returns:
        [str] -- [Post returns JSON, which is converted to str and returned.]
    """
    apipath = "/api/sys/firmware/dnld/"
    url = serv_ip + apipath
    headers = {
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
        'TOKEN': auth_token}
    firmware_add = {
        "firmwareDownloader": [{
            "protocol": "scp",
            "port": "22",
            "dn": "sys/fw-catalogue/dnld-{}".format(firmware),
            "pwd": scp_passwd,
            "user": scp_uname,
            "remotePath": "/var/tmp",
            "server": "<server_IP or URL>"}]}
    response = requests.post(url, verify=False, stream=True, headers=headers, json=firmware_add)
    statuscode = response.status_code
    if statuscode == 200:
        return response.json()
    elif statuscode == 400:
        print("\nFXOS Firmware Upload Configuration Error: \n{}".format(response.text[32:]))
    elif statuscode == 404:
        print("\nFXOS Firmware Upload Configuration Error: \n{}".format(response.text))
    else:
        response.raise_for_status()

def set_timezone(auth_token, serv_ip):
    """POSTs Timezone configuration.
    Returns:
        [str] -- [Post returns JSON, which is converted to str and returned.]
    """
    apipath = "/api/sys/service/datetime-svc"
    url = serv_ip + apipath
    headers = {
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
        'TOKEN': auth_token}
    timezone_add = {
        "commDateTime": [{
            "timezone": "America/Chicago",
            "dn": "sys/svc-ext/datetime-svc"}]}
    response = requests.patch(url, verify=False, stream=True, headers=headers, json=timezone_add)
    statuscode = response.status_code
    if statuscode == 200:
        return response.json()
    elif statuscode == 400:
        print("\nTimezone Configuration Error: \n{}".format(response.text[32:]))
    elif statuscode == 404:
        print("\nTimezone Configuration Error: \n{}".format(response.text))
    else:
        response.raise_for_status()

def set_ntp(ipstring, auth_token, serv_ip):
    """POSTs DNS configuration.
    Returns:
        [str] -- [Post returns JSON, which is converted to str and returned.]
    """
    apipath = "/api/sys/service/dns-svc/dns/"
    url = serv_ip + apipath
    headers = {
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
        'TOKEN': auth_token}
    dns_add = {
        "commNtpProvider": [{
            "sha1KeyId": "<numberedID>",
            "sha1KeyString": "keystring",
            "dn": "sys/svc-ext/datetime-svc/ntp-{}".format(ipstring)}]}
    response = requests.post(url, verify=False, stream=True, headers=headers, json=dns_add)
    statuscode = response.status_code
    if statuscode == 200:
        return response.json()
    elif statuscode == 400:
        print("\nNTP Configuration Error: \n{}".format(response.text[32:]))
    elif statuscode == 404:
        print("\nNTP Configuration Error: \n{}".format(response.text))
    else:
        response.raise_for_status()

def set_dns(ipstring, auth_token, serv_ip):
    """POSTs DNS configuration.
    Returns:
        [str] -- [Post returns JSON, which is converted to str and returned.]
    """
    apipath = "/api/sys/service/dns-svc/dns/"
    url = serv_ip + apipath
    headers = {
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
        'TOKEN': auth_token}
    dns_add = {
        "commDnsProvider": [{
            "dn": "sys/svc-ext/dns-svc/dns-{}".format(ipstring)}]}
    response = requests.post(url, verify=False, stream=True, headers=headers, json=dns_add)
    statuscode = response.status_code
    if statuscode == 200:
        return response.json()
    elif statuscode == 400:
        print("\nDNS Configuration Error: \n{}".format(response.text[32:]))
    elif statuscode == 404:
        print("\nDNS Configuration Error: \n{}".format(response.text))
    else:
        response.raise_for_status()

def set_accesslist(ipstring, auth_token, serv_ip):
    """POSTs to REST API Agent to retrieve AUTH Token.
    Returns:
        [str] -- [Post returns JSON, which is converted to str and returned.]
    """
    apipath = "/api/sys/service/ip-block"
    url = serv_ip + apipath
    headers = {
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
        'TOKEN': auth_token}
    acl_add = {
        "commIpBlock": [{
            "dn": "sys/service/{}".format(ipstring)}]}
    response = requests.post(url, verify=False, stream=True, headers=headers, json=acl_add)
    statuscode = response.status_code
    if statuscode == 200:
        return response.json()
    elif statuscode == 400:
        print("\nAccess-List Configuration Error: \n{}".format(response.text[32:]))
    elif statuscode == 404:
        print("\nAccess-List Configuration Error: \n{}".format(response.text))
    else:
        response.raise_for_status()

def delete_accesslist(ipstring, auth_token, serv_ip):
    """Deletes specified IP-Block.
    Returns:
        [str] -- [Post returns JSON, which is converted to str and returned.]
    """
    apipath = "/api/sys/service/{}".format(ipstring)
    url = serv_ip + apipath
    headers = {
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
        'TOKEN': auth_token}
    response = requests.delete(url, verify=False, stream=True, headers=headers)
    statuscode = response.status_code
    if statuscode == 200:
        return response.json()
    elif statuscode == 400:
        print("\nAccess-List deletion Error: {}, An invalid request has been submitted. Verify that the request uses the correct syntax.\n".format(response))
    elif statuscode == 404:
        print("\nAccess-List deletion Error: {}, The specified resource cannot be found.\n".format(response))
    else:
        response.raise_for_status()

def session_timeout(auth_token, serv_ip):
    """Patches Default Session Timeout configuration.
    Returns:
        [str] -- [Patch returns JSON, which is converted to str and returned.]
    """
    apipath = "/api/sys/auth-default"
    url = serv_ip + apipath
    headers = {
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
        'TOKEN': auth_token}
    def_session = {
        "aaaDefaultAuth": [{
            "conSessionTimeout": "1800",
            "refreshPeriod": "1800",
            "sessionTimeout": "1800",
            "dn": "sys/auth-default"}]}
    response = requests.patch(url, verify=False, stream=True, headers=headers, json=def_session)
    statuscode = response.status_code
    if statuscode == 200:
        return response.json()
    elif statuscode == 400:
        print("\nSession Timeout Configuration Error: \n{}".format(response.text[32:]))
    elif statuscode == 404:
        print("\nSession Timeout Configuration Error: \n{}".format(response.text))
    else:
        response.raise_for_status()

def logoff_token(auth_token, serv_ip):
    """POSTs to REST API Agent to retrieve AUTH Token.
    Returns:
        [str] -- [Post returns JSON, which is converted to str and returned.]
    """
    apipath = "/api/logout"
    url = serv_ip + apipath
    headers = {
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
        'TOKEN': auth_token}
    response = requests.post(url, verify=False, stream=True, headers=headers)
    statuscode = response.status_code
    if statuscode == 200:
        return response.json()
    else:
        response.raise_for_status()

def main():
    try:
        entered_ip = input('Enter the FXOS Chassis IP address: ')
        serv_ip = "https://" + entered_ip
        def_uname = input('Enter FXOS Username: ')
        def_passwd = getpass.getpass(prompt='Enter FXOS Password: ', stream=None)
        scp_uname = getpass.getuser()
        scp_passwd = getpass.getpass(prompt='Enter your JHACorp Password for SCP Image Download: ', stream=None)
        logical_name = input('Enter the name for the Logical Device: ')
        logical_mgmtip = input('Enter the Management IP for the ASA Logical Device: ')
        logical_gatewayip = input('Enter the Gateway IP for the ASA Logical Device: ')
        logical_mask = input('Enter the Subnet Mask for the ASA Logical Device: ')
        token = auth_token(def_uname, def_passwd, serv_ip)
        cfg_portchannel(token, serv_ip)
        for ip in baseacces_ips:
            set_accesslist(ip, token, serv_ip)
        logoff = logoff_token(token, serv_ip)
        print("\nToken Logged off: {}\n".format(logoff["logout"]))
        token = auth_token(def_uname, def_passwd, serv_ip)
        for dns_ip in base_dns:
            set_dns(dns_ip, token, serv_ip)
        for ntp_ip in base_ntp:
            set_ntp(ntp_ip, token, serv_ip)
        set_timezone(token, serv_ip)
        for d_ip in del_default_ips:
            delete_accesslist(d_ip, token, serv_ip)
        time.sleep(1)
        upld_fxos_firmware(scp_uname, scp_passwd, base_fxos, token, serv_ip)
        time.sleep(3)
        upld_asa_firmware(scp_uname, scp_passwd, base_asa, token, serv_ip)
        time.sleep(3)
        install_logicaldevice(logical_name, logical_mgmtip, logical_gatewayip, logical_mask, token, serv_ip)
        session_timeout(token, serv_ip)
        logoff = logoff_token(token, serv_ip)
        print("\nToken Logged off: {}\n".format(logoff["logout"]))
    except requests.exceptions.HTTPError as e:
        print(e)


if __name__ == '__main__':
    main()
