#!/usr/bin/python3

import requests
import os
import sys
import re

USE_SYSTEM_ENV = True # if false, those four will be used
ZEROTIER_TOKEN = None   # Get it here: https://my.zerotier.com/account
ZEROTIER_NETWORK = None # Get it here(you must have access to it): https://my.zerotier.com/network
DNSPOD_TOKEN = None     # 'id,token'
DNSPOD_DOMAIN = None    # root domain(like 'google.com')

# first %s: Name of members from Zerotier Network
#           expecting a valid hostname here
#           will generate something like my-pc.zt.xxxx.me
RECORD_FORMAT = "%s.zt"


def check_ztc_auth():
    headers = {'Authorization': 'Bearer ' + ZEROTIER_TOKEN}
    response = requests.get(url="https://my.zerotier.com/api/network/%s" % (ZEROTIER_NETWORK), headers=headers)
    if response.status_code == 200:
        return True
    return False


def check_dnspod_auth():
    req_data = "lang=en&format=json&login_token=%s&domain=%s" % (DNSPOD_TOKEN, DNSPOD_DOMAIN)
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(url="https://dnsapi.cn/Domain.Info",
                             data=req_data, headers=headers)
    if response.status_code == 200:
        payload = response.json()
        if payload["status"]["code"] == "1":
            if payload["domain"]["status"] != "enable":
                sys.stderr.write("Warning: domain status: %s\n" % payload["domain"]["status"])
            return True
    return False


def get_zt_members():
    headers = {'Authorization': 'Bearer ' + ZEROTIER_TOKEN}
    response = requests.get(url="https://my.zerotier.com/api/network/%s/member" % (ZEROTIER_NETWORK), headers=headers)
    if response.status_code == 200:
        ret = []
        payload = response.json()
        regex_hostname = re.compile("([a-zA-Z0-9-]{1,63})")
        regex_v4 = re.compile("(^[\d]+.[\d]+.[\d]+.[\d]+)$")
        for node in payload:
            if node["name"] == "":  # silently skipping
                continue
            if regex_hostname.match(node["name"]).group(1) != node["name"]:  # does not a valid hostname
                sys.stderr.write("Not a valid hostname: %s! Skipping\n" % node["name"])
                continue

            ret_node = {"name": node["name"], "id": node["nodeId"], "v4": "", "v6": ""}

            for ip in node["config"]["ipAssignments"]:
                if regex_v4.match(ip).group(1) == ip:
                    if ret_node["v4"] == "":
                        ret_node["v4"] = ip
                else:
                    if ret_node["v6"] == "":
                        ret_node["v6"] = ip
            ret.append(ret_node)
        return ret
    else:
        sys.stderr.write("Error: HTTP %d\n" % response.status_code)
    return None


def get_managed_records():
    total_records_count = 100  # will be updated later
    parsed_records_count = 0

    # [{"ZTID":"xxxx","DPID":"xxxx", "subdomain":"xxx","type":"A/AAAA","value":"x.x.x.x"}]
    ret = []

    while True:
        to_be_request_index = parsed_records_count
        to_be_request_length = total_records_count - parsed_records_count
        if to_be_request_length > 100:
            to_be_request_length = 100
        req_data = "lang=en&format=json&login_token=%s&domain=%s&offset=%d&length=%d" % (
            DNSPOD_TOKEN, DNSPOD_DOMAIN, to_be_request_index, to_be_request_length)
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        response = requests.post(url="https://dnsapi.cn/Record.List",
                                 data=req_data,
                                 headers=headers)
        if response.status_code == 200:
            payload = response.json()
            if payload["status"]["code"] == "1":

                # now we get/refresh the total records count
                total_records_count = int(payload["info"]["record_total"])
                parsed_records_count += int(payload["info"]["records_num"])

                for record in payload["records"]:
                    if record["remark"].find("ZTC2DNSPOD: ") == 0:
                        ret.append({"ZTID": record["remark"][12:], "DPID": record["id"], "subdomain": record["name"],
                                    "type": record["type"],
                                    "value": record["value"]})

                if parsed_records_count >= total_records_count:
                    return ret
            else:
                sys.stderr.write("Error: %s\n" % payload["status"]["message"])
                sys.exit(-3)
        else:
            sys.stderr.write("Error: HTTP %d\n" % response.status_code)
            sys.exit(-4)


def add_new_record(hostname, type, addr, ztid):
    print("add %s %s %s %s" % (hostname, type, addr, ztid))
    req_data = "lang=en&format=json&login_token=%s&domain=%s&sub_domain=%s&record_type=%s&&record_line_id=0&value=%s" \
               % (DNSPOD_TOKEN, DNSPOD_DOMAIN, hostname, type, addr)
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(url="https://dnsapi.cn/Record.Create",
                             data=req_data, headers=headers)
    if response.status_code == 200:
        payload = response.json()
        if payload["status"]["code"] == "1":
            req_data = "lang=en&format=json&login_token=%s&domain=%s&record_id=%s&remark=ZTC2DNSPOD: %s" \
                       % (DNSPOD_TOKEN, DNSPOD_DOMAIN, payload["record"]["id"], ztid)
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            response_remark = requests.post(url="https://dnsapi.cn/Record.Remark",
                                            data=req_data, headers=headers)
            if response_remark.status_code == 200:
                payload_remark = response_remark.json()
                if payload["status"]["code"] == "1":
                    return True
                else:
                    sys.stderr.write("Error: %s\n" % payload_remark["status"]["message"])
            else:
                sys.stderr.write("Error: HTTP %d\n" % response.status_code)
            sys.stderr.write("Critical Error: subdomain %s lost track! Please manually delete it\n" % hostname)
        else:
            sys.stderr.write("Error: %s\n" % payload["status"]["message"])
    else:
        sys.stderr.write("Error: HTTP %d\n" % response.status_code)
    return False


def update_record(dpid, type, hostname, addr):
    print("update %s %s %s %s" % (dpid, type, hostname, addr))
    req_data = "lang=en&format=json&login_token=%s&domain=%s&record_id=%s&sub_domain=%s&record_type=%s&&record_line_id=0&value=%s" \
               % (DNSPOD_TOKEN, DNSPOD_DOMAIN, dpid, hostname, type, addr)
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(url="https://dnsapi.cn/Record.Modify",
                             data=req_data, headers=headers)
    if response.status_code == 200:
        payload = response.json()
        if payload["status"]["code"] == "1":
            return True
        else:
            sys.stderr.write("Error: %s\n" % payload["status"]["message"])
    else:
        sys.stderr.write("Error: HTTP %d\n" % response.status_code)
    return False


def remove_record(dpid):
    print("remove %s" % dpid)
    req_data = "lang=en&format=json&login_token=%s&domain=%s&record_id=%s" \
               % (DNSPOD_TOKEN, DNSPOD_DOMAIN, dpid)
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(url="https://dnsapi.cn/Record.Remove",
                             data=req_data, headers=headers)
    if response.status_code == 200:
        payload = response.json()
        if payload["status"]["code"] == "1":
            return True
        else:
            sys.stderr.write("Error: %s\n" % payload["status"]["message"])
    else:
        sys.stderr.write("Error: HTTP %d\n" % response.status_code)
    return False


if __name__ == '__main__':
    if USE_SYSTEM_ENV:
        ZEROTIER_TOKEN = os.getenv("ZEROTIER_TOKEN")
        if not ZEROTIER_TOKEN:
            sys.stderr.write("env ZEROTIER_TOKEN not set!\n")
            sys.exit(-1)
        ZEROTIER_NETWORK = os.getenv("ZEROTIER_NETWORK")
        if not ZEROTIER_NETWORK:
            sys.stderr.write("env ZEROTIER_NETWORK not set!\n")
            sys.exit(-1)

    if not check_ztc_auth():
        sys.stderr.write("Zerotier Central AUTH failed\n")
        sys.exit(-2)

    if USE_SYSTEM_ENV:
        DNSPOD_TOKEN = os.getenv("DNSPOD_TOKEN")
        if not DNSPOD_TOKEN:
            sys.stderr.write("env DNSPOD_TOKEN not set!\n")
            sys.exit(-1)

        DNSPOD_DOMAIN = os.getenv("DNSPOD_DOMAIN")
        if not DNSPOD_DOMAIN:
            sys.stderr.write("env DNSPOD_DOMAIN not set!\n")
            sys.exit(-1)

    if not check_dnspod_auth():
        sys.stderr.write("DNSPod AUTH failed\n")
        sys.exit(-2)

    managed_records = get_managed_records()
    zt_members = get_zt_members()

    for zt_dev in zt_members:
        if zt_dev["v4"] != "":
            corresponding_record = next((record for record in managed_records
                                         if record['ZTID'] == zt_dev["id"] and
                                         record['type'] == "A"),
                                        None)
            if corresponding_record is None:
                add_new_record(RECORD_FORMAT % zt_dev["name"], "A", zt_dev["v4"], zt_dev["id"])
            else:
                managed_records[:] = [d for d in managed_records if d['ZTID'] != zt_dev["id"] or d['type'] != "A"]
                if not (corresponding_record['subdomain'] == RECORD_FORMAT % zt_dev["name"] and corresponding_record[
                    'value'] == zt_dev["v4"]):
                    update_record(corresponding_record['DPID'], "A", RECORD_FORMAT % zt_dev["name"], zt_dev["v4"])
        if zt_dev["v6"] != "":
            corresponding_record = next((record for record in managed_records
                                         if record['ZTID'] == zt_dev["id"] and
                                         record['type'] == "AAAA"),
                                        None)
            if corresponding_record is None:
                add_new_record(RECORD_FORMAT % zt_dev["name"], "AAAA", zt_dev["v6"], zt_dev["id"])
            else:
                managed_records[:] = [d for d in managed_records if d['ZTID'] != zt_dev["id"] or d['type'] != "AAAA"]
                if not (corresponding_record['subdomain'] == RECORD_FORMAT % zt_dev["name"] and corresponding_record[
                    'value'] == zt_dev["v6"]):
                    update_record(corresponding_record['DPID'], "AAAA", RECORD_FORMAT % zt_dev["name"], zt_dev["v6"])

    for record in managed_records:
        remove_record(record['DPID'])
