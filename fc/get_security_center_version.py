# -*- coding: utf-8 -*-
import os
import json
import sys

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.auth.credentials import RamRoleArnCredential
from aliyunsdksas.request.v20181203.DescribeVersionConfigRequest import DescribeVersionConfigRequest

if(len(sys.argv) == 1):
    RoleARN = input("Enter Role ARN: ")
elif(len(sys.argv) == 2):
    RoleARN = sys.argv[1]

print("Role ARN: " + RoleARN)

RoleSession = "secops-create-vul-list-session"

def handler():

    ramRoleArnCredentials = RamRoleArnCredential(os.environ['AccessKeyId'], os.environ['AccessKeySecret'], RoleARN, RoleSession)

    client = AcsClient(region_id='us-west-1', credential=ramRoleArnCredentials)

    request = DescribeVersionConfigRequest()
    request.set_accept_format('json')

    response = client.do_action_with_exception(request)
    responseData = json.loads(response)

    map = {
        1: "Basic",
        2: "Enterprise",
        3: "Enterprise",
        5: "Advanced",
        6: "Basic Anti-Virus"
    }

    print("Security Center Version: " + map[responseData['Version']])

handler()
