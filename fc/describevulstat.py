# -*- coding: utf-8 -*-
import os
import json

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkecs.request.v20140526.DescribeInstancesRequest import DescribeInstancesRequest
from aliyunsdkcore.auth.credentials import RamRoleArnCredential
from aliyunsdksas.request.v20181203.DescribeVulListRequest import DescribeVulListRequest
from aliyunsdksas.request.v20181203.GetVulStatisticsRequest import GetVulStatisticsRequest

def handler():

    ramRoleArnCredentials = RamRoleArnCredential(os.environ['AccessKeyId'], os.environ['AccessKeySecret'], os.environ['RamRoleARN'], os.environ['RoleSession'])

    client = AcsClient(region_id='us-west-1', credential=ramRoleArnCredentials)

    request = DescribeVulListRequest()
    request.set_accept_format('json')
    request.set_Type("cve")

    response = client.do_action_with_exception(request)

    print("Vul list")
    print(json.dumps(json.loads(response), indent=1))

    request = GetVulStatisticsRequest()
    request.set_accept_format('json')
    request.set_GroupIdList("8908842")
    request.set_TypeList("cve")

    response = client.do_action_with_exception(request)

    print("\nVul statistics\n")
    print(json.dumps(json.loads(response), indent=1))

handler()