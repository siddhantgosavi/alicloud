# -*- coding: utf-8 -*-
import collections
import logging
import os
import json

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkecs.request.v20140526.DescribeInstancesRequest import DescribeInstancesRequest
from aliyunsdkcore.auth.credentials import RamRoleArnCredential
from aliyunsdksas.request.v20181203.DescribeVulListRequest import DescribeVulListRequest

def handler():

    logger = logging.getLogger()
    print('hello world')

    ramRoleArnCredentials = RamRoleArnCredential(os.environ['AccessKeyId'], os.environ['AccessKeySecret'], os.environ['RamRoleARN'], os.environ['RoleSession'])

    client = AcsClient(region_id='us-west-1', credential=ramRoleArnCredentials)

    request = DescribeVulListRequest()
    request.set_accept_format('json')
    request.set_Type("cve")

    response = client.do_action_with_exception(request)

    responseData = json.loads(response)

    print(str(response, encoding='utf-8'))

handler()