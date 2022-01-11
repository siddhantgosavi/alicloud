# -*- coding: utf-8 -*-
import logging
import os
import json

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkecs.request.v20140526.DescribeInstancesRequest import DescribeInstancesRequest
from aliyunsdksts.request.v20150401.AssumeRoleRequest import AssumeRoleRequest
from aliyunsdkcore.auth.credentials import RamRoleArnCredential

def handler():

    logger = logging.getLogger()
    print('hello world')

    ramRoleArnCredentials = RamRoleArnCredential(os.environ['AccessKeyId'], os.environ['AccessKeySecret'], os.environ['RamRoleARN'], os.environ['RoleSession'])

    print(ramRoleArnCredentials)
    #client = AcsClient(os.environ['AccessKeyId'], os.environ['AccessKeySecret'], 'us-west-1')

    client = AcsClient(region_id='us-west-1', credential=ramRoleArnCredentials)

    # # Construct an assume role request.
    # assumeRolerequest = AssumeRoleRequest()
    # assumeRolerequest.set_accept_format('json')

    # # Specify request parameters.
    # assumeRolerequest.set_RoleArn(os.environ['RamRoleARN'])
    # assumeRolerequest.set_RoleSessionName(os.environ['RoleSession'])

    # assumeRoleResponse = client.do_action_with_exception(assumeRolerequest)

    # assumedRoleData = json.loads(assumeRoleResponse)

    # assumedClient = AcsClient(accessKeyID=assumedRoleData['Credentials']['AccessKeyId'], accessKeySecret=assumedRoleData['Credentials']['AccessKeySecret'], securityToken=assumedRoleData['Credentials']['SecurityToken'])
    
    # print(str(assumeRoleResponse, encoding='utf-8')) 

    request = DescribeInstancesRequest()
    request.set_accept_format('json')

    response = client.do_action_with_exception(request)

    #print(str(response, encoding='utf-8'))

handler()