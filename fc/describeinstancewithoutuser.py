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
from aliyunsdkcore.auth.credentials import StsTokenCredential

def handler(event, context):
    logger = logging.getLogger()
    logger.info('hello world')

    sts_token_credential = StsTokenCredential(context.credentials.accessKeyId, context.credentials.accessKeySecret, context.credentials.securityToken)
    acs_client = AcsClient(region_id='us-west-1', credential=sts_token_credential)

    # Construct a request.
    request = AssumeRoleRequest()
    request.set_accept_format('json')

    # Specify request parameters.
    request.set_RoleArn(os.environ['RamRoleARN'])
    request.set_RoleSessionName(os.environ['RoleSession'])

    # Initiate the request and obtain a response.
    response = acs_client.do_action_with_exception(request)

    object = json.loads(response)

    sts_token_credential = StsTokenCredential(object['Credentials']['AccessKeyId'], object['Credentials']['AccessKeySecret'], object['Credentials']['SecurityToken'])
    acs_client = AcsClient(region_id='us-west-1', credential=sts_token_credential)

    request = DescribeInstancesRequest()
    request.set_accept_format('json')

    response = acs_client.do_action_with_exception(request)

    logger.info(str(response, encoding='utf-8'))
