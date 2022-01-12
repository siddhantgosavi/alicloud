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

class Vulnerability:
    def __init__(self, InstanceId, InstanceName, OSName, VulnerabilityName, CVEId, Level, Necessity, CanFix, Status):
        self.InstanceId = InstanceId
        self.InstanceName = InstanceName
        self.OSName = OSName
        self.VulnerabilityName = VulnerabilityName
        self.CVEId = CVEId
        self.Level = Level
        self.Necessity = Necessity
        self.CanFix = CanFix
        self.Status = Status

    def toJSON(self):
        print("abc")

def handler():

    ramRoleArnCredentials = RamRoleArnCredential(os.environ['AccessKeyId'], os.environ['AccessKeySecret'], os.environ['RamRoleARN'], os.environ['RoleSession'])

    client = AcsClient(region_id='us-west-1', credential=ramRoleArnCredentials)

    request = DescribeVulListRequest()
    request.set_accept_format('json')
    request.set_Type("cve")
    request.set_PageSize(100)

    response = client.do_action_with_exception(request)

    responseData = json.loads(response)

    vulList = []
    for vul in responseData['VulRecords']:
        vuldata = Vulnerability(vul['InstanceId'], vul['InstanceName'], vul['OsVersion'] + ":" + vul['ExtendContentJson']['Os'],
                                vul['AliasName'], vul['Related'], vul['Level'], 
                                vul['Necessity'], vul['CanFix'], vul['Status'])
        vulList.append(vuldata)

    vulList = sorted(vulList, key=lambda x: x.Level)

    print ("{:<22} {:<17} {:<12} {:<90} {:<10} {:<10} {:<10} {:<5}".format('InstanceId','InstanceName','OSName','VulnerabilityName', 'Level', 'Necessity', 'CanFix', 'Status'))
    print()

    for vul in vulList:
        print ("{:<22} {:<17} {:<12} {:<90} {:<10} {:<10} {:<10} {:<5}".format(vul.InstanceId,vul.InstanceName,vul.OSName,vul.VulnerabilityName,vul.Level,vul.Necessity,vul.CanFix,vul.Status))

    request = GetVulStatisticsRequest()
    request.set_accept_format('json')
    request.set_GroupIdList("8908842")
    request.set_TypeList("cve")

    response = client.do_action_with_exception(request)

    print("\nVul statistics\n")
    print(json.dumps(json.loads(response), indent=1))

handler()