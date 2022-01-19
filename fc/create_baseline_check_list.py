# -*- coding: utf-8 -*-
import logging
import os
import json
import csv
import sys
from datetime import datetime

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkcore.auth.credentials import RamRoleArnCredential
from aliyunsdksas.request.v20181203.DescribeCheckWarningSummaryRequest import DescribeCheckWarningSummaryRequest
from aliyunsdksas.request.v20181203.DescribeWarningMachinesRequest import DescribeWarningMachinesRequest
from aliyunsdksas.request.v20181203.DescribeCheckWarningsRequest import DescribeCheckWarningsRequest

if(len(sys.argv) == 1):
    RoleARN = input("Enter Role ARN: ")
elif(len(sys.argv) == 2):
    RoleARN = sys.argv[1]

print("Role ARN: " + RoleARN)

RoleSession = "secops-create-baseline-list-session"

def handler():
    try:
        logger = logging.getLogger()
        print('Script for creating a list of all baseline checks...')

        ramRoleArnCredentials = RamRoleArnCredential(os.environ['AccessKeyId'], os.environ['AccessKeySecret'], RoleARN, RoleSession)

        client = AcsClient(region_id='us-west-1', credential=ramRoleArnCredentials)

        print("\nFetching baseline catagories data...", end='')

        request = DescribeCheckWarningSummaryRequest()
        request.set_accept_format('json')
        request.set_Lang("en")
        request.set_PageSize(1)

        response = client.do_action_with_exception(request)
        request.set_PageSize(json.loads(response)['TotalCount'])

        response = client.do_action_with_exception(request)

        checkWarningSummaryData = json.loads(response)
        print(" Catagories Count: " + str(checkWarningSummaryData['TotalCount']))

        instanceCheckWarnings = []

        for checkWarningSummary in checkWarningSummaryData['WarningSummarys']:

            print("\nFetching data from Baseline: " + checkWarningSummary['RiskName'] + "...", end='')
            request = DescribeWarningMachinesRequest()
            request.set_accept_format('json')
            request.set_Lang("en")
            request.set_PageSize(1)

            request.set_RiskId(checkWarningSummary['RiskId'])

            response = client.do_action_with_exception(request)
            request.set_PageSize(json.loads(response)['TotalCount'])

            response = client.do_action_with_exception(request)
            warningMachineData = json.loads(response)
            print(" MachineCount: " + str(warningMachineData['TotalCount']) + "\n")

            for warningMachine in warningMachineData['WarningMachines']:

                print("\tFetching data for Instance: " + warningMachine['InstanceId'] + " : " + warningMachine['InstanceName'] + "...", end='')
                request = DescribeCheckWarningsRequest()
                request.set_accept_format('json')
                request.set_Lang("en")
                request.set_PageSize(1)

                request.set_Uuid(warningMachine['Uuid'])
                request.set_RiskId(checkWarningSummary['RiskId'])

                response = client.do_action_with_exception(request)
                request.set_PageSize(json.loads(response)['TotalCount'])

                response = client.do_action_with_exception(request)
                machineChecksData = json.loads(response)
                print(" Baseline Check Count: " + str(machineChecksData['TotalCount']))

                for machineWarning in machineChecksData['CheckWarnings']:
                    object = {
                        'LastFoundTime': checkWarningSummary['LastFoundTime'],
                        'RiskName' : checkWarningSummary['RiskName'],
                        'RiskId' : checkWarningSummary['RiskId'],
                        'InstanceId' : warningMachine['InstanceId'],
                        'InstanceName' : warningMachine['InstanceName'],
                        'RegionId' : warningMachine['RegionId'],
                        'PublicIp' : warningMachine['InternetIp'],
                        'PrivateIp' : warningMachine['IntranetIp'],
                        'Item' : machineWarning['Item'],
                        'Type' : machineWarning['Type'],
                        'Level' : machineWarning['Level'],
                        'Status' : ("Failed" if (machineWarning['Status'] == 1) else "Success")
                    }

                    instanceCheckWarnings.append(object)
        
        timestamp = str(datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"))
        filename = 'baselineList_' + timestamp + '.csv'

        if(len(instanceCheckWarnings) != 0):
            with open(filename, 'w', newline='') as outf:
                dw = csv.DictWriter(outf, instanceCheckWarnings[0].keys())
                dw.writeheader()
                for warning in instanceCheckWarnings:
                    dw.writerow(warning)
            
            print("\nBaseline list created in the file: ", filename)
            print("Total baseline checks: " + str(len(instanceCheckWarnings)))
        else:
            print("No Baseline checks found !!!")
        
    except ClientException as e:
        print(e)
    except ServerException as e:
        print(e)
    except Exception as e:
        print(e)

handler()