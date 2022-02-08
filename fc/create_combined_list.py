# -*- coding: utf-8 -*-
import logging
import os
import json
import csv
import sys
from datetime import datetime

import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkcore.auth.credentials import RamRoleArnCredential
from aliyunsdksas.request.v20181203.DescribeVulListRequest import DescribeVulListRequest
from aliyunsdksas.request.v20181203.DescribeVulDetailsRequest import DescribeVulDetailsRequest
from aliyunsdksas.request.v20181203.DescribeCheckWarningSummaryRequest import DescribeCheckWarningSummaryRequest
from aliyunsdksas.request.v20181203.DescribeWarningMachinesRequest import DescribeWarningMachinesRequest
from aliyunsdksas.request.v20181203.DescribeCheckWarningsRequest import DescribeCheckWarningsRequest
from aliyunsdksas.request.v20181203.DescribeRiskCheckResultRequest import DescribeRiskCheckResultRequest

if(len(sys.argv) == 1):
    RoleARN = input("Enter Role ARN: ")
    toemail = input("Enter Email: ")
elif(len(sys.argv) == 2):
    RoleARN = sys.argv[1]
    toemail = input("Enter Email: ")
elif(len(sys.argv) == 3):
    RoleARN = sys.argv[1]
    toemail = sys.argv[2]

print("Role ARN: " + RoleARN)
print("Email: " + toemail)

RoleSession = "secops-combined-list-session"

def handler():
    try:
        logger = logging.getLogger()
        print('\nScript for creating a list of config assesments, baselines and vulnerabilities...')

        ramRoleArnCredentials = RamRoleArnCredential(os.environ['AccessKeyId'], os.environ['AccessKeySecret'], RoleARN, RoleSession)

        client = AcsClient(region_id='us-west-1', credential=ramRoleArnCredentials)

        ##################### Config Assessment #####################

        print("\nFetching data for Config Assesment...\n")
        request = DescribeRiskCheckResultRequest()
        request.set_accept_format('json')
        request.set_Lang("en")
        request.set_PageSize(1)

        response = client.do_action_with_exception(request)
        request.set_PageSize(json.loads(response)['TotalCount'])

        response = client.do_action_with_exception(request)

        configData = json.loads(response)

        combinedList = []

        highConfigData = [c for c in configData['List'] if (c['RiskLevel'] == "high")]

        for config in highConfigData:

            combinedObject = {
                'Kind': "ConfigAssesment",
                'Config': config['Title'],
                'Severity/Level': config['RiskLevel'],
                'Status' : config['Status'],
                'AffectedAssetsCount': config['AffectedCount'],
                'ConfigType': config['Type'],
                'LastFoundTime' :  str(datetime.fromtimestamp(config['CheckTime']/1000).strftime("%Y-%m-%d %H:%M:%S")),
                'RiskName' : '',
                'RiskId' : '',
                'InstanceId' : '',
                'InstanceName' : '',
                'RegionId' : '',
                'PublicIp' : '',
                'PrivateIp' : '',
                'Item' : '',
                'Type' : '',
                'AffectedAssets' : '',
                'RegionId': '',
                'VulnerabilityName' : '',
                "CVE" : '',
                'Impact' : '',
                'FirstScanTime' : '',
                'LatestScanTime' :  str(datetime.fromtimestamp(config['CheckTime']/1000).strftime("%Y-%m-%d %H:%M:%S")),
                'Priority' :  '',
                'AffectedSoftware' : '',
                'SoftwarePath' : '',
                'Cause' :  '',
                'Fix' : '',
                'Summary': ''
            }

            combinedList.append(combinedObject)

        ##################### Vulnerbaility #####################

        print("\nFetching data for Vulnerbilities...\n")
        request = DescribeVulListRequest()
        request.set_accept_format('json')
        request.set_Lang("en")
        request.set_Type("cve")
        request.set_PageSize(1)

        response = client.do_action_with_exception(request)            
        request.set_PageSize(json.loads(response)['TotalCount'])

        response = client.do_action_with_exception(request)

        cveResponseData = json.loads(response)

        request = DescribeVulListRequest()
        request.set_accept_format('json')
        request.set_Lang("en")
        request.set_Type("sys")
        request.set_PageSize(1)

        response = client.do_action_with_exception(request)            
        request.set_PageSize(json.loads(response)['TotalCount'])

        response = client.do_action_with_exception(request)

        sysResponseData = json.loads(response)

        highVulData = [v for v in (cveResponseData['VulRecords'] + sysResponseData['VulRecords']) if v['Level'] == "high"]

        for vul in highVulData:

            request = DescribeVulDetailsRequest()
            request.set_accept_format('json')

            request.set_Type(vul['Type'])
            request.set_Name(vul['Name'])
            request.set_Lang("en")

            response = client.do_action_with_exception(request)

            vulDetailData = json.loads(response)
            
            combinedObject = {
                'Kind': "Vulnerability",
                'Config': '',
                'Severity/Level': vul['Level'],
                'Status' : '',
                'AffectedAssetsCount': '',
                'ConfigType': '',
                'LastFoundTime' :  '',
                'RiskName' : '',
                'RiskId' : '',
                'InstanceId' : '',
                'InstanceName' : '',
                'RegionId' : '',
                'PublicIp' : '',
                'PrivateIp' : '',
                'Item' : '',
                'Type' : '',
                'AffectedAssets' : str(vul['InstanceId'] + " " + vul['InstanceName']),
                'RegionId': vul['RegionId'],
                'VulnerabilityName' : vul['AliasName'],
                "CVE" : vul['Related'],
                'Impact' : vul['ExtendContentJson']['Necessity'].get('Cvss_factor',''),
                'FirstScanTime' : str(datetime.fromtimestamp(vul['FirstTs']/1000).strftime("%Y-%m-%d %H:%M:%S")),
                'LatestScanTime' :  str(datetime.fromtimestamp(vul['LastTs']/1000).strftime("%Y-%m-%d %H:%M:%S")),
                'Priority' :  "high" if vul['Necessity'] == "asap" else "medium" if vul['Necessity'] == "later" else "low",
                'AffectedSoftware' : ('\n').join([str(r['Name'] + " " + r['FullVersion']) for r in vul['ExtendContentJson']['RpmEntityList']]),
                'SoftwarePath' : ('\n').join([r['Path'] for r in vul['ExtendContentJson']['RpmEntityList']]),
                'Cause' :  ('\n').join([r['MatchDetail'] for r in vul['ExtendContentJson']['RpmEntityList']]),
                'Fix' : ('\n').join([r['UpdateCmd'] for r in vul['ExtendContentJson']['RpmEntityList']]),
                'Summary': ('\n').join([d['Summary'] for d in vulDetailData['Cves']])
            }
            combinedList.append(combinedObject)

        ##################### Baseline #####################

        print("\nFetching data for Baseline...\n")
        request = DescribeCheckWarningSummaryRequest()
        request.set_accept_format('json')
        request.set_Lang("en")
        request.set_PageSize(1)

        response = client.do_action_with_exception(request)
        request.set_PageSize(json.loads(response)['TotalCount'])

        response = client.do_action_with_exception(request)

        checkWarningSummaryData = json.loads(response)

        for checkWarningSummary in checkWarningSummaryData['WarningSummarys']:

            #print("\nFetching data from Baseline: " + checkWarningSummary['RiskName'] + "...", end='')
            request = DescribeWarningMachinesRequest()
            request.set_accept_format('json')
            request.set_Lang("en")
            request.set_PageSize(1)

            request.set_RiskId(checkWarningSummary['RiskId'])

            response = client.do_action_with_exception(request)
            request.set_PageSize(json.loads(response)['TotalCount'])

            response = client.do_action_with_exception(request)
            warningMachineData = json.loads(response)
            #print(" MachineCount: " + str(warningMachineData['TotalCount']) + "\n")

            for warningMachine in warningMachineData['WarningMachines']:

                #print("\tFetching data for Instance: " + warningMachine['InstanceId'] + " : " + warningMachine['InstanceName'] + "...", end='')
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
                #print(" Baseline Check Count: " + str(machineChecksData['TotalCount']))

                highMachineChecksData = [m for m in machineChecksData['CheckWarnings'] if m['Level'] == "high"]

                for machineWarning in highMachineChecksData:
                    combinedObject = {
                        'Kind': "Baseline",
                        'Config': '',
                        'Severity/Level': machineWarning['Level'],
                        'Status' : ("Failed" if (machineWarning['Status'] == 1) else "Success"),
                        'AffectedAssetsCount': '',
                        'ConfigType': '',
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
                        'AffectedAssets' : '',
                        'RegionId': '',
                        'VulnerabilityName' : '',
                        "CVE" : '',
                        'Impact' : '',
                        'FirstScanTime' : '',
                        'LatestScanTime' :  '',
                        'Priority' :  '',
                        'AffectedSoftware' : '',
                        'SoftwarePath' : '',
                        'Cause' :  '',
                        'Fix' : '',
                        'Summary': '',
                    }
                    combinedList.append(combinedObject)

        timestamp = str(datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S"))
        filename = 'combined_list_' + timestamp + '.csv'

        if(len(combinedList) != 0):
            with open(filename, 'w', newline='') as outf:
                dw = csv.DictWriter(outf, combinedList[0].keys())
                dw.writeheader()
                for warning in combinedList:
                    dw.writerow(warning)
            
            print("\nCombined list created in the file: " + filename)
            print("Sending Email...")
            sendEmail(filename, toemail)
        else:
            print("No Config Assesment checks found !!!")

    except ClientException as e:
        print(e)
    except ServerException as e:
        print(e)
    except Exception as e:
        print(e)

def sendEmail(file, toemail):
    mailserver = os.environ['MailServer']
    username = os.environ['SMTPUserName']
    password = os.environ['SMTPPassword']
    toemails = toemail.split(',')
    subject = "Combined Report"
    files = [file]

    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = '%s <%s>' % ('SecOps Automation', username)
    msg['To'] = toemail

    htmlbody = MIMEText ("<p>Hi,</p><p>Reports are attached in the mail.</p><p>Thanks,<br>SecOps Automation</p>", _subtype='html', _charset='UTF-8')
    msg.attach(htmlbody)

    for file in files:
        part = MIMEBase('application', "octet-stream")
        part.set_payload(open(file, "rb").read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment', filename=file)
        msg.attach(part)

    smtpclient = smtplib.SMTP_SSL(mailserver)
    smtpclient.connect(mailserver)
    smtpclient.login(username, password)

    smtpclient.sendmail(username, toemails, msg.as_string())
    smtpclient.close()

handler()