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

RoleSession = "secops-create-config-list-session"

def handler():
    try:
        logger = logging.getLogger()
        print('\nScript for creating a list of all config assesments...')

        ramRoleArnCredentials = RamRoleArnCredential(os.environ['AccessKeyId'], os.environ['AccessKeySecret'], RoleARN, RoleSession)

        client = AcsClient(region_id='us-west-1', credential=ramRoleArnCredentials)

        request = DescribeRiskCheckResultRequest()
        request.set_accept_format('json')
        request.set_Lang("en")
        request.set_PageSize(1)

        response = client.do_action_with_exception(request)
        request.set_PageSize(json.loads(response)['TotalCount'])

        response = client.do_action_with_exception(request)

        configData = json.loads(response)

        configList = []

        for config in configData['List']:

            configObject = {
                'Config': config['Title'],
                'Severity': config['RiskLevel'],
                'AffectedAssets': config['AffectedCount'],
                'ConfigType': config['Type'],
                'LatestScanTime' :  str(datetime.fromtimestamp(config['CheckTime']/1000).strftime("%Y-%m-%d %H:%M:%S"))
            }

            configList.append(configObject)

        timestamp = str(datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S"))
        filename = 'config_assesment_list_' + timestamp + '.csv'

        if(len(configList) != 0):
            with open(filename, 'w', newline='') as outf:
                dw = csv.DictWriter(outf, configList[0].keys())
                dw.writeheader()
                for warning in configList:
                    dw.writerow(warning)
            
            print("\nConfig Assesment list created in the file: " + filename)
            if(toemail):
                print("Sending Email...")
                sendEmail(filename, toemail)
            else:
                print("Email is not given")
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
    subject = "Config Assesment Report"
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