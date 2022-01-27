# -*- coding: utf-8 -*-
import logging
import os
import json
import csv
from datetime import datetime

import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from aliyunsdkcore.client import AcsClient
from aliyunsdksts.request.v20150401.AssumeRoleRequest import AssumeRoleRequest
from aliyunsdkcore.auth.credentials import StsTokenCredential
from aliyunsdksas.request.v20181203.DescribeCheckWarningSummaryRequest import DescribeCheckWarningSummaryRequest
from aliyunsdksas.request.v20181203.DescribeWarningMachinesRequest import DescribeWarningMachinesRequest
from aliyunsdksas.request.v20181203.DescribeCheckWarningsRequest import DescribeCheckWarningsRequest
import oss2

def handler(event, context):
    logger = logging.getLogger()
    logger.info('\nScript for creating a list of all baseline checks...')
    accountNumber = os.environ['RamRoleARN'].split(':')[3]
    folder = "/home/app/" + context.service.name + "/" + accountNumber + "/"+ context.function.name
    if not os.path.exists(folder):
        os.makedirs(folder)
    os.chdir(folder)
    os.system('echo $PWD')

    # constructing credentials and acs client for the function compute
    sts_token_credential = StsTokenCredential(context.credentials.accessKeyId, context.credentials.accessKeySecret, context.credentials.securityToken)
    client = AcsClient(region_id='us-west-1', credential=sts_token_credential)

    # Construct an assume role request.
    request = AssumeRoleRequest()
    request.set_accept_format('json')

    # Specify request parameters.
    request.set_RoleArn(os.environ['RamRoleARN'])
    request.set_RoleSessionName(os.environ['RoleSession'])

    # Initiate the request and obtain a response.
    response = client.do_action_with_exception(request)

    object = json.loads(response)

    # constructing credentials and acs client for the assumed role
    sts_token_credential = StsTokenCredential(object['Credentials']['AccessKeyId'], object['Credentials']['AccessKeySecret'], object['Credentials']['SecurityToken'])
    client = AcsClient(region_id='us-west-1', credential=sts_token_credential)

    ###############################################################################

    logger.info("\nFetching baseline data...")

    request = DescribeCheckWarningSummaryRequest()
    request.set_accept_format('json')
    request.set_Lang("en")
    request.set_PageSize(1)

    response = client.do_action_with_exception(request)
    request.set_PageSize(json.loads(response)['TotalCount'])

    response = client.do_action_with_exception(request)

    checkWarningSummaryData = json.loads(response)
    logger.info("Baseline Count: " + str(checkWarningSummaryData['TotalCount']))

    instanceCheckWarnings = []

    for checkWarningSummary in checkWarningSummaryData['WarningSummarys']:

        logger.info("\nFetching data from Baseline: " + checkWarningSummary['RiskName'] + "...")
        request = DescribeWarningMachinesRequest()
        request.set_accept_format('json')
        request.set_Lang("en")
        request.set_PageSize(1)

        request.set_RiskId(checkWarningSummary['RiskId'])

        response = client.do_action_with_exception(request)
        request.set_PageSize(json.loads(response)['TotalCount'])

        response = client.do_action_with_exception(request)
        warningMachineData = json.loads(response)
        logger.info(" MachineCount: " + str(warningMachineData['TotalCount']) + "\n")

        for warningMachine in warningMachineData['WarningMachines']:

            logger.info("\tFetching data for Instance: " + warningMachine['InstanceId'] + " : " + warningMachine['InstanceName'] + "...")
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
            logger.info(" Baseline Check Count: " + str(machineChecksData['TotalCount']))

            for machineWarning in machineChecksData['CheckWarnings']:
                baseobject = {
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

                instanceCheckWarnings.append(baseobject)
    
    timestamp = str(datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S"))
    filename = 'baselineList_' + timestamp + '.csv'

    if(len(instanceCheckWarnings) != 0):
        with open(filename, 'w', newline='') as outf:
            dw = csv.DictWriter(outf, instanceCheckWarnings[0].keys())
            dw.writeheader()
            for warning in instanceCheckWarnings:
                dw.writerow(warning)
        
        logger.info("\nBaseline list created in the file: " + filename)
        logger.info("Total baseline checks: " + str(len(instanceCheckWarnings)))

        stsAuth = oss2.StsAuth(object['Credentials']['AccessKeyId'], object['Credentials']['AccessKeySecret'], object['Credentials']['SecurityToken'])
        bucket = oss2.Bucket(stsAuth, os.environ['Endpoint'], os.environ['BucketName'])
        localFile = folder + "/" + filename
        blobName = context.service.name + "/" + accountNumber + "/Baseline_List/" + filename

        logger.info("\nUploading the file to oss bucket " + os.environ['BucketName'] + "/" + blobName)
        bucket.put_object(blobName, localFile)

        logger.info("Sending Email...")
        sendEmail(filename)
    else:
        logger.info("No Baseline checks found !!!")

def sendEmail(file):
    mailserver = os.environ['MailServer']
    username = os.environ['SMTPUserName']
    password = os.environ['SMTPPassword']
    toemails = os.environ['ToMail'].split(',')
    subject = "Baseline Report FC"
    files = [file]

    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = '%s <%s>' % ('SecOps Automation', username)

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