# -*- coding: utf-8 -*-
import logging 
import json
import calendar
from datetime import datetime
import requests

def handler(event, context):
    logger = logging.getLogger()
    file = open("create_baseline_check_list.json", 'r')
    schedules = json.loads(file.read())

    utcnow = datetime.utcnow()

    day = calendar.day_name[utcnow.weekday()]

    date = utcnow.day

    hour = utcnow.hour

    torun = []

    for schedule in schedules:

        if (day in schedule['DayOfWeek']) and (hour == schedule['HourOfDay']):
            torun.append(schedule)
        elif (date in schedule['DateOfMonth']) and (hour == schedule['HourOfDay']):
            torun.append(schedule)

    for run in torun:
        logger.info("Executing the Baseline check list for the following parameters")
        logger.info("RoleARN: " + run['RoleARN'])
        logger.info("EmailAddress: " + run['EmailAddress'])

        url = "https://5680671669106366.us-west-1.fc.aliyuncs.com/2016-08-15/proxy/SecurityCenterAutomation.LATEST/create_baseline_check_list_http/"

        body = {
            'RamRoleARN': run['RoleARN'],
            'EmailAddress': run['EmailAddress']
        }

        requests.post(url, json.dumps(body))
        print("")
