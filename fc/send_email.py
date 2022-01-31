import os
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

mailserver = os.environ['MailServer']
username = os.environ['SMTPUserName']
password = os.environ['SMTPPassword']
toemails = ["siddhantgosavi23@gmail.com"]
subject = "From SMTP Python Local"
files = ["vulnerability_list_cve_2022-01-27T16-49-28.csv", "baselineList_2022-01-27T18-43-44.csv"]

msg = MIMEMultipart()
msg['Subject'] = subject
msg['From'] = '%s <%s>' % ('SecOps Automation', username)
msg['To'] = toemails

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
