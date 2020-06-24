from string import Template
alert_template = """ 
A severity ${SEVERITY} alert was detected by the IDS. Details below:

${MSG_BODY}
"""
