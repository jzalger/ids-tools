from string import Template

# TODO: Add HTML wrapping to templates
email_template = Template(""" 
<html>
<head></head>
<body>
${msg_body}
</body>
</html>
""")

alert_template = Template(""" 
<div>Time: ${timestamp}</div>
<div>Severity: ${severity}</div>
<div>Category: ${category}</div>
<div>Signature: ${signature}</div>
<div>Source IP: ${src_ip}</div>
<div>Destination IP: ${dest_ip}</div>
""")