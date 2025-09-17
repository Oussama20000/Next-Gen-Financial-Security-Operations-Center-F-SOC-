
<img width="1585" height="882" alt="image" src="https://github.com/user-attachments/assets/53767513-4f26-4fcd-a5a1-4569f739f0e9" />
<img width="1583" height="678" alt="image" src="https://github.com/user-attachments/assets/27aac899-4041-446b-b715-6d6fbf32fa8c" />


### **F-SOC Integration & Automation Pipeline**

This guide details the custom rules and configurations that connect Wazuh to Shuffle, creating a fully automated security pipeline.

#### **1. Wazuh Custom Rules**

The following custom rules were created to detect specific threats and send alerts with a unique ID to the automation pipeline. These rules are crucial for triggering Shuffle's workflows.

**Powershell Script Execution**

```xml
<group name="windows,powershell,">
  <rule id="100200" level="8">
    <if_sid>60009</if_sid>
    <field name="win.eventdata.payload" type="pcre2">(?i)CommandInvocation|EncodedCommand|FromBase64String|EncodedArguments|b[a|c|g]-enc|i[e|x]|&lt;.+&gt;</field>
    <description>Encoded command executed via PowerShell.</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
  <rule id="100202" level="4">
    <if_sid>60009</if_sid>
    <field name="win.system.message" type="pcre2">.*blocked by your antivirus software.</field>
    <description>Windows Security blocked malicious command executed via PowerShell.</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
  <rule id="100203" level="10">
    <if_sid>60009</if_sid>
    <field name="win.system.message" type="pcre2">(?i)Add-Persistence|Find-AVSignature|Get-GPPPassword|Get-HttpStatus|Get-Keystrokes|Get-SecurityPackages|Get-TimerScreenshot|Get-VaultCredential|Get-VolumeShadowCopy|Install-Persistence</field>
    <description>Risky cmdlet executed. Possible malicious activity detected.</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
  <rule id="100204" level="8">
    <if_sid>91002</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">.*(I)EX|I[nI]voke-(O)bject|mshta|*GetObject|htaht|New-ActiveXObject</field>
    <description>Mshta used to download a file. Possible malicious activity detected.</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
  <rule id="100205" level="5">
    <if_sid>60009</if_sid>
    <field name="win.eventdata.contextInfo" type="pcre2">(?i)ExecutionPolicy bypass|exec bypass</field>
    <description>PowerShell execution policy set to bypass.</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
</group>
```

**Suricata Alerts**

```xml
<group name="suricata,">
  <rule id="100002" level="7" frequency="5">
    <if_matched_sid>86601</if_matched_sid>
    <if_matched_sid>86601</if_matched_sid>
    <field name="alert.signature" type="pcre2">ET SCAN Potential SSH Scan OUTBOUND</field>
    <options>no_full_log</options>
    <description>Suricata: Un scan agressif potentiel de SSH a ete detecte</description>
    <mitre>
      <id>T1046</id>
      <id>T1069</id>
    </mitre>
  </rule>
  <rule id="100003" level="7">
    <if_sid>86601</if_sid>
    <field name="alert.signature" type="pcre2">ET SCAN NMAP OS Detection Probe</field>
    <options>no_full_log</options>
    <description>Suricata: Un scan agressif avec NMAP a ete detecte</description>
    <mitre>
      <id>T1046</id>
      <id>T1069</id>
    </mitre>
  </rule>
</group>
```

**Failed Login Attempts**

```xml
<group name="windows,authentication_failures,failed_login,">
  <rule id="998906" level="5" frequency="3" timeframe="2m">
    <if_matched_sid>60122</if_matched_sid>
    <if_matched_sid>60122</if_matched_sid>
    <description>Multiple failed login attempts from same user detected (3 in 2 min).</description>
  </rule>
</group>
```

**Mimikatz Detection**

```xml
<group name="windows">
  <rule id="100004" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Mimikatz Usage Detected</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>
</group>
```

-----

#### **2. Wazuh Manager Integration (`ossec.conf`)**

The integration is configured in the Wazuh manager's `ossec.conf` file to forward alerts to the Shuffle webhook.

```xml
<integration>
  <name>shuffle</name>
  <hook_url>http://192.168.1.53:3001/api/v1/hooks/webhook_e3236605-8ec1-4909-98d5-2bf6d5fa90cf</hook_url>
  <rule_id>100002,100003,100004</rule_id>
  <alert_format>json</alert_format>
</integration>
```

-----

#### **3. Shuffle Application Workflows**

Within Shuffle, dedicated apps and custom Python scripts are used to connect to and automate actions on other security tools.

**DFIR IRIS Integration:** Shuffle uses its apps and the IRIS API to automatically create alerts and cases whenever a Wazuh alert is received.

**Cortex and MISP Integration:** Shuffle apps are used to query Cortex and MISP for threat intelligence. For example, a custom workflow can be created to submit a file hash from a Wazuh alert to **Cortex** to run a VirusTotal analyzer.

**Custom Python Scripts:** Shuffle also runs custom scripts for specific tasks, such as:

**I WorkFlow**

**Nmap Scan Check**

This script is used in a Shuffle workflow to check if a Suricata alert for an Nmap scan originates from a trusted IP address.

<img width="440" height="121" alt="image" src="https://github.com/user-attachments/assets/ddb71a1e-992c-46e8-8d1e-6635086f7043" />

```python
import json

# === CONFIG === #
TRUSTED_IP_PREFIXES = ["192.168.2."] # add more prefixes
source_ip = "192.168.1.53"

def is_trusted(ip):
    for prefix in TRUSTED_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False

if is_trusted(source_ip):
    result = {"Block_Ip": "false"}
else:
    result = {
        "Block_Ip": "true",
        "timestamp": "$suricata_events.valid.#.timestamp",
        "title": "$change_me.title",
        "description": "$suricata_events.valid.#.rule.description",
        "source": "$suricata_events.valid.#.agent.name",
        "severity": "$suricata_events.valid.#.data.alert.severity"
    }

print(json.dumps(result))
```

<img width="477" height="551" alt="image" src="https://github.com/user-attachments/assets/76d66e50-bfd6-4c48-98e8-7d6b6c78a4fd" />

**Creating an Alert from Suricata**

This JSON template defines the structure for a comprehensive alert, using data from a Suricata alert as its source. This ensures all relevant details are captured and forwarded for analysis.


```JSON

{
  "alert_title": "$verify_ip.#.message.description",
  "alert_description": "Alert detected from $suricata_events.valid.#.rule.description from $suricata_events.valid.#.data.flow.src_ip. Rule ID: $suricata_events.valid.#.rule.id. Event source: $suricata_events.valid.#.location from Agent $suricata_events.valid.#.agent.name",
  "alert_source": "wazuh",
  "alert_source_ref": "RuleId: $suricata_events.valid.#.rule.id",
  "alert_severity_id": "$verify_ip.#.message.severity",
  "alert_status_id": "5",
  "alert_source_event_time": "$verify_ip.#.message.timestamp",
  "alert_note": "Suricata aggressive scan detected from $suricata_events.valid.#.data.flow.src_ip. Event collected from $suricata_events.valid.#.location",
  "alert_tags": ["T1046", "T1069"],
  "alert_customer_id": "1",
  "alert_classification_id": "2",
  "alert_source_content": "wazuh"
}
```
**Creating a Case from Suricata**

<img width="335" height="717" alt="image" src="https://github.com/user-attachments/assets/e42777ed-f677-4510-8264-f8c80aebf913" />

**Merging Alerts with Cases (DFIR IRIS API)**

This is the final step in the automated workflow, performed by a Shuffle app. It ensures that related alerts are not created as new cases but are instead merged into a single, comprehensive case for the analyst.

1. API Endpoint
The process uses the DFIR IRIS API's alerts/merge endpoint to merge a new alert with an existing case.

2. curl Command
This curl command, executed within a Shuffle app, performs the merge operation.

```Bash

curl -X POST "https://192.168.1.57/alerts/merge/$create_case_suricata.#.body.data.alert_id" \
  -H "Authorization: Bearer API key For Your IRIS" \
  -H "Content-Type: application/json" \
  -d '{
  "target_case_id": "$create_case_suricata.#.body.data.case_id",
  "import_as_event": false,
  "note": "",
  "iocs_import_list": [],
  "assets_import_list": []
}'
```
**Add IOC to the Case**

<img width="338" height="660" alt="image" src="https://github.com/user-attachments/assets/96778fd0-8db8-4b2d-b4ff-e135549238c5" />

**Run Cortex Analyzer**

<img width="334" height="725" alt="image" src="https://github.com/user-attachments/assets/987fcb32-cf9b-4229-8cf7-30646976d71a" />
<img width="330" height="584" alt="image" src="https://github.com/user-attachments/assets/ca19b966-ec75-404c-978c-2f8688e922b6" />

**Results**

<img width="1107" height="206" alt="image" src="https://github.com/user-attachments/assets/91e4233a-fd56-477a-9278-102a817cd5a7" />
<img width="1194" height="690" alt="image" src="https://github.com/user-attachments/assets/fad0e611-b028-4f3e-9122-d89fef2c380a" />
<img width="1550" height="755" alt="image" src="https://github.com/user-attachments/assets/0b752f20-7903-458f-b620-9008ffb24a71" />
<img width="1547" height="751" alt="image" src="https://github.com/user-attachments/assets/d9a2d0ca-bea8-4250-9a19-28763b75713f" />




**II WorkFlow**

<img width="495" height="172" alt="image" src="https://github.com/user-attachments/assets/4640d385-f462-4331-a410-cf8868b37ef1" />

**Mimikatz Hash Extraction**

This script is the first step in the Mimikatz detection workflow. It takes the alert data sent from Wazuh and uses a regular expression to extract the **SHA256 hash** of the detected file.

```python
import re
import json

# Example input (replace with your real event string)
text = "$mimikatz_event.valid.#.data.win.eventdata.hashes SHA256=92804FAAAB2175DC501D73E814663058C78C0A042675A8937266357BCFB96C50"

# Regex to capture SHA256
pattern = r"SHA256=([0-9A-Fa-f]{64})"

match = re.search(pattern, text)

if match:
    sha256 = match.group(1)
    result = {"success": True, "sha256": sha256}
else:
    result = {"success": False, "error": "No SHA256 found"}

# Print JSON result
print(json.dumps(result, indent=4))
```

**VirusTotal Analysis**

This script works in tandem with the hash extraction script. It takes the extracted hash and makes an API call to **VirusTotal** to get a detailed report on the file's reputation.

**NOTE:** You must replace the `x-apikey` value in the headers with your own VirusTotal API key for the script to function.

```python
import requests

# Replace with your extracted SHA256
sha256 = "$extruct_sha256.#.message.sha256"

url = f"https://www.virustotal.com/api/v3/files/{sha256}"

# Replace with your VirusTotal API key
headers = {
    "accept": "application/json",
    "x-apikey": "api_key_for_your_virusTotal"
}

response = requests.get(url, headers=headers)

# Print the full JSON response
print(response.json())
```
<img width="534" height="225" alt="image" src="https://github.com/user-attachments/assets/39617201-527e-4cea-9fa7-057639056669" />

**Creating a Rich Alert**
This JSON template, used within a Shuffle app, defines the structure for a comprehensive alert. It consolidates information from multiple sources—including the original Wazuh alert and the VirusTotal analysis—into a single, rich data object.

```JSON

{
  "alert_title": "$schange_me.title",
  "alert_description": "Mimikatz detected on host: $schange_me.text.win.system.computer via user: $schange_me.text.win.eventdata.user & The VirusTotal scan's result is of 70. Mimicatz activity detection on the process ID : $schange_me.text.win.system.processID in the Path : $schange_me.text.win.eventdata.image The SHA of The File Is $extruct_sha256.#.message.sha256",
  "alert_source": "shuffle",
  "alert_source_ref": "RuleId: 100004",
  "alert_source_link": "https://www.virustotal.com/gui/file/$extruct_sha256.#.message.sha256",
  "alert_severity_id": "5",
  "alert_status_id": "5",
  "alert_source_event_time": "$mimikatz.event.valid.#.data.win.system.systemTime",
  "alert_note": "Mimikatz detected on host:$schange_me.text.win.system.computer via user: $schange_me.text.win.eventdata.user & The VirusTotal scan's result is of 70. Mimicatz activity detection on the process ID : $schange_me.text.win.system.processID, alert_tags : [\"T1003\"], alert_customer_id: \"1\", alert_classification_id\": 2, alert_source_content\": \"shuffle\"}",
  "alert_tags": [
    "T1003"
  ],
  "alert_customer_id": "1",
  "alert_classification_id": "2"
}
```

**Case Creation**
This JSON template, used within a Shuffle app, is used to automatically create a new case in DFIR IRIS based on a Wazuh alert.

```JSON

{
  "case_customer": "$create_alert_mimikatz.#.body.data.customer_id",
  "case_description": "$mimikatz_event.valid.#.rule.description",
  "case_name": "$create_alert_mimikatz.#.body.data.alert_title",
  "case_soc_id": "shuffleS",
  "cid": "${cid}"
}
```
<img width="423" height="123" alt="image" src="https://github.com/user-attachments/assets/c592b3d1-e728-44f2-afdd-b13de3c052ad" />



**Merging Alerts with Cases (DFIR IRIS API)**

This is the final step in the automated workflow, performed by a Shuffle app. It ensures that related alerts are not created as new cases but are instead merged into a single, comprehensive case for the analyst.

1. API Endpoint
The process uses the DFIR IRIS API's alerts/merge endpoint to merge a new alert with an existing case.

2. curl Command
This curl command, executed within a Shuffle app, performs the merge operation.

```Bash

curl -X POST "https://192.168.1.57/alerts/merge/$create_case_mimikatz.#.body.data.alert_id" \
  -H "Authorization: Bearer API key For Your IRIS" \
  -H "Content-Type: application/json" \
  -d '{
  "target_case_id": "$create_case_mimikatz.#.body.data.case_id",
  "import_as_event": false,
  "note": "",
  "iocs_import_list": [],
  "assets_import_list": []
}'
```
**Results**

<img width="1197" height="688" alt="image" src="https://github.com/user-attachments/assets/d0d7f9e2-ba9d-4317-851b-f3b232763eb0" />
<img width="1120" height="217" alt="image" src="https://github.com/user-attachments/assets/ae94ad01-93e3-4c90-aaf7-24848301dd3e" />
<img width="1525" height="749" alt="image" src="https://github.com/user-attachments/assets/84fa42da-e668-4e41-8c5f-43f7c6279bfa" />
<img width="1552" height="797" alt="image" src="https://github.com/user-attachments/assets/686dcf63-5689-4d47-b7c2-48b76b05c518" />


**III WorkFlow**
<img width="1583" height="678" alt="image" src="https://github.com/user-attachments/assets/0a59909c-bea2-4cd1-aa12-68a3a2240786" />

lets begin with 
 <img width="281" height="231" alt="image" src="https://github.com/user-attachments/assets/52288e1e-57f6-4240-a629-a25139547471" />
1. Filter with that rules_id
 <img width="334" height="716" alt="image" src="https://github.com/user-attachments/assets/9c7bffd5-2b37-402a-a036-d8e06b67a433" />
2. Custom Python Script: Alert Generation


This script, used in a Shuffle workflow, takes a raw alert from Wazuh and formats it into a clear, critical alert message. It uses conditional logic to check the rule_id and provides a specific, detailed message for each type of threat.

Script Functionality
The script pulls dynamic information such as the user, timestamp, IP address, and rule ID from the incoming alert. It then uses if statements to match specific rule IDs and print a unique, formatted alert message.

91837: Powershell code execution detected.

100202: Mimikatz execution attempt detected.

100206: Powershell download and execute detected.

92057: Powershell Encoded Command detected.

```Python

import time
import json

timestamp = "$filter_powershell_cmd.valid.#.timestamp"
user = "$filter_powershell_cmd.valid.#.agent.name"
rule_id = "$filter_powershell_cmd.valid.#.rule.id"
ip = "$filter_powershell_cmd.valid.#.agent.ip"

# Default output
output = {}

if rule_id == "91837":
    print("CRITICAL ALERT: PowerShell code execution detected! \n user:" + user + "\n Time:" + timestamp + "\nRule_id:" + rule_id + "\nIp Address:" + ip + "\nReason: A malicious user can download and execute a malicious payload using this method")
elif rule_id == "100202":
    print("CRITICAL ALERT: Mimikatz execution attempt! \n user:" + user + "\nTime:" + timestamp + "\nRule_id:" + rule_id + "\nIp Address:" + ip + "\n Reason: Mimikatz credential dumping attempts ")
elif rule_id == "100206":
    print("CRITICAL ALERT: PowerShell download and execute detected! \n user:" + user + "\n Time:" + timestamp + "\nRule_id:" + rule_id + "\nIp Address:" + ip + "\nReason: SharpHound reconnaissance tool executed ")
elif rule_id == "92057":
    print("CRITICAL ALERT: PowerShell Encoded Command detected! \n user:" + user + "\nTime:" + timestamp + "\nRule_id:" + rule_id + "\nIp Address:" + ip + "\n Reason: Suspicious command line activity using Base64 encoding for obfuscation This is a common technique for bypassing security controls. ")
else:
    print("")
```
3. Create an Alert in Discord

<img width="875" height="756" alt="image" src="https://github.com/user-attachments/assets/5c6625ba-9344-46c4-b66e-f4d05e637fc0" />


4. Results
   <img width="1045" height="665" alt="image" src="https://github.com/user-attachments/assets/430b998b-26c2-4953-9cea-e516af1c649d" />

**IV WorkFlow**

<img width="213" height="415" alt="image" src="https://github.com/user-attachments/assets/adc5fd06-3dd9-419a-9dc0-5c3d89102527" />

1. Filter with that rules_id
   <img width="331" height="722" alt="image" src="https://github.com/user-attachments/assets/3db4522c-7862-440b-821a-6f80d5db932c" />

3. Custom Python Script: Privilege Escalation Detection Script

This Python script is a key component of your automated response workflow. It is designed to detect and take action on unauthorized privilege escalation.

Functionality
The script first checks if a user is part of a trusted group and if the action originates from a trusted IP address. It then makes an intelligent decision:

If Trusted: It generates a notification message to log the action but does not take any automated action.

If Not Trusted: It generates a critical alert and sets a flag to automatically remove the user from the privileged group.

Script Code
```Python

# Values you already extracted
source_ip = "$filter_privilage_escalation.valid.#.agent.ip"
admin_account = "$filter_privilage_escalation.valid.#.data.win.eventdata.subjectUserName"
username = "$filter_privilage_escalation.valid.#.data.win.eventdata.memberName"

# === CONFIG === #
TRUSTED_ADMINS = ["Administrator", "TrustedAdminUser"]
TRUSTED_IP_PREFIXES = ["192.168.1.70"]

def is_trusted(admin_account, ip):
    # Check if admin is trusted
    if admin_account not in TRUSTED_ADMINS:
        return False

    # Check IP starts with trusted subnet
    for prefix in TRUSTED_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False

# Decide action
if is_trusted(admin_account, source_ip):
    action = "allow"
    messageNotif = f"✅ Trusted change: {username} added by {admin_account} from {source_ip}"
    remove_user = "false"

else:
    action = "remove"
    messageNotif = f"⚠️ Unauthorized change: {username} added by {admin_account} from {source_ip}"
    # Extract the CN part
    cn_part = username.split('=')[1]
    # Take the first word (first name) and capitalize it
    first_name = cn_part.split(' ')[0].capitalize()
    remove_user = "true"

ru = {}
if action == "remove":
    ru = {
        "username": username,
        "admin_account": admin_account,
        "source_ip": source_ip,
        "action": "remove",
        "name": first_name,
        "remove_user": "true"
    }
else:
    # Do not output anything if trusted
    ru = {}

output = {
    "messageNotif": messageNotif,
    "remove_user": remove_user,
    "ru": ru
}

print(output)
```


4. Custom Python Script: User Removal Script
   
This script, used in a Shuffle workflow, processes the output from the previous privilege escalation script. Its primary function is to extract and format the username for a user removal action.

Script Functionality
The script takes two variables from the previous workflow's output: the full member name and the remove_user flag. It then extracts the Common Name (CN) part from the full member name, capitalizes the first name, and prepares it for the user removal action.

```Python

member_name_variable = "$verify_ip_and_user.#.message.ru.username"
remove_user = "$verify_ip_and_user.#.message.remove_user"

#Extract the CN part
cn_part = member_name_variable.split('=')[1]
#Take the first word (first name) and capitalize it
first_name = cn_part.split(' ')[0].capitalize()

print(first_name)
```
5. Create an Alert in discord
   <img width="336" height="717" alt="image" src="https://github.com/user-attachments/assets/df9509f3-dcea-4a87-9c90-25e315b42ee3" />

6. remove use from Group
   <img width="336" height="719" alt="image" src="https://github.com/user-attachments/assets/5b78444c-1d47-44d3-a2a1-d38fe674a4f0" />

7. Create an Alert in Discord
   <img width="333" height="720" alt="image" src="https://github.com/user-attachments/assets/97faa09c-1161-410b-97eb-e2e8a129aaa8" />

8. Results
<img width="548" height="62" alt="image" src="https://github.com/user-attachments/assets/c5a50255-6cf7-4cf0-b8ff-e84d7d58f476" />


**V WorkFlow**

<img width="199" height="345" alt="image" src="https://github.com/user-attachments/assets/85173c26-05ec-4818-8079-75e3f329856e" />

1. Filter with that rules_id

<img width="333" height="712" alt="image" src="https://github.com/user-attachments/assets/7b741d51-e7bd-4e68-9721-e311d9789402" />

3. Custom Python Script: Username Extraction Script

This command, used in a Shuffle workflow, is a concise and powerful way to extract a clean username from a log entry. It's a key step for ensuring that a script receives a usable username without a domain or other unnecessary characters.

Command Functionality
The command uses a series of pipes to perform the extraction:

It starts by echoing the full user field.

The first rev command reverses the string.

The cut command then isolates the first part of the reversed string, using the backslash (\) as a delimiter.

The second rev command reverses the result back to its original order, leaving only the username.

```Bash
echo $exec_all_fields.data.win.eventdata.user | rev | cut -d'\' -f1 | rev
```

4. Custom Python Script: SAM Credential Dumping Alert Script

This script, used in a Shuffle workflow, is a valuable addition to your automation. It is specifically designed to detect and format a critical alert for SAM credential dumping, a key threat in Windows environments.

Script Functionality
The script checks for a specific rule_id (92026). When this rule is triggered, the script pulls key information like the user, timestamp, and IP address from the alert and generates a formatted message for a security team to review.

```Python

timestamp = "$sam.valid.#.timestamp"
user = "$sam.valid.#.data.win.eventdata.user"
rule_id = "$sam.valid.#.rule.id"
ip = "$sam.valid.#.agent.ip"

# Default output
output = {}

if rule_id == "92026":
    print("CRITICAL ALERT: SAM credential dumping detected! \n User: "+user+"\n Time: "+timest
```
5. Disable User
<img width="336" height="719" alt="image" src="https://github.com/user-attachments/assets/58face2e-4b7f-4309-916d-ef2764f23844" />

6. Create an Alert in Discord

$<img width="334" height="722" alt="image" src="https://github.com/user-attachments/assets/c1a76a0d-6d05-4ac0-aaae-1c490cf871b0" />

7. Results

   <img width="1308" height="33" alt="image" src="https://github.com/user-attachments/assets/4a1ea7b9-d89b-41c6-80cf-27e1180c6dd5" />











