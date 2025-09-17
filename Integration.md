
<img width="1585" height="882" alt="image" src="https://github.com/user-attachments/assets/53767513-4f26-4fcd-a5a1-4569f739f0e9" />

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

**Nmap Scan Check**

This script is used in a Shuffle workflow to check if a Suricata alert for an Nmap scan originates from a trusted IP address.

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

````Bash

curl -X POST "https://192.168.1.57/alerts/merge" \
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


