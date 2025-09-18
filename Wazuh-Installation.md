### **Wazuh Installation Guide**

This guide provides a detailed, step-by-step walkthrough of the **Wazuh** installation on a Debian-based Linux system.

#### **Prerequisites
    
    * A clean Ubuntu Server 24 instance.
    * IP Address: 192.168.1.54
    * Resource Allocation: 2 vCPUs, 4GB RAM, 100GB HDD
    * Dependencies: Docker and Docker Compose must be installed on your server.

#### **Step 1: System and Repository Setup**

Ensure `curl` and `gpg` are installed on your system.

```bash
sudo apt update && sudo apt install curl gpg
```

Next, add the Wazuh GPG key and the official repository to your system's package list.

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
sudo apt update
```

#### **Step 2: Configuration & Certificate Generation**

Download the installation assistant script and the configuration file.

```bash
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.12/config.yml
```

Edit the `config.yml` file to define your node names and IP addresses for the Wazuh indexer, manager, and dashboard.

Then, run the assistant to generate the necessary cluster key, certificates, and passwords. These files will be stored in a `.tar` archive.

```bash
bash wazuh-install.sh --generate-config-files
```

You need to copy the `wazuh-install-files.tar` file to all servers in your deployment using a utility like `scp`.

#### **Step 3: Install Wazuh Indexer**

Install and configure the Wazuh indexer by running the installation assistant with the `--wazuh-indexer` option and the corresponding node name (e.g., `node-1`).

```bash
bash wazuh-install.sh --wazuh-indexer node-1
```

#### **Step 4: Cluster Initialization**

After installing all indexer nodes, run the `security admin` script to initialize the cluster. This command only needs to be executed once on any of the indexer nodes.

```bash
bash wazuh-install.sh --start-cluster
```

#### **Step 5: Install Wazuh Manager and Dashboard**

Install the Wazuh manager and dashboard using the installation assistant.

```bash
bash wazuh-install.sh --wazuh-manager wazuh-1
bash wazuh-install.sh --wazuh-dashboard dashboard
```

#### **Step 6: Test the Installation**

To confirm a successful installation, first retrieve the `admin` password.

```bash
tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P "\'admin\'" -A 1
```

Then, use `curl` with the retrieved password to test the connection.

```bash
curl -k -u admin:<ADMIN_PASSWORD> https://<WAZUH_INDEXER_IP>:9200
```

The output should show details of your Wazuh cluster, confirming that the installation was successful.

#### **Step 7: To check the status of the services, you can use the following commands:

```bash
sudo systemctl status wazuh-dashboard
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer 
```

<img width="861" height="225" alt="image" src="https://github.com/user-attachments/assets/705daa82-c89d-444b-b91b-fca62f370212" />
<img width="810" height="140" alt="image" src="https://github.com/user-attachments/assets/2a8ceaa9-59fe-4710-bada-c38a44ea8d1b" />
<img width="826" height="127" alt="image" src="https://github.com/user-attachments/assets/cf689e8a-e7ba-40d0-9bae-4674293beab2" />


#### **Step 8: Interface Wazuh

Once the installation is complete, you need to connect using https://<server_IP_address>.

<img width="859" height="698" alt="image" src="https://github.com/user-attachments/assets/cfbb5424-502c-4ab9-8fb3-756fd332e8b6" />



Detailed documentation is available on the official Wazuh website.
https://documentation.wazuh.com/current/installation-guide/index.html

#### **Wazuh Agents: Installation & Configuration Guide**

This section provides a step-by-step guide on how the Wazuh agents were deployed and configured on the endpoints within the LAN VLAN. The agents were installed on both Linux and Windows machines to ensure comprehensive security telemetry collection.

1. Suricata (Linux Endpoint)
   
The Wazuh agent was installed on the Suricata machine to forward its logs and security events to the central Wazuh manager.

Download and Install the Agent
Use the following command to download the Wazuh agent package and install it in a single step. This command automatically configures the agent to connect to the Wazuh manager's IP address.

<img width="1919" height="971" alt="image" src="https://github.com/user-attachments/assets/6bca1d13-a197-438f-a72c-1a27d2bac5d2">

````Bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.12.0-1_amd64.deb && sudo WAZUH_MANAGER='192.168.1.34' WAZUH_AGENT_NAME='Suricata' dpkg -i ./wazuh-agent_4.12.0-1_amd64.deb
````

WAZUH_MANAGER: Set to the IP address of the Wazuh server on the SOC network.
WAZUH_AGENT_NAME: The name assigned to the Suricata agent in the Wazuh dashboard.

Start the Agent Service
Execute these commands to start the Wazuh agent service and enable it to run automatically on system boot.

```Bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```
<img width="959" height="226" alt="image" src="https://github.com/user-attachments/assets/5d68febd-e015-42ba-9b54-85827896373e">

2. Active Directory & Windows Endpoints
   
The Wazuh agent was deployed on both the Active Directory server and other Windows endpoints to monitor system activity, security logs, and integrity of critical files.

Download and Install the Agent
Open a PowerShell terminal as an administrator and run the following command to download and install the agent silently.

<img width="1919" height="928" alt="image" src="https://github.com/user-attachments/assets/b5387671-69c2-44f3-a6dd-c96f801d56fa">

```Bash
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi -OutFile $env:tmp\wazuh-agent.msi;msiexec.exe /i $env:tmp\wazuh-agent.msi WAZUH_MANAGER='192.168.1.54' WAZUH_AGENT_NAME='ActiveDirectory'
```

WAZUH_MANAGER: The IP address of the Wazuh server.
WAZUH_AGENT_NAME: The name assigned to the agent (e.g., ActiveDirectory).

Start the Agent Service
After a successful installation, the agent service is started using the NET START command.

```Bash
NET START WazuhSvc
```
<img width="815" height="601" alt="image" src="https://github.com/user-attachments/assets/a9e6faf8-cd0c-4fbc-b87c-e22cf019a61a">

<img width="1919" height="716" alt="image" src="https://github.com/user-attachments/assets/5fb9726c-7457-4518-9638-44dd8004d0e7">


File Integrity Monitoring (FIM) Configuration
A crucial security layer of the F-SOC is the File Integrity Monitoring (FIM) configured within the Wazuh agents. FIM provides real-time detection of changes to critical files and directories, which is vital for detecting malware, unauthorized access, and insider threats on a financial network.

The FIM configuration is managed directly on the Wazuh agent within the /var/ossec/etc/ossec.conf file. The following configuration was applied to monitor key system files and directories.

Agent Configuration (ossec.conf)
The syscheck module in the agent's configuration was used to define which files to monitor.

````XML

<ossec_config>
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <directories recursion_level="256" check_all="yes" report_changes="yes" realtime="yes">C:\Users\Public</directories>
    <directories recursion_level="256" check_all="yes" report_changes="yes" realtime="yes">C:\Users\Administrator\Downloads</directories>
````
<img width="1571" height="207" alt="image" src="https://github.com/user-attachments/assets/c38b9aa3-d55e-4f6a-9d88-ba968bed9630" />


The <frequency> tag defines how often a full scan of the monitored directories occurs (e.g., 3600 seconds = once every hour).

The <directories> tag specifies the exact path to monitor. The check_all="yes" attribute ensures that changes to permissions, ownership, and file attributes are also detected, not just content changes.

The realtime="yes" attribute enables real-time monitoring of the directory, which is essential for a proactive security solution.

Once this configuration is added, the Wazuh agent must be restarted for the changes to take effect.





<img width="766" height="526" alt="image" src="https://github.com/user-attachments/assets/92da9003-9ef1-47c5-87c9-2fd8947f97ec" />

<img width="1918" height="146" alt="image" src="https://github.com/user-attachments/assets/9c5e0bd9-f29f-41c3-9fee-216edad8dc53" />

<img width="1118" height="519" alt="image" src="https://github.com/user-attachments/assets/d8ba9064-a566-46e4-bed5-b12abbe86a33" />



