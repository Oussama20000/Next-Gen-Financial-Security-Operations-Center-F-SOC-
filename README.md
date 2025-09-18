<img width="851" height="314" alt="image" src="https://github.com/user-attachments/assets/db1d1b76-b8a2-4ae1-aa28-4ff6b4bb6ff9" />

### **Next-Gen Financial Security Operations Center (F-SOC)**

### **Project Description**

This project details the engineering and deployment of a holistic, next-generation Security Operations Center (SOC). It unifies real-time log analysis, network segmentation, and automated incident response for continuous security monitoring and compliance with strict financial regulations on an isolated, internal network.

-----

### **Architecture & Components**

The F-SOC architecture is built on a layered defense model, using two distinct network zones managed by **pfSense**.

  * **LAN (192.168.2.0/24):** This is the local network, housing the **Active Directory** and **Windows endpoints**.
  * **SOC (192.168.1.0/24):** This highly secured zone is home to all the core security tools and is isolated from the LAN to ensure the integrity of security data.

The solution is powered by a suite of powerful open-source tools:

  * **Wazuh:** Used as the **SIEM** for log collection, real-time threat detection, and file integrity monitoring.
  * **pfSense:** Configured as the **firewall** to segment the network.
  * **Shuffle:** The central **orchestration and automation** engine that connects all the platforms.
  * **DFIR IRIS:** Serves as the **incident response platform** for case management and collaboration.
  * **Cortex:** A **threat intelligence engine** that enriches alerts with analysis from sources like VirusTotal and AbuseIPDB.
  * **MISP:** A **threat intelligence platform** for sharing and correlating Indicators of Compromise (IOCs).
  * **Suricata:** An **Intrusion Detection System (IDS)** used to passively monitor network traffic for suspicious activity.

-----

### **Installation & Deployment Guide**

The F-SOC solution was built using multiple virtual machines on Ubuntu Server 24, all communicating within a private network.

#### **Step 1: Network & Firewall Configuration (pfSense)**

  * **Interfaces:** Set up three virtual network adapters: WAN, LAN, and SOC.
  * **IP Addressing:** The following IP addresses were assigned to the VMs.
  * **Note on Firewall Rules:** While not explicitly configured in the initial setup, a robust F-SOC would require firewall rules to strictly control traffic flow between the LAN and SOC, allowing only necessary communication (e.g., logs from LAN to Wazuh).

#### **Step 2: Core Platform Installation **

All security tools were installed on separate Ubuntu Server 24 VMs.

| **VM** | **IP Address** | **Resource Allocation** |
| :--- | :--- | :--- |
| **pfSense** | **LAN:** `192.168.2.1`\<br\>**SOC:** `192.168.1.1` | 2 vCPUs, 1MB RAM, 20GB HDD |
| **Wazuh** | `192.168.1.54` | 2 vCPUs, 4GB RAM, 100GB HDD |
| **Shuffle** using Docker | `192.168.1.53` | 2 vCPUs, 7GB RAM, 100GB HDD |
| **Cortex + MISP** using Docker | `192.168.1.55` | 2 vCPUs, 7GB RAM, 100GB HDD |
| **DFIR IRIS** using Docker| `192.168.1.57` | 2 vCPUs, 4GB RAM, 100GB HDD |
| **Suricata** | `192.168.1.56` | 2 vCPUs, 2GB RAM, 50GB HDD |
| **Active Directory** | `192.168.2.70` | 2 vCPUs, 4GB RAM, 50GB HDD |
| **Windows Endpoint** | `192.168.2.71` | 2 vCPUs, 2GB RAM, 50GB HDD |

#### **Step 3: Wazuh Agent Deployment**

Wazuh agents were deployed on the **Windows Endpoint** and **Active Directory** machines. The agents were configured to send logs and telemetry to the Wazuh server in the SOC network.

#### **Step 4: Suricata IDS Setup**

Suricata was installed on a separate Ubuntu VM with two network adapters. One adapter was configured with an IP address on the SOC network for management and log output, while the other was configured without an IP and used in promiscuous mode to passively listen to network traffic.

-----

### **Integration & Automation Pipeline**

The core of the F-SOC solution is a robust automation pipeline orchestrated by **Shuffle**, which unifies the different tools to provide a streamlined, automated response to threats.

#### **Wazuh to Shuffle (Webhooks)**

Wazuh is configured to send alerts to Shuffle using webhooks based on specific custom rule IDs. When an alert with one of these rule IDs is triggered, Shuffle receives the alert data and begins its automated workflow.

#### **Shuffle to DFIR IRIS (API)**

Shuffle uses its built-in applications and the IRIS API to create cases and alerts. For more complex workflows, custom Python scripts are used.

  * **Mimikatz Detection:** A custom Wazuh rule detects the execution of Mimikatz. This alert is sent to Shuffle, which then runs a custom Python script. The script extracts the file hash from the alert, submits it to **Cortex** for analysis, and then adds the analysis results to the IRIS case.
  * **Nmap Scan Check:** When a Suricata alert for an Nmap scan is triggered, it is sent to Shuffle. A custom Python script checks if the source IP is from a list of trusted IPs. If not, a case is created in IRIS for a security analyst to investigate.

#### **Shuffle to Cortex & MISP (API)**

Shuffle uses dedicated apps to connect to **Cortex** and **MISP** via API keys.

  * **Cortex:** When a case is created, Shuffle sends IOCs (IPs, hashes, domains) to Cortex for automated analysis using its analyzers (e.g., VirusTotal, AbuseIPDB). The results are then added back to the IRIS case to enrich the alert.
  * **MISP:** MISP is used to proactively search for IOCs related to an alert. The workflow queries MISP through a Shuffle app, and the returned information is used to generate a report within IRIS.

#### **Additional Repositories**

For a detailed breakdown of the installation and configuration of each component, please refer to the related repositories:

* [Wazuh-Installation.md](https://github.com/Oussama20000/Next-Gen-Financial-Security-Operations-Center-F-SOC-/blob/main/Wazuh-Installation.md)
* [Shuffle-Installation.md](https://github.com/Oussama20000/Next-Gen-Financial-Security-Operations-Center-F-SOC-/blob/main/Shuffle-Installation.md)
* [DFIR-IRIS-Installation.md](https://github.com/Oussama20000/Next-Gen-Financial-Security-Operations-Center-F-SOC-/blob/main/DFIR-IRIS-Installation.md)
* [MISP+Cortex-Installation.md](https://github.com/Oussama20000/Next-Gen-Financial-Security-Operations-Center-F-SOC-/blob/main/MISP%2BCortex-Installation.md)
* [Suricata-Installation.md](https://github.com/Oussama20000/Next-Gen-Financial-Security-Operations-Center-F-SOC-/blob/main/Suricata-Installation.md)
* [Integration.md](https://github.com/Oussama20000/Next-Gen-Financial-Security-Operations-Center-F-SOC-/blob/main/Integration.md)
