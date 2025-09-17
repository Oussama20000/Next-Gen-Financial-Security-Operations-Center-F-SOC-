### **Suricata Installation Guide**

This guide provides the steps to install and configure **Suricata**, an Intrusion Detection System (IDS), to passively monitor network traffic on a dedicated server.

#### **1. Prerequisites**

  * A clean Ubuntu Server 24 instance.
  * **IP Address:** `192.168.1.56`
  * **Resource Allocation:** 2 vCPUs, 2GB RAM, 50GB HDD
  * **Network Adapters:** The server must have **two network adapters**. One for management (with the IP address `192.168.1.56`) and the second one (`ens37`) for passive sniffing (with no IP address).

#### **2. Installation**

You can install Suricata directly from the Ubuntu package repository.

```bash
sudo apt update
sudo apt install suricata
```

#### **3. Network Configuration**

This is a crucial step for a proper IDS deployment. You need to configure one network adapter for management and a second one to listen for traffic without an IP address.

  * **Configure `netplan`:** Ensure the `ens37` interface has no IP address in your network configuration file. The management interface should have the static IP `192.168.1.56`.
  * **Enable promiscuous mode:** To allow Suricata to capture all network traffic, the sniffing interface (`ens37`) must be put into promiscuous mode.
    ```bash
    sudo ip link set dev ens37 promisc on
    ```

#### **4. Initial Configuration**

Edit the main Suricata configuration file to specify the sniffing interface.

```bash
sudo nano /etc/suricata/suricata.yaml
```

  * Locate the `af-packet` section and ensure it is configured to listen on the `ens37` interface. You may need to uncomment the `- interface: ens37` line.
    
    <img width="522" height="203" alt="image" src="https://github.com/user-attachments/assets/89e3b089-303a-4299-b16e-58a8641c1291" />
    <img width="680" height="32" alt="image" src="https://github.com/user-attachments/assets/c2f6c88a-397d-4e9e-819e-7ac8ed1ea805" />

    


#### **5. Start and Test Service**

Start the Suricata service and verify its status.

```bash
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata
```

<img width="1154" height="230" alt="image" src="https://github.com/user-attachments/assets/0274a6f6-3d23-402a-8658-64911f9b14aa" />
