I will format the Wazuh installation guide you provided into a more professional and well-structured document in English.

-----

### **Wazuh Installation Guide**

This guide provides a detailed, step-by-step walkthrough of the **Wazuh** installation on a Debian-based Linux system.

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

To check the status of the services, you can use the following commands:

```bash
sudo systemctl status wazuh-dashboard
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer 
```

<img width="861" height="225" alt="image" src="https://github.com/user-attachments/assets/705daa82-c89d-444b-b91b-fca62f370212" />
<img width="810" height="140" alt="image" src="https://github.com/user-attachments/assets/2a8ceaa9-59fe-4710-bada-c38a44ea8d1b" />
<img width="826" height="127" alt="image" src="https://github.com/user-attachments/assets/cf689e8a-e7ba-40d0-9bae-4674293beab2" />


