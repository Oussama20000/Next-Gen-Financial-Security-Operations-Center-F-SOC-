### **Shuffle Installation Guide**

This guide provides the steps to install and configure **Shuffle**, an orchestration and automation engine, using Docker on a Linux-based system.

#### **1. Prerequisites**

    * A clean Ubuntu Server 24 instance.
    * IP Address: 192.168.1.53
    * Resource Allocation: 2 vCPUs, 4GB RAM, 100GB HDD
    * Dependencies: Docker and Docker Compose must be installed on your server.
    
Ensure your server meets the following requirements before proceeding

#### **2. System Configuration**

Before installing Shuffle, configure the system to ensure the database runs smoothly.

  * **Disable Swap:** Temporarily disable swap to prevent performance issues with the database.
    ```bash
    sudo swapoff -a
    ```
  * **Configure VM Map Count:** Set the `vm.max_map_count` kernel parameter, which is a requirement for the OpenSearch database used by Shuffle.
    ```bash
    sudo sysctl -w vm.max_map_count=262144
    ```

#### **3. Installation**

  * **Download Shuffle:** Clone the official Shuffle repository from GitHub.
    ```bash
    git clone https://github.com/Shuffle/Shuffle.git
    cd Shuffle
    ```
  * **Create Database Directory:** Create a dedicated directory for the database and set the correct permissions.
    ```bash
    mkdir shuffle-database
    sudo chown -R 1000:1000 shuffle-database
    ```
    *Note: If `chown` returns an error, you may need to add the `opensearch` user first with `sudo useradd opensearch`.*
  * **Run Docker Compose:** Start the installation process by running Docker Compose. The `-d` flag runs the containers in detached mode.
    ```bash
    docker-compose up -d
    ```

<img width="751" height="621" alt="image" src="https://github.com/user-attachments/assets/c706218a-0d58-4498-a4ba-ec979d22a50f" />


Detailed documentation is available on the official Shuffle website. (https://shuffler.io/docs/configuration/)


