### **Shuffle Installation Guide**

This guide provides the steps to install and configure Shuffle, an orchestration and automation engine, using Docker on a Linux-based system.

#### **1. Prerequisites**

    * A clean Ubuntu Server 24 instance.
    * IP Address: 192.168.1.57
    * Resource Allocation: 2 vCPUs, 4GB RAM, 100GB HDD
    * Dependencies: Docker and Docker Compose must be installed on your server.

Ensure your server meets the following requirements before proceeding:

  * A clean server instance with a Linux-based operating system.
  * **Docker and Docker Compose:** These must be installed and functional.
       https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository
  * **Minimum Resources:** A minimum of **4GB of RAM** must be available.

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

      * **Note:** If `chown` returns an error, you may need to add the `opensearch` user first with `sudo useradd opensearch`.

  * **Run Docker Compose:** Start the installation process by running Docker Compose. The `-d` flag runs the containers in detached mode.

    ```bash
    docker-compose up -d
    ```
#### **4. After installation**

After installation, go to http://localhost:3001 (or your servername - https is on port 3443)
    <img width="740" height="599" alt="image" src="https://github.com/user-attachments/assets/a2ea1051-ee0d-4030-8f02-dc82c5f45983" />


Detailed documentation is available on the official Shuffle website. (https://shuffler.io/docs/configuration/)


