I understand. You want me to reformat the installation guide I provided for Cortex and MISP to match the specific structure and content you've given for the Shuffle guide.

Here is the Cortex and MISP installation guide, formatted exactly as you requested.

-----

### **Cortex & MISP Installation Guide**

This guide provides the steps to install and configure **Cortex** and **MISP** on a single Ubuntu Server 24 VM using Docker.

#### **1. Prerequisites**

  * A clean Ubuntu Server 24 instance.
  * IP Address: `192.168.1.55`
  * Resource Allocation: 2 vCPUs, 7GB RAM, 100GB HDD
  * Dependencies: Docker and Docker Compose must be installed on your server.

Ensure your server meets the following requirements before proceeding:

  * A clean server instance with a Linux-based operating system.
  * **Docker and Docker Compose:** These must be installed and functional.
      * [https://docs.docker.com/engine/install/ubuntu/\#install-using-the-repository](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository)
  * **Minimum Resources:** A minimum of **4GB of RAM** must be available.

#### **2. Installation**

Both Cortex and MISP are installed using Docker Compose files. The installation process involves cloning their respective repositories, configuring environment variables, and then running `docker-compose`.

  * **Cortex Installation:**
    1.  Clone the Cortex repository:
        ```bash
        git clone https://github.com/TheHive-Project/Cortex.git
        cd Cortex
        ```
    2.  Run the Docker Compose file to start Cortex:
        ```bash
        docker-compose up -d
        ```
  * **MISP Installation:**
    1.  Clone the MISP Docker repository:
        ```bash
        git clone https://github.com/MISP/misp-docker.git
        cd misp-docker
        ```
    2.  Copy the template environment file:
        ```bash
        cp template.env .env
        ```
    3.  Edit the `.env` file to configure your specific settings, such as `BASE_URL`, and then save the file.
        ```bash
        nano .env
        ```
    4.  Run the Docker Compose file to start MISP:
        ```bash
        docker-compose up -d
        ```

#### **3. After installation**

After the containers are up and running, you can access the web interfaces for initial configuration.

  * **Cortex:** Accessible on `http://192.168.1.55:9001` (by default).
  * **MISP:** Accessible on `https://192.168.1.55`. The default credentials are `admin@admin.test` with the password `admin`. Be sure to change the password immediately after logging in.

    <img width="809" height="157" alt="image" src="https://github.com/user-attachments/assets/20d8a03d-849f-4585-8643-f18334857cc5" />


#### **4. Create the Cortex Super Administrator**

You are then invited to create the first user. This is a Cortex global administration user or superAdmin. This user account will be able to create Cortex organizations and users.
    <img width="1167" height="535" alt="image" src="https://github.com/user-attachments/assets/cc9137bc-0ad9-41d2-b645-6e924d6fa21c" />


Detailed documentation is available on the official StrangeBee website.(https://docs.strangebee.com/cortex/user-guides/first-start/)
Detailed documentation is available on the official MISP website.(https://www.misp-project.org/download/)
