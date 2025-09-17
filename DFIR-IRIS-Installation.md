### **DFIR IRIS Installation Guide**

This guide provides the steps to install and configure DFIR IRIS, the incident response and case management platform, using Docker.

#### **1. Prerequisites**

  * A clean Ubuntu Server 24 instance.
  * **IP Address:** `192.168.1.57`
  * **Resource Allocation:** 2 vCPUs, 4GB RAM, 100GB HDD
  * **Dependencies:** Docker and Docker Compose must be installed on your server.

#### **2. Installation**

DFIR IRIS is composed of five separate Docker services. The easiest way to install it is by cloning the official repository and using Docker Compose.

  * **Clone the DFIR IRIS Repository:**
    ```bash
    git clone https://github.com/dfir-iris/iris-web.git
    cd iris-web
    ```
  * **Configure Environment Variables:** Copy the sample environment file to your working directory. You must edit this file to configure your database and set a secure administrator password.
    ```bash
    cp .env.model .env
    nano .env
    ```
   * **Required Configuration Changes
    This section outlines the critical configuration changes needed for a production environment. You must edit the .env file to replace the default secrets.

  We recommend using openssl to generate different, secure values for each secret:
  
  ```bash
    openssl rand -base64 64
  ```

    * POSTGRES_PASSWORD: The password for the PostgreSQL user.
    * POSTGRES_ADMIN_PASSWORD: The password for the database administrator.
    * IRIS_SECRET_KEY: A key used by Flask to secure the session cookies.
    * IRIS_SECURITY_PASSWORD_SALT: A unique salt for password encryption in the database.
   
  * **Pull and Start the Containers:**
    Pull the necessary Docker containers and start the application. The `-d` flag runs the containers in detached mode.
    ```bash
    docker-compose pull
    docker-compose up -d
    ```

#### **3. Initial Access**

After the containers have been started, you can access the DFIR IRIS web interface.

  * **Access URL:** The interface is typically available on `https://<your_instance_ip>`.
  * **Administrator Credentials:** By default, an administrator account is created during the first boot. The password will be printed to the console output. To retrieve it, you can check the Docker logs:
    ```bash
    docker-compose logs app | grep "WARNING :: post_init :: create_safe_admin"
    ```

    <img width="1920" height="891" alt="image" src="https://github.com/user-attachments/assets/6a6c266f-cd44-44d0-b737-0bed58df50bb" />

Detailed documentation is available on the official DFIR-IRIS website. (https://docs.dfir-iris.org/getting_started/)
