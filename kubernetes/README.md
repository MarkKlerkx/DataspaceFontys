This folder contains parts of the following repository: https://github.com/wistefan/deployment-demo/tree/main

------------------------------------------------------------------------------

To install the demo environment follow the instructions below:

1. Get docker credentials.
   To able to download the container images without any restrictions you have to create a Docker Hub account.

2. Afterwards you have to create an access token
 
3. Server installation and configuration:
   * Linux Ubuntu 25.04 server
   * Ubuntu Server (Minimized)
   * Set static ip-address
   * Enable OpenSSH Server

4. Server credentials:
   * Loginname: dataspace-admin
   * Password: F0nty$2026!@

5. Make directories	
sudo mkdir /fiware
sudo mkdir /fiware/scripts

Get installation script	cd /fiware/scripts

sudo wget raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/installationScript.sh

Set permissions on the script	sudo chmod +x /fiware/scripts/installationScript.sh
Execute the script

Note: when the script fails at the first steps, the time of the server is possibly not good. Wait a few minutes and try again.	cd /fiware/scripts

sudo ./installationScript.sh
When the script is finished run this command	source ~/.bashrc

