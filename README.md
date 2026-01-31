# SOC-Automation-Lab
Here I will be detailing the steps of my SOC Automation Lab.

## Home Lab Environment Setup & Troubleshooting (Wazuh SIEM)

The first phase of this lab focused on preparing a home lab environment to support a Wazuh SIEM deployment. A Windows 10 client virtual machine was created using VirtualBox by downloading and installing a Windows 10 ISO. In parallel, an Ubuntu Server instance hosted on Vultr was provisioned to act as the centralized Wazuh SIEM server. Secure access to the Ubuntu server was established using SSH from PowerShell, allowing for remote administration and configuration.


## Initial Issue: Unable to Access Wazuh Web Dashboard

After installing Wazuh on the Ubuntu server, I was unable to access the Wazuh web dashboard via a browser. Attempting to reach the web interface resulted in a timeout error, indicating a potential networking or firewall-related issue.

To validate connectivity, I first attempted to ping the server from the local machine using the ping comamand in the cmd. The request timed out, suggesting that inbound traffic might be blocked at the network or host level.

Suspecting a firewall misconfiguration, I reviewed the Vultr cloud firewall rules and ensured that inbound TCP traffic on port 443 (HTTPS) was explicitly allowed. This step was necessary because the Wazuh dashboard is accessed over HTTPS. Next, I checked the status of Ubuntu's firewall using sudo ufw status and updated with sudo ufw allow 443/tcp & sudo ufw reload.

On powershell, I tested whether the server was reachable externally on port 443 with Test-NetConnection (ip address) -Port 443. However the test failed meaning that the HTTPS traffic was still not being allowed to process. 

Next, I used sudo ss -tulpn | grep LISTEN to confirm if the Wazuh dashboard was actually running and listening for connections which everything seemed to be running fine. Lastly, I used Test-NetConnections to confirm if the website would be reacble and the value returned True. I was able to then log on the URL using https://(ip address) and successfully logged into Wazuh.
