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
Wazuh Detection & Telemetry Lab (Progress Documentation)

After encountering persistent misconfiguration issues with TheHive, I decided to pause further implementation in order to focus on strengthening my Wazuh SIEM configuration, prioritizing log visibility and detection accuracy.

## Sysmon Telemetry Integration

I modified the Wazuh agent configuration files on my Windows endpoint to enable ingestion of Sysmon telemetry. After restarting the Wazuh service, I verified successful data collection by checking Windows Event Viewer and confirming that Sysmon-generated events were being forwarded correctly. I then validated ingestion on the Wazuh dashboard, where Sysmon events appeared as expected, confirming proper agent-to-manager communication.

## Attack Simulation (Mimikatz)

To simulate real-world attacker behavior and practice detection and response, I downloaded Mimikatz onto the Windows endpoint. Using PowerShell, I executed the binary to generate malicious activity and credential access artifacts. This allowed me to observe how Wazuh handles known adversary techniques during execution.

## Log Forwarding & Archive Enablement

On the Linux Wazuh manager, I accessed and modified the OSSEC configuration to ensure all relevant logs were permitted for forwarding. To support deeper visibility, I updated the Filebeat configuration to enable log archives, allowing raw event data to be ingested rather than only pre-parsed alerts. After applying these changes, I restarted the Filebeat service to apply the updated configuration.

## Index Creation & Validation

To analyze the full set of collected logs, I created a new index pattern (wazuh-archives-*) within Wazuh. This enabled comprehensive visibility into archived event data, allowing me to review low-level telemetry generated during the Mimikatz execution and Sysmon activity.Before simulating any attacker behavior, I verified that Sysmon process creation events were successfully being ingested into Wazuh. This step ensures the telemetry pipeline is functioning correctly prior to conducting detection and response testing.

Using the Wazuh dashboard, I filtered logs for Sysmon Event ID 1 (Process Creation). Event ID 1 logs every process execution on the Windows endpoint and serves as a reliable indicator that Sysmon is actively collecting data and that Wazuh is receiving and indexing those logs.

I confirmed the presence of Event ID 1 entries associated with normal system activity (e.g., PowerShell, command prompt, and Windows system processes). The successful appearance of these events validated end-to-end log flow from the Windows endpoint to the Wazuh manager.

This validation step was completed prior to executing any attack simulations (such as Mimikatz) to ensure that subsequent malicious activity would be observable and detectable once introduced. Using Wazuh’s custom rules framework, I configured a rule to monitor Sysmon Event ID 1 (Process Creation) for indicators associated with Mimikatz activity. The rule was designed to trigger when a process execution matched known Mimikatz characteristics, such as the executable name (mimikatz.exe) or suspicious command-line patterns commonly associated with credential dumping.To validate that the custom detection rule was functioning correctly and that Wazuh was actively receiving endpoint telemetry, I executed Mimikatz on the Windows endpoint. This action generated process creation activity captured by Sysmon Event ID 1.

Upon execution, Wazuh successfully ingested the associated Sysmon logs and triggered the custom detection rule, generating an alert tied to the Mimikatz process. This confirmed that endpoint telemetry was flowing correctly from the Windows host to the Wazuh manager and that the detection logic was operating as expected.

The successful alert served as proof that Wazuh was capable of observing and identifying simulated credential access activity, validating the effectiveness of the logging and detection pipeline.

## Wazuh Manager Troubleshooting During Workflow Integration

Next, I began building an automated workflow using Shuffle.io by creating a webhook to collect event data from the Wazuh manager. To support this integration, I updated the ossec.conf configuration file on the Wazuh manager to include the new webhook-related settings.

After making these changes, I encountered an error when attempting to restart the Wazuh manager. Initial restart attempts failed, indicating an issue with the service. To troubleshoot, I listed Wazuh-related services using systemctl list-units --type=service | grep wazuh and observed that the Wazuh manager service had failed.

I then reviewed the detailed service status using systemctl status wazuh-manager --no-pager -l, which revealed an error message stating “Error reading XML file ‘etc/ossec.conf’.” This indicated a configuration syntax issue rather than a service or dependency failure.

Upon revisiting the ossec.conf file, I identified that a portion of the XML syntax was incomplete due to missing text within one of the configuration tags. After correcting the XML formatting error, I successfully restarted the Wazuh manager, confirming that the issue was resolved.
