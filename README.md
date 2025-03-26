# SIEM Lab: Mapping Windows Logs in Azure Sentinel

## Overview
In this lab, I set up a system to collect logs from both a **Windows 10 virtual machine** and a **Linux virtual machine** visualizing my windows machine in Azure Sentinel, and to display the vulnerabilities of using a linux machine without hardening and securing it. The goal was to gain hands-on experience with SIEM tools, log analysis, and threat detection while building a practical security monitoring solution.

## Lab Setup
### **Tools & Technologies Used:**
- **Azure Sentinel** – Cloud-native SIEM for log analysis and security monitoring
- **Log Analytics Workspace** – Stores and processes log data
- **Windows Event Logs** – Provides system, security, and application logs
- **Linux Logs via SSH** – Demonstrates security vulnerabilities on an unprotected Linux machine
- **GeoIP Data Mapping** – Translates IP addresses into geographic locations

## Implementation Steps
### **1. Setting Up Virtual Machines**
I created two virtual machines:
- **Windows 10 VM**: Configured to collect security event logs and forward them to Azure Sentinel.
- **Linux VM**: Used to demonstrate how attackers attempt to access an unsecured system.

For the Windows machine, I modified its **Network Security Groups (NSGs)** to make it vulnerable by deleting RDP restrictions and allowing all incoming traffic. I also disabled the **Windows Defender Firewall** to simulate an unprotected system. 

### **2. Configuring Log Collection**
#### **Windows Machine:**
- Enabled **Windows Security Event Auditing** for both successful and failed logins.
- Used **Event Viewer** to verify failed login attempts (Event ID: 4625).
- Installed the **Azure Monitor Agent (AMA)** to forward logs to a **Log Analytics Workspace** (since the Log Analytics Agent was deprecated).

#### **Linux Machine:**
The Linux system was not connected to Sentinel but was used to demonstrate how vulnerable it is by default.
- Accessed logs using SSH: `$ ssh labuser@[linux machine public ip]`
- Navigated to log directory: `$ cd /var/log/`
- Inspected authentication logs: `$ cat auth.log`
- Filtered login attempts using: `$ cat auth.log | grep password`

This showed how quickly attackers attempted to log in to an unprotected Linux system.

### **3. Ingesting Logs into Azure Sentinel**
- Created an **Azure Log Analytics Workspace** and connected it to **Azure Sentinel**.
- Enabled **Windows Security Events via AMA** within Sentinel's **Content Hub**.
- Configured a **Data Collection Rule** to ingest security logs from the Windows VM.
- Verified log ingestion using KQL queries in **Log Analytics**.

As you can see after only 20 minutes I have around 10,000 failed login attempts from bad actors, this is a good way to show how dangerous it is to have an insecure machine.

### **4. Visualizing Attack Sources on a World Map**
To map failed login attempts geographically:
- Created a **Geo-IP Watchlist** in **Sentinel**.
- Queried failed login attempts using **KQL** to extract IP addresses.
- Mapped IPs to geographic locations.
- Created an **Azure Workbook** using the following **JSON query** to visualize attacks on a heatmap:

To put it simply the objective of this workbook is to take the data from my Log Analytics workspace, and map them onto the world map that is set to be presented as a heat map.

```json
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents = SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname\n| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,\nfriendly_location = strcat(cityname, \" (\", countryname, \")\");",
    "size": 3,
    "timeContext": {
      "durationMs": 2592000000
    },
    "queryType": 0,
    "resourceType": "microsoft.operationalinsights/workspaces",
    "visualization": "map",
    "mapSettings": {
      "locInfo": "LatLong",
      "locInfoColumn": "countryname",
      "latitude": "latitude",
      "longitude": "longitude",
      "sizeSettings": "FailureCount",
      "sizeAggregation": "Sum",
      "opacity": 0.8,
      "labelSettings": "friendly_location",
      "legendMetric": "FailureCount",
      "legendAggregation": "Sum",
      "itemColorSettings": {
        "nodeColorField": "FailureCount",
        "colorAggregation": "Sum",
        "type": "heatmap",
        "heatmapPalette": "greenRed"
      }
    }
  },
  "name": "query - 0"
}
```

As you can see my heatmap was successful and I’m able to see where my attacks have come from with 3 larger brute force attempts from poland, belgium, and argentina
IN CONCLUSION: this lab gave me a much deeper understanding of Azure, Sentinel , and cloud computing overall. I’m aware conceptually how dangerous it is to have a machine left without a firewall and vulnerable to the internet, but this lab has shown me real world evidence that has proven this much more. I particularly struggled getting familiar with finding AMA(Azure Monitor Agent) as I was unfamiliar with it and log analytics agent was deprecated. 

## Key Takeaways
- **Security Risk Awareness**: An unprotected system receives thousands of attack attempts within minutes.
- **Hands-On Experience**: Worked with Azure Sentinel, Log Analytics, and KQL.
- **Log Analysis & Visualization**: Mapped real-world attack attempts using GeoIP data.

## Challenges & Solutions
- **Log Analytics Agent Deprecation**: Solved by switching to **Azure Monitor Agent (AMA)** and configuring Windows Security Events in Sentinel.
- **Data Collection Rule Setup**: Required learning Sentinel's new data collection process.

## Future Improvements
- Implement **Automated Incident Response** for detected threats.
- Set up **Real-Time Alerts** for brute-force attempts.
- Expand the lab to simulate a **full Security Operations Center (SOC)** workflow.

---
🚀 This project significantly improved my understanding of **SIEM, cloud security, and log analysis**. Next, I plan to integrate **incident response mechanisms** and further automate security monitoring!
