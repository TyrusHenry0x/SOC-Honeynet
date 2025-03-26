# SIEM Lab: Mapping Brute Force Attacks Using Azure Sentinel

## Lab Setup Overview

To start this lab, I created two virtual machines: a Windows 10 machine and a Linux machine. The Linux VM serves to demonstrate how logs can be viewed via SSH and how vulnerable a default Linux installation can be without any hardening measures. I used the Windows machine to expose it to the internet by opening both its cloud firewall (Network Security Groups) and internal firewall. Then, I configured it to forward logs to a Log Analytics Workspace, connected that workspace to Azure Sentinel, and queried failed logon attempts to map their origins geographically.

---

## Configuring the Windows Machine

- I edited the Network Security Group (NSG) settings for the Windows VM to make it as vulnerable as possible. This included deleting the RDP rule and setting the destination port ranges to "All," effectively allowing all inbound traffic from the internet.
- After connecting to the VM, I opened **Windows Defender Firewall with Advanced Security** and disabled all firewall profiles.
- I then enabled **login auditing** for both successful and failed attempts by modifying the security policy settings.
- With these changes, failed login attempts began appearing in the **Event Viewer** under the **Security logs** with Event ID `4625`.

---

## Configuring the Linux Machine

- To verify connectivity, I pinged the Linux VM from my Windows machine.
- I then SSHed into the Linux VM using:  
  `ssh labuser@[Linux Public IP Address]`
- After authentication, I navigated to the logs directory:  
  `$ cd /var/log/`
- To view authentication related logs:  
  `$ cat auth.log`
- To filter for login related events:  
  `$ cat auth.log | grep password`
- From this output, I could see multiple failed connection attempts from unknown sources, as well as my own successful logins from the `labuser` account.

---

## Setting Up Log Collection

- I created a **Log Analytics Workspace** within my resource group and connected it to **Azure Sentinel**.
- I encountered a hurdle here since Azure deprecated the **Log Analytics Agent (MMA)**. To work around this, I used the **Azure Monitor Agent (AMA)** for the first time.
- I installed the **Windows Security Events connector** via the **Content Hub** in Sentinel and enabled Windows security event collection through AMA.
- I then created a **Data Collection Rule (DCR)** to link my Windows VM to the Log Analytics Workspace.

---

## Reviewing Security Logs

- With everything configured, I ran additional failed login attempts to generate logs.
- Checking Log Analytics, I saw thousands of failed login attempts—over 10,000 within just 20 minutes, clearly indicating brute force attacks from bad actors.

---

## Visualizing Attacks on a Map

- I created a **Sentinel Workbook** to visualize where attacks were originating.
- First, I removed default content in the workbook and added the following custom KQL query using the **Advanced Editor**:

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

- The goal of this query was to project failed logins on a world map, visualized as a heatmap using IP geolocation.  
- The result was successful — I was able to see concentrated brute-force attempts from **Poland**, **Belgium**, and **Argentina**.

---

## Conclusion

This lab provided me with hands-on experience in **Azure**, **Sentinel**, and **cloud security**. While I was conceptually aware of the risks of having an unprotected machine exposed to the internet, this exercise gave me real-world evidence of those dangers. I encountered and overcame challenges with the **Azure Monitor Agent**, which deepened my technical knowledge.

---

## Next Steps

My next goal is to expand this project from a **SIEM demonstration** into a full **Security Operations Center (SOC)** setup. This would include creating incident response workflows, setting up automated alerts, and scheduling regular log updates.
