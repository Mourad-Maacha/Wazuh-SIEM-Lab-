## Wazuh SIEM Lab

The **Wazuh SIEM Lab** is a home lab environment built to demonstrate centralized security monitoring and incident response using [Wazuh](https://wazuh.com) – an open-source security platform for threat detection, compliance, and incident handling. The lab runs in VirtualBox with three VMs:  
- **Ubuntu Server (Wazuh Manager)** – Hosts the Wazuh manager service (and storage) on a host-only network.  
- **Windows 10/11 (Agent)** – A monitored endpoint running the Wazuh agent and [Sysmon](https://docs.microsoft.com/sysinternals/downloads/sysmon) (Sysinternals). All Windows event logs (Event Viewer and Sysmon/Operational) are collected and sent to the Wazuh manager for analysis.  
- **Kali Linux (Attacker)** – Simulates a threat actor to perform manual exploits and network scans against the Windows VM.  

Wazuh acts as a centralized SIEM, collecting and analyzing log data from the Windows agent in real time to detect anomalies and generate alerts. This project documents both **normal system behavior** and **simulated compromises** (using NextronSystems’ [APTSimulator](https://github.com/NextronSystems/APTSimulator)) as well as manual attacks from Kali, and shows how Wazuh rules identify malicious activity. This project showcases skills in security monitoring and incident response – valuable for security engineering roles.

## Lab Architecture

The lab uses **NAT + Host-Only networking**: all VMs can reach the internet via NAT, while while also sharing a Host-Only network. The Wazuh manager listens on TCP port **1514** by default, and the Windows agent sends encrypted event data to this port. The Kali VM also located on the host-only network will simulate an attacker.  

- **Ubuntu (Wazuh Manager)** – Wazuh manager (analysis engine) receives agent data. It can run as an all-in-one node (with Filebeat/Elasticsearch/Kibana) for alert indexing and a dashboard.  
- **Windows 10/11 (Agent)** – Runs the Wazuh Windows agent (monitors Event Viewer logs) and Sysmon for detailed process and network logging. The agent establishes a secure connection to the manager’s default port 1514.  
- **Kali Linux (Attacker)** – Conducts reconnaissance and exploitation against the Windows VM.  

### The diagram below illustrates the network topology for the lab:  
<img width="600" alt="Network Topology" src="https://github.com/user-attachments/assets/fbc91bc4-34f6-46ec-ab2f-3874acb9476e" />
/>

## Prerequisites

- **Hardware & Platform:** A machine capable of running VirtualBox (or UTM) with sufficient resources (4+ CPU cores, 8+ GB RAM). Support for 64-bit virtualization is required.  
- **Virtual Machines:** ISO images for Ubuntu Server (20.04+), Windows 10/11 (64-bit), and Kali Linux (latest).  
- **Wazuh:** Wazuh manager (version 4.x) on Ubuntu, and Wazuh agent on Windows.  
- **Sysmon (Windows):** Download the latest [Sysinternals Sysmon](https://docs.microsoft.com/sysinternals/downloads/sysmon) binary. **Note:** On Windows ARM64 (e.g. UTM on Apple Silicon), use the *Sysmon64a.exe* (ARM64 build) instead of the x64 binary. Sysmon v4.x or later is recommended.  
- **APT Simulator:** Download [APTSimulator](https://github.com/NextronSystems/APTSimulator) on the Windows VM (password: `apt`). This tool is very useful as it quickly emulates an APT-like compromise.  
- **Network Config:** VirtualBox Host-Only and NAT adapters created in advance. Know the static IPs used (e.g. Host-Only network 172.16.x.x).  

## Setup Steps

### 1. **Prepare VMs:** Install Virtualbox. Install Ubuntu Server, Windows 10/11, and Kali Linux VMs.

### 2. **Network Configuration:**
- Each VM uses two Adapters:
   - **Adapter 1 - NAT:** For safe Internet Access/Downloads/updates.
   - **Adapter 2 - Host-Only:** For internal communication and lab setup.
- **Subnetting:** /28 subnet (16 addresses, mask 255.255.255.240).
Makes sure all three systems share the same isolated network while maintaining controlled segmentation.

**Note1:** If Windows can ping the other VMs but the other VMs can't ping windows it's because Windows Defender Firewall is blocking ICMP. Here are two ways you can fix it:
   1. Option 1 - GUI:
      - Open Windows Security → Firewall & Network Protection → Advanced Settings → Inbound Rules → New Rule... →
Choose Custom → ICMPv4 → Allow the connection (all profiles) → name it “Allow Ping (ICMPv4)”.
   2. Option 2 - Command Line (Faster):
      - Open Powershell as Administrator and paste this:
```bash
netsh advfirewall firewall add rule name="Allow ICMPv4-In" dir=in action=allow protocol=icmpv4
```
**Note2:** In Ubuntu if the second Adapter (Host-only) appears to be "Down", you'll have to bring it up manually following these steps:
   - `ls /etc/netplan/`
   - `sudo nano /etc/netplan/<config-file>.yaml`

Add `enp0s9` (or your secondary NIC) with `dhcp4: true`, then:

   - `sudo netplan apply`
   - `sudo systemctl restart wazuh-dashboard.service`

You can now access the Wazuh Dashboard using the host-only IP.

**Note3:** In Kali if the the second adapter (Host-only) doesn't appear, you'll also have to bring it up manually following these steps:
   -`sudo nano /etc/network/interfaces`
   - Add these lines:
   - #NAT adapter
      - `auto eth0`
      - `iface eth0 inet dhcp`
   - #Host-Only Adapter
      - `auto eth1`
      - `iface eth1 inet dhcp`
- Apply:
   - `sudo systemctl restart networking`

**Note4:** Verify if Windows has a default gateway for the Host-Only Network by typing `IpConfig` in cmd. If it doesn't you'll have to add it manually in the Network Adapter Settings.

> 💡 Tip: When using SSH to access Ubuntu or Kali, use their Host-Only IP addresses for secure, internal connections.

### 3. **Install Wazuh Manager (Ubuntu):** On the Ubuntu VM:
Follow the [official Wazuh Quickstart Guide](https://documentation.wazuh.com/current/quickstart.html) to set up the Wazuh Manager on your Ubuntu VM.

Steps:

1. Update & Upgrade system Packages:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

3. Run wazuh installation script:
   ```bash
   curl -sO https://packages.wazuh.com/4.13/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
   ```
This installs the Wazuh manager, indexer, and dashboard components automatically.

3. It will give you your default Dashboard Credentials:

`username: admin`

`password: ...`

4. Access the Wazuh Dashboard:

Open a browser and navigate to
   ```cpp
https://<wazuh-dashboard-ip>:443
   ```

Replace <wazuh-dashboard-ip> with your Ubuntu VM’s Host-Only IP address (you can verify with ip a).

> 💡 Tip: If the dashboard is unreachable, restart the service:

`sudo systemctl restart wazuh-dashboard.service`


### 4. **Install Wazuh Agent (Windows):** 

1. Go to your Wazuh Dashboard → Click “Add agent” in the top-right corner.
- Select Windows as the operating system.
- Copy the PowerShell command it provides.
2. Run PowerShell as Administrator on your Windows VM and paste the command you copied from the dashboard.
- This automatically downloads, installs, and registers the agent to your Wazuh Manager.

### 5. **Install and Configure Sysmon:**

Sysmon provides detailed system activity logs such as process creation, file access, and network connections, which are essential for detection and correlation within Wazuh.

Steps:

#### 1. Install Sysmon:
   - Create folder:

    ` New-Item -Path "C:\Sysmon" -ItemType Directory -Force`

   - Download Sysmon zip from Microsoft:
  
     `Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Sysmon\Sysmon.zip"`

   - Extract:
     
     `Expand-Archive -Path "C:\Sysmon\Sysmon.zip" -DestinationPath "C:\Sysmon" -Force`

   - Install the wazuh Config (You can choose any config you'd like I just like this one.):
     
     `Invoke-WebRequest -Uri "https://wazuh.com/resources/blog/emulation-of-attack-techniques-and-detection-with-wazuh/sysmonconfig.xml" -OutFile "C:\Sysmon\sysmonconfig.xml"`

   - Install Sysmon using the configuration:

     `Set-Location C:\Sysmon`

     `.\Sysmon.exe -accepteula -i sysmonconfig.xml`

> **💡 Note**: Choose the correct binary for your system:
> - Sysmon.exe → 32-bit
> - Sysmon64.exe → 64-bit
> - Sysmon64a.exe → ARM64 (Apple Silicon)

#### 2. Add Sysmon as a log source for Wazuh:

- Open the Wazuh Agent configuration file:

`C:\Program Files (x86)\ossec-agent\ossec.conf`

- Add the following lines before the closing </ossec_config> tag:

```bash
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

- Restart the Wazuh Agent service:

  `Restart-Service WazuhSvc`

#### 3. Create Custom Wazuh Rules for Sysmon:

- Wazuh only alerts on logs that match defined rules.

Add custom detection logic under /var/ossec/etc/rules/local_rules.xml on the Wazuh server or through Server Management → Rules in the Dashboard.

- These are the rules I added:

```bash
<group name="sysmon">

   <rule id="101101" level="5">
      <if_sid>61603</if_sid>
      <description>Sysmon - Event 1:  Process creation</description>
      <options>no_full_log</options>
   </rule>

   <rule id="101102" level="5">
      <if_sid>61604</if_sid>
      <description>Sysmon - Event 2:  Process changed file creation time</description>
      <options>no_full_log</options>
   </rule>

   <rule id="101103" level="5">
      <if_sid>61605</if_sid>
      <description>Sysmon - Event 3:  Network connection</description>
      <options>no_full_log</options>
   </rule>

   <rule id="101104" level="5">
      <if_sid>61606</if_sid>
      <description>Sysmon - Event 4:  Sysmon service state changed</description>
      <options>no_full_log</options>
   </rule>

   <rule id="101105" level="5">
      <if_sid>61607</if_sid>
      <description>Sysmon - Event 5:  Process terminated</description>
      <options>no_full_log</options>
   </rule>

   <rule id="101106" level="5">
      <if_sid>61608</if_sid>
      <description>Sysmon - Event 6:  Driver loaded</description>
      <options>no_full_log</options>
   </rule>

   <rule id="101107" level="5">
      <if_sid>61609</if_sid>
      <description>Sysmon - Event 7:  Image loaded</description>
      <options>no_full_log</options>
   </rule>

   <rule id="101108" level="5">
      <if_sid>61610</if_sid>
      <description>Sysmon - Event 8:  CreateRemoteThread</description>
      <options>no_full_log</options>
   </rule>

   <rule id="101109" level="5">
      <if_sid>61611</if_sid>
      <description>Sysmon - Event 9:  RawAccessRead</description>
      <options>no_full_log</options>
   </rule>

   <rule id="101110" level="5">
      <if_sid>61612</if_sid>
      <description>Sysmon - Event 10:  ProcessAccess</description>
      <options>no_full_log</options>
   </rule>

   <rule id="101111" level="5">
      <if_sid>61613</if_sid>
      <description>Sysmon - Event 11:  FileCreate</description>
      <options>no_full_log</options>
   </rule>

   <rule id="101112" level="5">
      <if_sid>61614</if_sid>
      <description>Sysmon - Event 12:  RegistryEvent (Object create and delete)</description>
      <options>no_full_log</options>
   </rule>

   <rule id="101113" level="5">
      <if_sid>61615</if_sid>
      <description>Sysmon - Event 13:  RegistryEvent (value set)</description>
      <options>no_full_log</options>
   </rule>

   <rule id="101114" level="5">
      <if_sid>61616</if_sid>
      <description>Sysmon - Event 14:  RegistryEvent (Key and Value rename)</description>
      <options>no_full_log</options>
   </rule>

   <rule id="101115" level="5">
      <if_sid>61617</if_sid>
      <description>Sysmon - Event 15:  FileCreateStreamHash</description>
      <options>no_full_log</options>
   </rule>

</group>
```

Restart Wazuh Manager to apply:

`sudo systemctl restart wazuh-manager`

Once configured, Sysmon logs (e.g., process creation, file creation, network activity) will appear under
Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
and corresponding alerts will be visible in the Wazuh Dashboard.


## Normal Behavior Monitoring

Once running, Windows logs from Sysmon and Event Viewer are sent to Wazuh. These include routine behavior like process creation, file access, network connections, and logons. Wazuh rules are used to selectively alert on notable activity.

Here are some Baseline Activity Logs I recorded:

> **💡 Note**: It's important to play around with the filters, by using Sysmon as a log source and configuring those rules earlier in `local_rules.xml` the logs may be noisy, Windows generates lots of logs by just running - services like Service Host (svchost.exe) are very noisy so you'll have to filter them out.

### 1. 🗂️ File Activity

<img width="600" alt="File Activity" src="https://github.com/user-attachments/assets/e868cbf1-ba14-4500-9cab-57f28f3bcadd" />

### 2. 🌐 Network Activity

<img width="600" alt="Network Activity" src="https://github.com/user-attachments/assets/af683a23-46fb-45b4-afd9-c81a5f34377d" />

### 3. 🗂️ File Download

<img width="600" alt="File Download" src="https://github.com/user-attachments/assets/4e037c54-6c9f-4519-84c8-58fc7148d148" />

### 4. ⚙️ Command Line

<img width="600" alt="cmd" src="https://github.com/user-attachments/assets/5409e345-62e3-407e-b77b-2fc83565ff1a" /> <img width="600" alt="IpConfig" src="https://github.com/user-attachments/assets/d06b082c-0962-4feb-9689-bdad31a54c4e" />

## ⚔️ Attack Simulation
> **Safety note:** run all attack tools **only** in this isolated lab (Host-Only or bridged lab network). Do **not** run these tools against production, home, or public systems. Take a clean snapshot before running anything, and revert when finished. Never run on production or your home network.

### A. APTSimulator
**Purpose:** Quickly emulate a wide range of adversary TTPs (process spawn, credential dump, persistence, scheduled tasks, network beaconing) so you can validate Wazuh detection and rule coverage.

Steps:
1. Download & extract APTSimulator
   - On the Windows VM (run as Administrator):
      1. Download the APTSimulator ZIP from GitHub (latest release).
      2. Extract to `C:\APTSimulator` (or a similar folder).
2. Run it as admin:
   - Open an elevated PowerShell or CMD and run:
      - cd C:\APTSimulator
      - .\APTSimulator.bat
      - This is what you should see:

<img width="600" alt="APTSimulator" src="https://github.com/user-attachments/assets/cf09d6ff-6495-4517-a1d3-57059216513b" />

   - Select an attack. Let it run through its scenario (usually < 1 minute). It performs many behaviors: PowerShell abuse, process creation, registry persistence, LSASS dumping, etc.
   - You should Expect Wazuh alerts for suspicious PowerShell commands, known malicious filenames/hashes, unusual process chains.

Verify

- In Wazuh Dashboard: Threat Hunting -> Security events → filter by Agent (Windows) and rules.
- Inspect the document / event details (click an alert to view full fields). Example fields you can (and should) inspect:
   - `agent.id` / `agent.name` — which host generated the event
   - `agent.ip` — host IP on host-only network
   - `data.win.eventdata.commandLine` — full command that was executed
   - `data.win.eventdata.currentDirectory` — working directory when the process ran
   - `data.win.eventdata.image` — the process binary path (e.g., `C:\Users\Public\svchost.exe)`
   - `data.win.eventdata.hashes` — file hashes (SHA1/MD5/SHA256) of created/executed files
   - `data.win.eventdata.parentCommandLine` / `data.win.eventdata.parentImage` — parent process context
   - `timestamp` — when the action happened

### 🔍 Examples of notable Events I recorded:

<img width="600" alt="Binary" src="https://github.com/user-attachments/assets/5de479b1-c942-41df-b861-c1c17f4eaf72" />

> Example alert showing the detected event for a dropped/executed binary.


<img width="600" alt="Powershell execution" src="https://github.com/user-attachments/assets/99c90778-c4c2-43a9-a5c4-d9364f7ed11c" />

> Sysmon Operational event showing a PowerShell execution that created a temporary script/payload

### B. Manual Attack (Kali)

Steps:

1. Scan Windows Open ports using Nmap.
   - Type `sudo nmap -sV -O "windows-ip-address"`
   - You should see some open ports:

<img width="600" alt="NMAP scan" src="https://github.com/user-attachments/assets/de6c3b7a-390a-4527-8462-b36e4fae010c" />


   - Port 22 is open, let's try to bruteforce into it.
   - I'll be using hydra.
   - Just type: `hydra -l "username" -P "Password File Directory" ssh://"Ip_Address"`
   - Wazuh should show the failed log in log:

<img width="600" alt="SSH failed log in" src="https://github.com/user-attachments/assets/e226e941-e1a0-4866-9804-2cbf560e1504" />

> **💡 Note** The SSH brute-force example above is intentionally simple and performed only to generate log data and validate that the Windows Wazuh agent, the manager rules, and alerting are working end-to-end. This was a controlled, lab-only test — the attempt was expected to fail and was used only to confirm alert visibility. In real enterprise environments, detection is far more comprehensive: organizations use tuned rules, threat intelligence, behavioral analytics, anomaly detection, network controls to detect and block much more sophisticated attacks than a single-port brute force. Always run offensive or disruptive tests only on isolated lab systems you own and snapshot before/after.

## Incident Response (Playbook)
After simulated attacks, you can use the following SOC-style playbook to triage, contain, analyze, and document the incident. 

1. Triage — quickly gather context
   - Identify high-priority alerts in Wazuh Dashboard → Overview / Analysis → Security events.
   - Capture the alert details (click an alert and copy the raw event fields): `commandLine`, `image`, `parentImage`, `hashes`, `user`, `destinationIp/destinationPort`.
2. Contain - prevent any further damage
   - Isolate the infected VM:
        - Power it off.
        - Disable host-only adapter.
3. Evidence Collection

Collect every relevant log before any cleanup. Store them in an artifacts/ folder:
   - Export Sysmon event log (on Windows, elevated PowerShell):
```bash
# export Sysmon operational log to EVTX
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Temp\sysmon.evtx
```
   - Collect manager alerts and logs (Ubuntu):
```bash
# copy alerts (JSON/plain) - edit path as you want
sudo cp /var/ossec/logs/alerts/alerts.json /home/"Username"/artifacts/wazuh-alerts.json
sudo cp /var/ossec/logs/ossec.log /home/"Username"/artifacts/wazuh-manager-ossec.log
```
> Store evtx, ossec.log, and alerts.json together. Hash them (SHA256) for integrity:
```bash
sha256sum /home/youruser/artifacts/* > /home/"Username"/artifacts/checksums.txt
```

4. Analysis
Ideally you would quickly reconstruct timelines to understand how any event happened, search telemetry across hosts for matching indicators (hashes, filenames, or suspicious processes) to determine the scope or any lateral movement.

5. Eradicate
   - In this lab you can just revert to the pre-attack VM snapshot

6. Lessons Learned
   - Review which `rule.id` values fired and whether the alerts were actionable or noisy.
   - Tune `local_rules.xml`
   - Add new rules as you please.

7. Reporting and Documentation
   - Make a short incident report for your `reports/` folder with:
        - Executive summary
        - Timeline (first detection → containment → recovery)
        - Evidence list
        - Rule changes made
        - lessons learned and next steps
   - Here's a fromal template you can use:
```text
- 2025-10-21 10:12 UTC — APTSimulator run started (Agent: WindowsVM)
- 2025-10-21 10:12:10 UTC — Alert 101103 (Network connection) observed on agent WindowsVM
- 2025-10-21 10:12:15 UTC — Alert 101111 (FileCreate) observed — payload written to C:\Users\Public\
- 2025-10-21 10:15 UTC — Host isolated (Host-only adapter disabled)
- 2025-10-21 10:20 UTC — Sysmon EVTX exported & artifacts collected
- 2025-10-21 10:30 UTC — VM reverted to snapshot: Pen-Test-Clean-Snapshot
```
8. Final notes and tips
   - Take notes as you go, even your mistakes, everything has to be documented, you will gain knowledge.
   - Snapshot frequently.
   - Make sure you don't upload sensitive information on the internet if you're planning on it.
   
## Closing summary

This project demonstrates an end-to-end SIEM lab: deploy Wazuh, collect host telemetry with Sysmon, simulate bad behavior (APTSimulator + Kali tests), detect with custom rules, and perform incident response. Everything in this repo is designed to be reproducible and educational.

## Contact

**Mourad Maacha** – [LinkedIn](https://linkedin.com/in/your-linkedin-profile)

## License

This project is licensed under the MIT License.

