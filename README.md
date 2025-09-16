# 🛠️ Cybersecurity Project: Building a Basic Home Lab

This project documents the setup and usage of a **cybersecurity home lab** for practicing threat detection, malware analysis, and network defense in a safe sandboxed environment.  

---

## 🔍 Project Overview
In cybersecurity, practicing on real systems is critical—but dangerous on production machines.  
This project builds an **isolated lab environment** using **VMWare Workstation Player 17, Windows 10, and Kali Linux** to:
- Test new security tools and techniques  
- Safely analyze malware behavior  
- Generate **telemetry logs with Sysmon + Splunk** for detection engineering  
- Practice red-team (attacker) and blue-team (defender) workflows  

---

## ⚙️ Lab Setup (Part 1)
- Installed **VMWare Workstation Player 17** on host system  
- Verified download integrity with **SHA-256 checksums**  
- Created two virtual machines:  
  - **Windows 10 VM** (victim machine) with **Sysmon** & **Splunk** for log collection  
  - **Kali Linux VM** (attacker machine) with penetration testing tools preinstalled  

📸 *Placeholder: Screenshot of VirtualBox with both Windows 10 and Kali Linux VMs created*  

---

## 🌐 Network Configuration (Part 2)
Proper isolation is critical when executing malware. Configured VM networking modes in VirtualBox:  
- **NAT** → For internet connectivity when testing tools  
- **Host-Only / Internal Network** → For malware analysis in a safe, isolated environment  
- Assigned **static IPs** to Windows (192.168.20.10) and Kali (192.168.20.11) to ensure communication  
- Validated connectivity via `ping` while keeping machines isolated from the host  

📸 *Placeholder: Screenshot of VirtualBox network settings (showing NAT/Internal)*  
📸 *Placeholder: Screenshot of Windows `ipconfig` and Kali `ifconfig` showing static IPs*  

---

## 🧑‍💻 Attack Simulation & Telemetry Collection (Part 3)
Simulated attacker vs. defender workflows to study system behavior:

1. **Reconnaissance**  
   - Ran `nmap -A -Pn` from Kali to scan Windows 10 VM  
   - Discovered open services (e.g., RDP on port 3389)  

   📸 *Placeholder: Screenshot of Nmap scan results on Kali*  

2. **Malware Creation**  
   - Generated reverse TCP payload using **msfvenom**  
   - Hosted malicious file via Python HTTP server  
   - Executed payload on Windows 10 to establish **reverse shell** connection  

   📸 *Placeholder: Screenshot of msfvenom payload generation*  
   📸 *Placeholder: Screenshot of Python HTTP server serving the payload*  

3. **Exploitation**  
   - Obtained Meterpreter shell  
   - Executed commands like `net user`, `ipconfig`, and `net localgroup`  

   📸 *Placeholder: Screenshot of Meterpreter session with executed commands*  
   📸 *Placeholder: Screenshot of Task Manager showing malicious process (resume.pdf.exe)*  

4. **Detection Engineering (Blue Team)**  
   - Configured **Sysmon** to capture process creation & network connections  
   - Ingested logs into **Splunk (index=endpoint)**  
   - Installed Splunk Sysmon Add-on to parse telemetry  
   - Detected malicious activity:  
     - Parent process spawning (`resume.pdf.exe → cmd.exe`)  
     - Outbound connections to Kali attacker IP  
     - Suspicious commands logged from shell activity  

   📸 *Placeholder: Screenshot of Splunk dashboard with Sysmon logs*  
   📸 *Placeholder: Screenshot of Splunk query result highlighting suspicious process creation*  

---

## 🧾 Key Learning Outcomes
- Gained practical experience with **VM setup & isolation** for cybersecurity testing  
- Understood **network modes** (NAT, Bridged, Host-Only, Internal) and their security implications  
- Built custom **malware payloads** and analyzed their behavior  
- Developed **Splunk queries** for detecting suspicious process creation and network activity  
- Strengthened hands-on skills in both **offensive security (red team)** and **defensive monitoring (blue team)**  

---

## 🚀 Future Improvements
- Add **network sensors (Zeek/Suricata)** for richer packet-level visibility  
- Expand lab to include **Active Directory** environment for enterprise-level attack/defense practice  
- Automate detection rules and response using **SOAR playbooks**  

---

## 📌 Recruiter/Manager Value
This project demonstrates:
- **Hands-on SOC skills**: detection engineering, log analysis, incident investigation  
- **Practical malware analysis** in a controlled lab environment  
- **Strong understanding of attack/defense lifecycle** across MITRE ATT&CK stages  

---

## 🔗 References
- [YouTube Series Part 1](https://www.youtube.com/watch/kku0fVfksrk) – Lab setup with VirtualBox  
- [YouTube Series Part 2](https://www.youtube.com/watch/5iafC6vj7kM) – Network configuration  
- [YouTube Series Part 3](https://www.youtube.com/watch/-8X7Ay4YCoA) – Attack simulation & telemetry  
- Splunk Sysmon Add-on: [Splunkbase](https://splunkbase.splunk.com/app/1914)  

---
