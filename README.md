# REMnuxSec-Lab
🛡️ REMnuxSec-Lab – A malware analysis lab using `REMnux` for **static malware analysis**. Includes setup instructions, safe practices, and guided analysis of a malware sample (malware.bin).

---

## Disclaimer

This project is for **educational and research purposes only**.  
Do not upload or distribute live malware in this repository.  
Always perform analysis in a **virtualized, isolated environment**.

---

## 1. Setup Instructions

### 1.1 Install Virtualization Software

- [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
- [VMware Fusion](https://www.vmware.com/products/fusion.html)
- [UTM](https://mac.getutm.app/)

### 1.2 Download REMnux

1. Get the REMnux `.ova` image from [https://remnux.org](https://remnux.org).  

2. Import the OVA into your hypervisor.  

3. Allocate resources:  
   - RAM: `4–8 GB`
   - CPU: `2+ cores` 
   - Disk: `20 GB+`

4. Configure the network interface:
    - `NAT mode` → isolates the VM from your local network while allowing internet access.
    - Optional: use `Host-Only` if you want the VM completely isolated from the internet. 

![REMnux VM](/screenshots/get_started.png)

### 1.3 Take a Snapshot

Before beginning analysis, create a snapshot:

![REMnux VM](/screenshots/snapshot.png)

---

## 2. Analyze Malware

### 2.1 Generate SHA256 Hash

We first generate the `SHA256` hash of the malware file. This **ensures we have a unique fingerprint for the file**, which is useful for tracking, verification, and searching in threat intelligence databases.

```bash
sha256sum malware.bin
```

![Generate SHA256 Hash value](/screenshots/malware_hash_value.png)

### 2.2 Search the Hash on VirusTotal

Next, we use the SHA256 hash to check VirusTotal. **VirusTotal aggregates antivirus results and threat intelligence to identify malware families**.

**Steps**:

1. Go to [VirusTotal](https://www.virustotal.com/)

2. Paste the SHA256 hash:

```bash
d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee
```
 
3. View File Details (In the `Details` section on VirusTotal), we see:
    - File type: MS Word Document (Knowing the file type helps select the correct analysis tools)

![VirusTotal Malware File Type](/screenshots/virustotal.png)

4. View Malware Family (In the `Detection` section on VirusTotal):
    - `Downloader/DOC.Emotet.S1072`

![VirusTotal Malware Family](/screenshots/malware_family.png)

**About this malware family**:

- Emotet is a well-known **banking Trojan and malware downloader**.

- It often spreads via **malicious Word or Excel documents** with macros.

- Once executed, Emotet can **download additional malware**, steal credentials, and propagate across networks.

- The `Downloader/DOC.Emotet.S1072` tag indicates this sample is a **document-based downloader variant** used for spreading Emotet infections.
