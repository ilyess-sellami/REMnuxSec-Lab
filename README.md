# REMnuxSec-Lab
🛡️ REMnuxSec-Lab – A malware analysis lab using `REMnux` for **static malware analysis**. Includes setup instructions, safe practices, and guided analysis of a malware sample (malware.bin).

---

## Disclaimer

This project is for **educational and research purposes only**.  
Do not upload or distribute live malware in this repository.  
Always perform analysis in a **virtualized, isolated environment**.

---

## 1. Setup Instructions

### Install Virtualization Software

- [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
- [VMware Fusion](https://www.vmware.com/products/fusion.html)
- [UTM](https://mac.getutm.app/)

### Download REMnux

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

### Take a Snapshot

Before beginning analysis, create a snapshot:

![REMnux VM](/screenshots/snapshot.png)

---

## 2. Analyze Malware

### Generate SHA256 Hash

We first generate the `SHA256` hash of the malware file. This **ensures we have a unique fingerprint for the file**, which is useful for tracking, verification, and searching in threat intelligence databases.

```bash
sha256sum malware.bin
```

![Generate SHA256 Hash value](/screenshots/hash_value.png)



 
