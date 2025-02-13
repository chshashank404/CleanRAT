# **CleanRAT**

## **Detailed Abstract**

CleanRAT is a Rust-based, modular Remote Administration Tool designed for ethical red team simulations and cybersecurity training. Drawing inspiration from state-sponsored adversaries (e.g., APT41 and similar groups), CleanRAT replicates advanced threat techniques in a controlled environment. Its primary C2 channel leverages the Google Drive API to store and retrieve encrypted command files—allowing its communications to blend with legitimate cloud traffic.

Key aspects include:

- **Secure Communication:**  
  - TLS/SSL (with trusted certificates) combined with Perfect Forward Secrecy (PFS) for dynamic key exchange using RSA/ECDHE.  
  - AES-256-GCM encryption of all data (including configuration files using AES-CFB for flexibility) to ensure end-to-end confidentiality.

- **C2 Channel via Google Drive:**  
  - The RAT client polls a designated Google Drive folder at randomized intervals.  
  - Encrypted command files are uploaded/downloaded, simulating a covert C2 channel that mimics routine cloud file activity.

- **Advanced Evasion & Persistence Techniques:**  
  - Anti-reverse engineering measures: code obfuscation, binary encryption/packing, and runtime polymorphism.  
  - Anti-debugging techniques (detecting tools like OllyDbg/x64dbg) and in-memory execution to minimize forensic artifacts.  
  - Techniques such as DLL sideloading/hollowing and Windows Fibers are integrated to execute shellcode stealthily.
  - Self-integrity checks and anti-tampering routines trigger self-destruction and cleanup if modifications are detected.
  - Persistence mechanisms include process injection, registry modifications, and service installation.

- **Functional Capabilities:**  
  - Keylogging, screen capturing, clipboard monitoring, file exfiltration, and remote command execution.  
  - Steganography (e.g., hiding commands via whitespace encoding) further obscures malicious communication.

CleanRAT is built to simulate real-world advanced persistent threat (APT) operations in a safe, isolated environment, providing realistic scenarios for both red team exercises and blue team training.

---

## **Modules Involved & Their Details**

1. **Communication Module:**  
   - **Google Drive C2 Integration:**  
     - Uses the Google Drive API to upload/download encrypted command files.  
     - Implements OAuth2 (or service account authentication) and polling at randomized intervals.  
     - Supports port knocking and IP restrictions to allow only authorized clients.
   - **TLS/HTTPS Communication:**  
     - Utilizes Rust’s `tokio-rustls` (with trusted certificates) for encrypted channels.  

2. **Encryption & Key Exchange Module:**  
   - **AES-256-GCM Encryption:**  
     - Secures data transmission and payload encryption.  
   - **RSA/ECDHE Key Exchange:**  
     - Facilitates secure exchange of AES session keys with support for Perfect Forward Secrecy.

3. **Evasion & Anti-Analysis Module:**  
   - **Code Obfuscation & Polymorphism:**  
     - Employs compile-time and runtime obfuscation techniques to alter binary signatures dynamically.  
   - **Anti-Debugging & VM/Sandbox Detection:**  
     - Detects and responds to debuggers (e.g., OllyDbg, x64dbg) and virtualization environments.  
   - **In-Memory Execution & Process Injection:**  
     - Loads payloads exclusively in memory and performs DLL sideloading/hollowing to avoid disk artifacts.
   - **Windows Fibers:**  
     - Uses fibers for shellcode execution, bypassing traditional thread-based detection.

4. **Payload & Functional Module:**  
   - **Keylogging, Screen Capture, Clipboard Monitoring:**  
     - Captures and encrypts sensitive data from the target system.
   - **File Exfiltration & Remote Command Execution:**  
     - Facilitates extraction and uploading of files and remote shell operations.
   - **Steganography:**  
     - Hides commands/data using whitespace encoding (or similar techniques) within benign files.

5. **Persistence & Self-Destruction Module:**  
   - **Persistence Mechanisms:**  
     - Implements registry modifications, scheduled tasks, and service installation for long-term access.  
   - **Self-Integrity Checks & Anti-Tampering:**  
     - Continuously verifies binary integrity and triggers a self-destruction routine if compromised.
   - **Remote Update Capability:**  
     - Supports silent, automated updates of the RAT components.

6. **C2 Server Backend Module:**  
   - **Rust-based Backend:**  
     - Provides a secure, scalable command-and-control server running on Ubuntu (or Docker) with HTTPS.
   - **Management Interface:**  
     - Offers a CLI or web-based dashboard for red team operators to dispatch commands and monitor RAT activity.
   - **Logging & IP Restrictions:**  
     - Enforces connection policies and logs all RAT client interactions for auditing and training purposes.

---

## **High-Level Architecture Diagram (ASCII)**

```
         +------------------------------+
         | Blue Team / Host (Windows 11)|
         |  Management Console (CLI/Web)|
         +--------------+---------------+
                        |
                        | Secure TLS/HTTPS (Polling, Port Knocking)
                        |
         +--------------v---------------+
         |      C2 Server Backend       |
         |   (Rust-based, Ubuntu/Docker)|
         | - Google Drive API Integration|
         | - TLS/SSL with PFS            |
         | - IP Restrictions & Logging   |
         +--------------+---------------+
                        |
          Secure Encrypted Channel (Google Drive C2)
                        |
         +--------------v---------------+
         |  RAT Client (Windows 10 VM)  |
         |   CleanRAT (Modular RAT)   |
         | - Communication Module       |
         | - Encryption & Key Exchange  |
         | - Evasion & In-Memory Execution|
         | - Payloads (Keylog, Screen, File Exfil)|
         | - Persistence & Self-Destruction|
         | - Steganography (Whitespace) |
         +------------------------------+
```

---

## **Brief Low-Level Architecture Diagram (ASCII)**

```
[CleanRAT Client]
  ├─[Comm Module]
  │    ├─ TLS/HTTPS Client (tokio-rustls)
  │    ├─ Google Drive Polling & File Retrieval
  │    └─ Port Knocking Handler
  │
  ├─[Encryption Module]
  │    ├─ AES-256-GCM (Data Encryption)
  │    └─ RSA/ECDHE (Key Exchange, PFS)
  │
  ├─[Evasion Module]
  │    ├─ Anti-Debugging, VM Detection
  │    ├─ Code Obfuscation & Polymorphism
  │    ├─ In-Memory Execution (DLL Sideloading/Hollowing)
  │    └─ Windows Fibers for Shellcode Execution
  │
  ├─[Payload Module]
  │    ├─ Keylogging, Screen Capture
  │    ├─ Clipboard & File Operations
  │    └─ Steganography (Whitespace Encoding)
  │
  └─[Persistence & Self-Destruction Module]
       ├─ Registry/Scheduled Task Persistence
       ├─ Self-Integrity Checks & Anti-Tampering
       └─ Remote Update & Self-Destruct Mechanisms
```

## **CleanRAT: Detailed Weekly Development Schedule & Step-by-Step Project Plan**  

This schedule provides a structured development timeline to ensure CleanRAT is built efficiently, incorporating all the required features while maintaining security and stealth. The plan spans **10 weeks**, covering everything from research to deployment and testing.

---

# **📅 Weekly Development Schedule (10 Weeks)**  

| Week        | **Task**                                        | **Details**                                                                                                                                                                                                                                   |
|-------------|-------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Week 1**  | **Research & Design Phase**                     | - Deep dive into APT41 TTPs (Google Drive C2, DLL sideloading, Windows Fibers) <br> - Finalize feature list & architectural blueprint <br> - Select necessary Rust libraries                                                                  |
| **Week 2**  | **Setup & Environment Configuration**           | - Set up Rust development environment <br> - Configure Google Drive API <br> - Set up Docker-based C2 server on Ubuntu <br> - Prepare VM targets (Windows 10 for RAT testing)                                                                 |
| **Week 3**  | **Core Communication Module (Google Drive C2)** | - Implement Google Drive API polling mechanism <br> - Encrypt C2 commands (AES-256-GCM) <br> - Implement TLS/SSL communication fallback <br> - Test connection between RAT & C2                                                               |
| **Week 4**  | **Encryption & Key Exchange Module**            | - Implement AES-256-GCM for secure data handling <br> - Implement AES-CFB for configuration encryption <br> - Implement RSA/ECDHE key exchange with Perfect Forward Secrecy                                                                   |
| **Week 5**  | **Evasion & Anti-Analysis Module**              | - Implement code obfuscation (`obfstr` crate) <br> - Add binary-level encryption & packing <br> - Implement anti-debugging techniques (detecting OllyDbg, x64dbg) <br> - Implement process hollowing & Windows Fibers for shellcode execution |
| **Week 6**  | **Persistence & Self-Defense Module**           | - Implement process injection into trusted processes <br> - Add registry modifications & scheduled task persistence <br> - Implement self-integrity checks & anti-tampering mechanisms <br> - Add self-destruction mechanism                  |
| **Week 7**  | **Payload & Data Exfiltration Module**          | - Implement keylogging <br> - Implement screen capture <br> - Implement clipboard monitoring <br> - Implement file exfiltration & remote command execution                                                                                    |
| **Week 8**  | **Stealth & Advanced Features**                 | - Implement steganography (whitespace encoding for hidden data transfer) <br> - Add polymorphism to change RAT’s signature dynamically <br> - Implement DLL sideloading/hollowing techniques                                                  |
| **Week 9**  | **Testing & Debugging**                         | - Test CleanRAT in real-world attack simulations <br> - Analyze detection rate using Defender, EDRs, & logging tools <br> - Optimize stealth mechanisms & performance                                                                       |
| **Week 10** | **Finalization & Documentation**                | - Document all features, configurations, and red team use cases <br> - Prepare training exercises for blue teams <br> - Create a demo & finalize deployment                                                                                   |

---

# **🛠 Step-by-Step Development Plan (Detailed Breakdown)**  

## **Phase 1: Research & Initial Setup (Week 1-2)**  
### 🔹 **Step 1: Define Project Scope & Threat Model**  
- Identify key APT41 tactics for simulation.  
- Select Rust libraries for networking, encryption, and evasion.  
- Define C2 structure and secure communication channels.  

### 🔹 **Step 2: Set Up Development & Testing Environment**  
- Install Rust, Cargo, and required dependencies.  
- Configure Ubuntu-based Docker C2 server.  
- Set up Windows 10 VM for RAT deployment & evasion testing.  

---

## **Phase 2: Communication & C2 Development (Week 3-4)**  
### 🔹 **Step 3: Implement Google Drive-Based C2**  
- Register Google Drive API keys and configure authentication.  
- Implement polling mechanism to check for encrypted commands.  
- Encrypt commands & responses using AES-256-GCM.  
- Implement fallback TLS/HTTPS communication.  
- Test encrypted command retrieval from Google Drive.  

### 🔹 **Step 4: Implement Encryption & Key Exchange**  
- Generate AES keys dynamically for secure C2 communication.  
- Implement AES-CFB for storing encrypted configurations.  
- Use RSA/ECDHE for secure key exchange & Perfect Forward Secrecy.  

---

## **Phase 3: Evasion & Stealth Techniques (Week 5-6)**  
### 🔹 **Step 5: Implement Advanced Evasion & Stealth Techniques**  
- Add code obfuscation using `obfstr` & custom Rust transformations.  
- Implement binary encryption & packing for stealth.  
- Develop anti-debugging techniques to detect OllyDbg/x64dbg.  

### 🔹 **Step 6: Implement In-Memory Execution & Process Injection**  
- Implement Windows Fibers for shellcode execution.  
- Integrate DLL sideloading & hollowing techniques.  
- Hide CleanRAT within trusted system processes.  

### 🔹 **Step 7: Implement Persistence & Self-Defense**  
- Add registry & scheduled task persistence mechanisms.  
- Implement self-integrity checks to detect tampering.  
- Develop self-destruction mechanisms if RAT is detected.  

---

## **Phase 4: Payload Development & Data Exfiltration (Week 7-8)**  
### 🔹 **Step 8: Implement Core RAT Functionalities**  
- Develop keylogging, screen capturing, and clipboard monitoring.  
- Implement file exfiltration & remote command execution.  

### 🔹 **Step 9: Implement Stealth Features**  
- Develop steganography using whitespace encoding.  
- Implement polymorphism to change RAT’s signature dynamically.  

---

## **Phase 5: Testing, Optimization, & Deployment (Week 9-10)**  
### 🔹 **Step 10: Perform Testing & Debugging**  
- Deploy CleanRATon a test Windows 10 VM.  
- Check for detection by Windows Defender, EDR, and forensic tools.  
- Optimize stealth techniques based on detection results.  

### 🔹 **Step 11: Finalize Project & Documentation**  
- Document features, configurations, and usage.  
- Prepare red team training materials & demo.  
- Optimize code for minimal footprint and high performance.  

---

# **📌 Key Milestones & Deliverables**  

| **Milestone**                         | **Week** | **Deliverable**                                        |
|---------------------------------------|----------|--------------------------------------------------------|
| Initial Setup Complete                | 2        | Rust dev environment, C2 server, VM configured         |
| Google Drive C2 Working               | 3        | Encrypted polling mechanism in place                   |
| Encryption & Key Exchange Implemented | 4        | AES-256-GCM & RSA/ECDHE functional                     |
| Stealth & Evasion Implemented         | 6        | Anti-debugging, in-memory execution, DLL sideloading   |
| RAT Functionalities Implemented       | 8        | Keylogging, screen capture, file exfiltration          |
| Testing & Optimization Completed      | 9        | Fully functional CleanRAT with stealth optimizations   |
| Final Documentation & Deployment      | 10       | Complete project, training docs, red team guide        |


---


