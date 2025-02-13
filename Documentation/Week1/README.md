## **Week 1: Research & Design Phase**

### **Primary Objectives:**
- **Deep Dive into APT41 TTPs:**
  - **Focus Areas:**
    - **Google Drive C2:** Study how APT41 uses cloud services like Google Drive to exchange encrypted command files.
    - **DLL Sideloading:** Investigate techniques where a legitimate signed EXE loads a malicious DLL (and related DLL hollowing).
    - **Windows Fibers:** Research how Windows Fibers are used to execute shellcode in-memory to evade detection.
  - **Action Items:**
    - Review technical articles (e.g., Zscaler deep dives on MoonWalk and DodgeBox).
    - Gather research papers, threat intelligence reports, and blog posts that detail these tactics.
    - Document the key technical steps used by APT41 in these areas.

- **Finalize Feature List & Architectural Blueprint:**
  - List core features to simulate:
    - Secure C2 communication via Google Drive API.
    - Robust encryption using AES-256-GCM with RSA/ECDHE key exchange and PFS.
    - Advanced evasion: code obfuscation, anti-debugging, polymorphism.
    - DLL sideloading/hollowing and in-memory execution using Windows Fibers.
    - Persistence (registry modifications, service installation) and self-destruction.
    - Steganography (e.g., whitespace encoding) for hiding commands.
  - Define module boundaries (Communication, Encryption, Evasion, Payload, Persistence, C2 Backend).
  - Draft high-level architecture diagrams to visualize data flows and interactions (as provided in the project documentation).

- **Select Necessary Rust Libraries:**
  - **Networking & Asynchronous Operations:**  
    - `tokio`, `hyper`, and optionally `reqwest` (for REST API calls).
  - **TLS/Encryption:**  
    - `tokio-rustls` and `rustls-pemfile` for TLS.
    - `ring` or `rust-crypto` for AES-256-GCM and RSA/ECDHE key exchange.
  - **Obfuscation & Anti-Debugging:**  
    - Explore crates like `obfstr` (for string obfuscation) and custom build scripts or compiler flags for additional obfuscation.
  - **File and Process Operations:**  
    - Use Rust’s FFI capabilities to interface with Windows APIs (e.g., for DLL injection, process hollowing, Windows Fibers).

- **Define C2 Structure & Secure Communication Channels:**
  - **C2 Server:**  
    - Develop a Rust-based backend (using `tokio`/`hyper`) that exposes HTTPS endpoints.
    - Integrate with Google Drive API for command file storage and retrieval.
    - Implement IP restrictions, polling, and port knocking within the communication protocols.
  - **RAT Client:**  
    - Build the client to poll for commands, decrypt them, and execute payloads.
    - Ensure in-memory execution and support for dynamic payload updates.
  - **Security Measures:**  
    - All communication channels must use TLS/SSL with proper certificate validation.
    - Incorporate PFS to protect session keys, ensuring that even if long-term keys are compromised, past sessions remain secure.

---

## **Next Steps for Week 1:**

1. **Research:**
   - Collect and summarize technical details on APT41's use of Google Drive C2, DLL sideloading, and Windows Fibers.
   - Reference articles such as those from Zscaler:
     - [MoonWalk Deep Dive – APT41 Part 2](https://www.zscaler.com/blogs/security-research/moonwalk-deep-dive-updated-arsenal-apt41-part-2)
     - [DodgeBox Deep Dive – APT41 Part 1](https://www.zscaler.com/blogs/security-research/dodgebox-deep-dive-updated-arsenal-apt41-part-1)
   - Create a document summarizing these techniques and how they can be ethically simulated.

2. **Finalize Feature List & Architecture:**
   - Write a detailed list of features to be implemented.
   - Create high-level and low-level architecture diagrams (using ASCII diagrams if needed) to illustrate module interactions and data flow.

3. **Library Selection:**
   - Evaluate and list Rust crates for each functionality (e.g., `tokio`, `hyper`, `tokio-rustls`, `ring`, `obfstr`).
   - Document the rationale for each library in your design document.

4. **C2 & Communication Design:**
   - Outline the design for the C2 server and RAT client, specifying endpoints, polling intervals, and key exchange protocols.
   - Decide on the data format for commands and responses (e.g., JSON with encrypted payloads).

5. **Team Coordination:**
   - Assign tasks to each team member (e.g., one focuses on communication/encryption, the other on evasion/persistence).
   - Set up regular check-ins to review research findings and design progress.

---

## Below is a list of point-to-point questions that your team should address during Week 1 (Research & Design Phase):

- **APT41 TTPs Research:**
  - What specific TTPs (Tactics, Techniques, and Procedures) does APT41 use for C2 communication via Google Drive?
  - How does APT41 implement DLL sideloading/hollowing, and what are the key indicators of these techniques?
  - In what ways are Windows Fibers employed for in-memory shellcode execution by APT41?
  - What additional evasion techniques (e.g., anti-debugging, code obfuscation) are prominently featured in APT41 operations?

- **Feature & Architecture Finalization:**
  - Which of APT41’s tactics should be simulated in our project for maximum training effectiveness?
  - What is the complete feature list we aim to replicate (e.g., secure C2, polling mechanism, AES-256-GCM encryption, RSA key exchange, persistence, DLL injection, steganography, etc.)?
  - How will we modularize the tool (what modules are needed: Communication, Encryption, Evasion, Payloads, Persistence, C2 Backend, etc.)?
  - What are the data flows and interactions between modules in our high-level architecture?

- **Rust Libraries Selection:**
  - Which Rust libraries best support asynchronous networking and secure TLS/SSL communication (e.g., `tokio`, `tokio-rustls`, `hyper`)?
  - Which libraries or crates provide AES-256-GCM encryption and RSA/ECDHE key exchange functionality (e.g., `ring`, `rustls`, `rustls-pemfile`)?
  - Are there any crates available for obfuscation or anti-debugging support (e.g., `obfstr`)?
  - How can we handle in-memory execution and process injection via Rust (considering FFI with Windows APIs)?

- **C2 Structure & Communication Channels:**
  - What will be the structure of our C2 server? How will it integrate with Google Drive for storing/retrieving encrypted commands?
  - How will our RAT clients poll for commands and securely receive updates?
  - What mechanisms (such as port knocking and IP restrictions) will be used to ensure that only authorized agents communicate with the C2?
  - What format (JSON, binary protocol, etc.) and encryption schemes will be used for command files?

- **Security & Evasion Considerations:**
  - What self-integrity and anti-tampering checks should be implemented to ensure the RAT hasn’t been modified?
  - How can we implement polymorphism and dynamic code obfuscation to continuously change our binary signature?
  - What stealth techniques (in-memory execution, DLL sideloading, process injection, use of Windows Fibers) will be implemented and how will we test their effectiveness?

- **Documentation & Deliverables:**
  - What documentation is required to capture the design, feature list, module breakdown, and architectural diagrams?
  - How will we validate the design through proof-of-concept or simulation in a controlled lab environment?
  - What are the expected deliverables at the end of Week 1 (research report, finalized architecture diagrams, library selections, and a feature specification document)?


---


## **Deliverables by End of Week 1:**

- A comprehensive **research document** summarizing APT41 tactics (Google Drive C2, DLL sideloading, Windows Fibers).
- A **detailed feature list** and architectural blueprint for CleanRAT-X.
- A list of **selected Rust libraries** with justification.
- High-level and low-level **architecture diagrams** for the overall system.

---
