CleanRat is a remote access tool (RAT). Its primary goal is to stay very clean, it a fileless APT-style RAT and evades Windows Defender. The RAT leverages Google Drive as the sole command-and-control (C2) channel, and uses in-memory execution techniques.

---

## Project Overview

CleanRat is engineered to run entirely in memory, minimizing on-disk artifacts and making it difficult for traditional security tools to detect its presence. The key features of CleanRat include:

- **Google Drive C2 Integration:**  
  Uses a Google Cloud service account and OAuth2 for authentication to interact with Google Drive. Command files (with a `.bak` extension) are uploaded to a designated folder, and the RAT polls for these files, executes the commands, and uploads responses back to Google Drive.

- **Evasion & In-Memory Execution:**  
Evasion techniques such as AMSI bypass, reflective DLL injection, and Windows Fibers scheduling are applied to ensure the payload is executed in-memory within a trusted process. This approach reduces its visibility and footprint on the target system.

- **Payload Module (Command Execution):**  
  Executes system shell commands with elevated privileges (for simulation, standard shell execution is used) and captures the output. This output is then packaged and sent back via the Google Drive C2 channel.

- **Minimal Footprint:**  
  The RAT is delivered as a single executable dropper. Once executed, it loads all functionality in memory, performs evasion, and begins polling Google Drive for command files.

---

## Modular Design

The project is organized into three main modules:

### 1. gdrive-communication Module

This module is responsible for all interactions with Google Drive. It is a consolidation of Google Drive authentication, file operations, and the command polling/processing logic.

- **Authentication & Token Management:**  
  Uses a service account key and JWT-based OAuth2 flow to obtain an access token for accessing Google Drive APIs.
  
- **File Operations:**  
  Implements functions to:
  - List files in a designated command folder (files with a `.bak` extension).
  - Download command files.
  - Upload response files.
  
- **Command Polling & Processing:**  
  Periodically polls the command folder, downloads new command files, executes the embedded command, captures the output, writes the output to a temporary file, and then uploads the response file to the response folder.

### 2. Evasion Module

This module encapsulates the advanced evasion techniques required to run the RAT stealthily in memory.

- **AMSI Bypass:**  
  Simulated bypass that patches AMSIScanBuffer to prevent Windows Defender from scanning the payload.
  
- **Reflective DLL Injection:**  
  Simulated reflective DLL injection that "injects" the payload into a trusted process (e.g., explorer.exe) without writing to disk.
  
- **Windows Fibers:**  
  Simulated fiber scheduling that converts threads to fibers and schedules payload execution in a cooperative manner to avoid thread-based detection.

### 3. Payload Module

The payload module is responsible for executing high-privilege commands on the target system.

- **Command Execution:**  
  Provides functions to execute commands (using the system shell) and capture the output.  
  - In a realistic environment, this module could leverage Windows API calls to escalate privileges, but for our PoC, standard command execution is used.
  
- **Integration with C2:**  
  The output from command execution is sanitized and sent back to the operator via the Google Drive communication channel.

---

## Workflow

1. **Initial Drop and In-Memory Loading:**  
   - The RAT is delivered as a single, small executable dropper.
   - Upon execution, the dropper triggers the evasion module to:
     - Patch AMSI (simulate AMSI bypass).
     - Perform reflective DLL injection (simulate payload injection into a trusted process).
     - Schedule payload execution using Windows Fibers (simulate fiber scheduling).

2. **Google Drive C2 Communication:**  
   - The payload, now running entirely in memory, loads its configuration from `gdrive_config.json` and uses the service account key to obtain an access token.
   - The RAT enters a continuous polling loop where it checks a designated command folder on Google Drive for new `.bak` files.

3. **Command Processing:**  
   - When a new command file is detected:
     - The file is downloaded and its content (a command) is extracted.
     - The command is executed using the payload module.
     - The output is captured, saved as a temporary response file, and then uploaded back to a designated response folder on Google Drive.
     - Temporary files are then cleaned up.

4. **Operator Interaction:**  
   - A host-side Python script (or similar tool) can be used to:
     - Prompt the operator to enter commands.
     - Create and upload command files to Google Drive.
     - Continuously poll for and download response files, displaying the sanitized output.

---

## Directory Structure

```
CleanRat_PoC/
├── Cargo.toml                # Project manifest with dependencies.
├── gdrive_config.json        # Configuration file for Google Drive credentials and folder IDs.
└── src/
    ├── main.rs               # Entry point: Initializes evasion routines and starts Google Drive polling.
    ├── gdrive_comm/          # gdrive-communication module.
    │    ├── mod.rs           # Re-exports sub-modules: auth, file_ops, drive_comm.
    │    ├── auth.rs          # OAuth2 token management using service account credentials.
    │    ├── file_ops.rs      # File listing, downloading, and uploading functions.
    │    └── drive_comm.rs    # Polling loop that processes command files and uploads responses.
    ├── evasion/              # Evasion module.
    │    ├── mod.rs           # Re-exports evasion sub-modules.
    │    ├── amsi_bypass.rs   # AMSI bypass routine.
    │    ├── dll_injection.rs # Reflective DLL injection routine.
    │    └── windows_fibers.rs# Windows Fibers scheduling routine.
    └── payload/              # Payload module.
         └── command_exec.rs # High-privilege command execution functionality.
```

## Stay tunned for demo
