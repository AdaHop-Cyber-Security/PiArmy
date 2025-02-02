### Explanation

1. **Modular Design & Sub‑Commands:**  
   The tool is divided into sub‑commands (scan, smb, dns, ldap, rdp, ftp, ssh, smtp, discover) so that you can select the desired functionality without running unnecessary modules.

2. **Advanced Scanning:**  
   The core scanner supports both TCP and UDP scans, banner grabbing, and service fingerprinting. It uses concurrent threads with rate‑limiting to balance speed with network safety.

3. **Protocol-Specific Modules:**  
   Modules for SMB, DNS, LDAP, RDP, FTP, SSH, and SMTP are provided, each using appropriate libraries or socket-level interactions.

4. **Auto-Discovery:**  
   The “discover” sub‑command automatically scans a target network using a default list of common ports (if none are specified) and reports live hosts with discovered services. Optionally, it performs OS detection.

5. **Logging and Error Handling:**  
   Comprehensive logging is implemented, with configurable log levels and output options to aid debugging and analysis.

6. **Disclaimer:**  
   Unauthorized scanning is illegal and the author is not responsible for any misuse.

Happy scanning!
