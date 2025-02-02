### How to Use This Tool

1. **Port Scanning:**  
   Use the `scan` sub-command to perform advanced TCP/UDP port scanning (with banner grabbing, OS detection, and rate‑limiting).  
   Example:  
   ```bash
   python advanced_net_tool.py scan --targets 192.168.1.0/24 --ports 22-443 --protocol both --os-detect --banner
   ```

2. **SMB Operations:**  
   Enumerate SMB shares or perform credential spraying using the `smb` sub-command.  
   Example (enumeration):  
   ```bash
   python advanced_net_tool.py smb --action enum --target 192.168.1.10
   ```

3. **DNS Lookups:**  
   Reverse‑resolve IPs using the `dns` sub-command.  
   Example:  
   ```bash
   python advanced_net_tool.py dns --targets 8.8.8.8,8.8.4.4
   ```

4. **LDAP Enumeration:**  
   Connect to an LDAP server and (optionally) search a base DN using the `ldap` sub-command.  
   Example:  
   ```bash
   python advanced_net_tool.py ldap --target 192.168.1.20 --search-base "dc=example,dc=com"
   ```

5. **RDP Enumeration:**  
   Check an RDP service by sending a basic negotiation request using the `rdp` sub-command.  
   Example:  
   ```bash
   python advanced_net_tool.py rdp --target 192.168.1.30
   ```

6. **FTP Enumeration:**  
   Enumerate an FTP server (with anonymous login by default) using the `ftp` sub-command.  
   Example:  
   ```bash
   python advanced_net_tool.py ftp --target 192.168.1.40
   ```

7. **SSH Enumeration:**  
   Retrieve the SSH host key fingerprint and optionally test credentials using the `ssh` sub-command.  
   Example:  
   ```bash
   python advanced_net_tool.py ssh --target 192.168.1.50 --username user --password secret
   ```
