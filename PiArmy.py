#!/usr/bin/env python3
"""
Advanced Network Tool (Swiss Army Knife)

This tool supports multiple sub‑commands:

  [scan]  Advanced port scanning with TCP/UDP, banner grabbing,
          service fingerprinting, OS detection, rate‑limiting, and CIDR support.
  [smb]   SMB operations including share enumeration and credential spraying.
  [dns]   Reverse DNS lookups.
  [ldap]  LDAP enumeration (with optional authenticated bind and search).
  [rdp]   RDP enumeration via a basic protocol negotiation.
  [ftp]   FTP enumeration with login (anonymous by default) and directory listing.
  [ssh]   SSH enumeration to obtain host key fingerprints and optionally test credentials.

Usage:
  python advanced_net_tool.py <command> [options]

Examples:
  # Port scan a CIDR range with OS detection:
  python advanced_net_tool.py scan --targets 192.168.1.0/24 --ports 22-443 --protocol both --os-detect --banner

  # Enumerate SMB shares:
  python advanced_net_tool.py smb --action enum --target 192.168.1.10

  # Reverse DNS lookup:
  python advanced_net_tool.py dns --targets 8.8.8.8,8.8.4.4

  # LDAP enumeration (anonymous or with credentials):
  python advanced_net_tool.py ldap --target 192.168.1.20 --search-base "dc=example,dc=com"

  # RDP enumeration:
  python advanced_net_tool.py rdp --target 192.168.1.30

  # FTP enumeration:
  python advanced_net_tool.py ftp --target 192.168.1.40

  # SSH enumeration:
  python advanced_net_tool.py ssh --target 192.168.1.50
"""

import sys
import socket
import ipaddress
import argparse
import queue
import threading
import time
import logging
import subprocess
import re

# =============================================================================
#                        COMMON HELPER CLASSES & FUNCTIONS
# =============================================================================

# --- Rate Limiter -------------------------------------------------------------
class RateLimiter:
    def __init__(self, rate):
        """
        Initialize the rate limiter.
        :param rate: Allowed operations per second.
        """
        self.rate = rate
        self.lock = threading.Lock()
        self.last = time.time()

    def wait(self):
        """
        Block until the next operation is allowed.
        """
        with self.lock:
            now = time.time()
            interval = 1.0 / self.rate
            elapsed = now - self.last
            if elapsed < interval:
                time.sleep(interval - elapsed)
            self.last = time.time()

# --- Service Fingerprinting ---------------------------------------------------
def fingerprint_service(banner):
    """
    Attempt to fingerprint a service based on its banner.
    :param banner: The banner string.
    :return: A string representing the identified service.
    """
    banner_lower = banner.lower()
    if "ssh" in banner_lower:
        return "SSH"
    elif "http" in banner_lower:
        return "HTTP"
    elif "smtp" in banner_lower:
        return "SMTP"
    elif "ftp" in banner_lower:
        return "FTP"
    elif "pop3" in banner_lower:
        return "POP3"
    elif "imap" in banner_lower:
        return "IMAP"
    elif "rdp" in banner_lower:
        return "RDP"
    elif "ldap" in banner_lower:
        return "LDAP"
    else:
        return "Unknown"

# --- OS Detection -------------------------------------------------------------
def detect_os(ip):
    """
    Detect the operating system of a host based on ping TTL.
    :param ip: Target IP address (str).
    :return: A string representing the guessed OS.
    """
    try:
        if sys.platform.startswith("win"):
            command = ["ping", "-n", "1", ip]
        else:
            command = ["ping", "-c", "1", ip]
        output = subprocess.check_output(command, universal_newlines=True, stderr=subprocess.STDOUT)
        ttl_search = re.search(r"ttl[=\s]*(\d+)", output, re.IGNORECASE)
        if ttl_search:
            ttl = int(ttl_search.group(1))
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Unknown"
        return "Unknown"
    except Exception as e:
        logging.error(f"OS detection failed for {ip}: {e}")
        return "Unknown"

# --- Port Range Parsing -------------------------------------------------------
def parse_port_range(port_range_str):
    """
    Parse a port range string (e.g. "1-100,443,8080-8090") into a sorted list.
    :param port_range_str: Port range string.
    :return: Sorted list of unique port numbers.
    """
    ports = set()
    for part in port_range_str.replace(" ", "").split(","):
        if "-" in part:
            try:
                start, end = part.split("-")
                for p in range(int(start), int(end) + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except Exception as e:
                logging.error(f"Error parsing port range '{part}': {e}")
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except Exception as e:
                logging.error(f"Error parsing port '{part}': {e}")
    return sorted(list(ports))

# --- Target Parsing -----------------------------------------------------------
def parse_targets(target_str):
    """
    Parse a string containing IP addresses and/or CIDR notations.
    :param target_str: e.g. "192.168.1.1,10.0.0.0/24"
    :return: List of ipaddress.IPv4Address or IPv4Network objects.
    """
    targets = []
    for item in [t.strip() for t in target_str.split(",")]:
        try:
            if "/" in item:
                net = ipaddress.ip_network(item, strict=False)
                targets.append(net)
            else:
                targets.append(ipaddress.ip_address(item))
        except ValueError as e:
            logging.error(f"Invalid target '{item}': {e}")
    return targets

# --- Printing Scan Results ----------------------------------------------------
def print_results(results, show_banner=False):
    """
    Print port scan results in a human‑readable format.
    :param results: List of tuples (ip, port, protocol, status, banner, fingerprint)
    :param show_banner: Whether to display the banner.
    """
    results.sort(key=lambda x: (x[0], x[1], x[2]))
    for ip, port, protocol, status, banner, fingerprint in results:
        if status in ("open", "open|filtered"):
            output = f"[+] {ip}:{port}/{protocol.upper()} - {status.upper()}"
            if show_banner and banner:
                output += f" | Banner: {banner[:100]}..."
            if fingerprint != "Unknown":
                output += f" | Fingerprint: {fingerprint}"
            print(output)
        # Uncomment below to list closed ports:
        # else:
        #     print(f"[-] {ip}:{port}/{protocol.upper()} - CLOSED")

# =============================================================================
#                         ADVANCED PORT SCANNER MODULE
# =============================================================================

class AdvancedPortScanner:
    """
    Advanced port scanner supporting TCP/UDP scanning,
    banner grabbing, rate limiting, and concurrent execution.
    """
    def __init__(self, targets, ports, max_threads=100, timeout=2.0,
                 grab_banner=False, protocol="tcp", rate_limit=0):
        """
        Initialize the scanner.
        :param targets: List of ipaddress.IPv4Address/Network objects.
        :param ports: List of port numbers.
        :param max_threads: Maximum concurrent threads.
        :param timeout: Socket timeout in seconds.
        :param grab_banner: Enable banner grabbing.
        :param protocol: "tcp", "udp", or "both".
        :param rate_limit: Max operations per second (0 means unlimited).
        """
        self.targets = targets
        self.ports = ports
        self.max_threads = max_threads
        self.timeout = timeout
        self.grab_banner = grab_banner
        self.protocol = protocol.lower()
        self.rate_limit = rate_limit
        self.rate_limiter = RateLimiter(rate_limit) if rate_limit > 0 else None

        # Task queue holds (ip, port, protocol)
        self.task_queue = queue.Queue()
        # Results: (ip, port, protocol, status, banner, fingerprint)
        self.results = []
        self.lock = threading.Lock()

    def enqueue_jobs(self):
        """
        Enqueue scanning tasks for each target/port/protocol combination.
        """
        for target in self.targets:
            if isinstance(target, ipaddress.IPv4Network):
                for host in target.hosts():
                    for port in self.ports:
                        if self.protocol in ("tcp", "both"):
                            self.task_queue.put((str(host), port, "tcp"))
                        if self.protocol in ("udp", "both"):
                            self.task_queue.put((str(host), port, "udp"))
            else:
                for port in self.ports:
                    if self.protocol in ("tcp", "both"):
                        self.task_queue.put((str(target), port, "tcp"))
                    if self.protocol in ("udp", "both"):
                        self.task_queue.put((str(target), port, "udp"))

    def scan_port(self, ip, port, protocol):
        """
        Scan a single port using the specified protocol.
        :return: Tuple (ip, port, protocol, status, banner, fingerprint)
        """
        if self.rate_limiter:
            self.rate_limiter.wait()

        banner = ""
        fingerprint = "Unknown"
        status = "closed"

        if protocol == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect((ip, port))
                status = "open"
                if self.grab_banner:
                    try:
                        # Send a simple HTTP HEAD request as an example
                        sock.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % ip.encode())
                        banner = sock.recv(1024).decode(errors="ignore").strip()
                    except Exception as e:
                        logging.debug(f"Banner grab TCP {ip}:{port} failed: {e}")
            except (socket.timeout, ConnectionRefusedError, OSError):
                status = "closed"
            finally:
                sock.close()
        elif protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            try:
                sock.sendto(b"", (ip, port))
                data, _ = sock.recvfrom(1024)
                status = "open"
                banner = data.decode(errors="ignore").strip() if data else ""
            except socket.timeout:
                status = "open|filtered"
            except Exception:
                status = "closed"
            finally:
                sock.close()

        if banner:
            fingerprint = fingerprint_service(banner)
        logging.debug(f"Scanned {ip}:{port}/{protocol.upper()} - {status}")
        return (ip, port, protocol, status, banner, fingerprint)

    def worker_thread(self):
        """
        Worker thread to process scan tasks.
        """
        while True:
            try:
                ip, port, protocol = self.task_queue.get_nowait()
            except queue.Empty:
                break
            result = self.scan_port(ip, port, protocol)
            with self.lock:
                self.results.append(result)
            self.task_queue.task_done()

    def run(self):
        """
        Enqueue tasks, spawn worker threads, and run the scan.
        :return: List of scan results.
        """
        self.enqueue_jobs()
        threads = []
        num_threads = min(self.max_threads, self.task_queue.qsize())
        for _ in range(num_threads):
            t = threading.Thread(target=self.worker_thread, daemon=True)
            t.start()
            threads.append(t)
        self.task_queue.join()
        for t in threads:
            t.join()
        return self.results

# =============================================================================
#                              SMB MODULE (IMPACKET)
# =============================================================================

def smb_enumerate(target, port, username, password):
    """
    Enumerate SMB shares on a target.
    :param target: Target IP address.
    :param port: SMB port.
    :param username: Username (empty for anonymous).
    :param password: Password (empty for anonymous).
    """
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        print("Error: The impacket library is required for SMB functionality. (pip install impacket)")
        sys.exit(1)
    try:
        conn = SMBConnection(target, target, sess_port=port)
        conn.login(username or "", password or "")
        shares = conn.listShares()
        print(f"[*] Shares on {target}:")
        for share in shares:
            share_name = share['shi1_netname'][:-1]
            print(f"  - {share_name}")
        conn.logoff()
    except Exception as e:
        print(f"[-] Error enumerating SMB shares on {target}: {e}")

def smb_spray(target, port, user_file, pass_file):
    """
    Perform credential spraying against SMB.
    :param target: Target IP address.
    :param port: SMB port.
    :param user_file: Path to file with usernames.
    :param pass_file: Path to file with passwords.
    """
    try:
        with open(user_file, "r") as uf:
            users = [line.strip() for line in uf if line.strip()]
        with open(pass_file, "r") as pf:
            passwords = [line.strip() for line in pf if line.strip()]
    except Exception as e:
        print(f"[-] Error reading user or password file: {e}")
        sys.exit(1)
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        print("Error: The impacket library is required for SMB functionality. (pip install impacket)")
        sys.exit(1)
    print(f"[*] Starting SMB credential spraying on {target}:{port}...")
    for user in users:
        for pwd in passwords:
            try:
                conn = SMBConnection(target, target, sess_port=port)
                conn.login(user, pwd)
                print(f"[+] Valid credentials found: {user}:{pwd}")
                conn.logoff()
            except Exception as e:
                logging.debug(f"Failed login {user}:{pwd} on {target}: {e}")

# =============================================================================
#                              DNS MODULE
# =============================================================================

def dns_lookup(targets):
    """
    Perform reverse DNS lookups on a list of IP addresses.
    :param targets: List of IP address strings.
    """
    for ip in targets:
        try:
            host, aliases, _ = socket.gethostbyaddr(ip)
            print(f"[+] {ip} resolves to {host} (aliases: {', '.join(aliases)})")
        except Exception as e:
            print(f"[-] Reverse DNS lookup failed for {ip}: {e}")

# =============================================================================
#                              LDAP MODULE
# =============================================================================

def ldap_enumerate(target, port, bind_dn, password, search_base, search_filter):
    """
    Enumerate an LDAP server.
    :param target: LDAP server IP.
    :param port: LDAP port.
    :param bind_dn: Bind DN for authentication (optional).
    :param password: Password (optional).
    :param search_base: Base DN for search.
    :param search_filter: LDAP search filter.
    """
    try:
        from ldap3 import Server, Connection, ALL, SUBTREE
    except ImportError:
        print("Error: The ldap3 library is required for LDAP functionality. (pip install ldap3)")
        sys.exit(1)
    try:
        server = Server(target, port=port, get_info=ALL)
        conn = Connection(server, user=bind_dn, password=password, auto_bind=True)
        print(f"[+] Connected to LDAP server at {target}:{port}")
        if search_base:
            conn.search(search_base=search_base, search_filter=search_filter, search_scope=SUBTREE, attributes=['*'])
            print(f"[*] LDAP Search Results for base '{search_base}':")
            for entry in conn.entries:
                print(entry)
        else:
            print("[*] No search base provided; only connection test was performed.")
        conn.unbind()
    except Exception as e:
        print(f"[-] LDAP enumeration failed on {target}:{port}: {e}")

# =============================================================================
#                              RDP MODULE
# =============================================================================

def rdp_enumerate(target, port):
    """
    Enumerate an RDP server by sending a basic negotiation request.
    :param target: Target IP.
    :param port: RDP port.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        # Send a basic RDP negotiation request packet.
        packet = b'\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00'
        sock.send(packet)
        data = sock.recv(1024)
        if data:
            print(f"[+] RDP on {target}:{port} responded: {data.hex()}")
        else:
            print(f"[+] RDP on {target}:{port} is open but no response was received.")
        sock.close()
    except Exception as e:
        print(f"[-] RDP enumeration failed on {target}:{port}: {e}")

# =============================================================================
#                              FTP MODULE
# =============================================================================

def ftp_enumerate(target, port, username, password):
    """
    Enumerate an FTP server.
    :param target: FTP server IP.
    :param port: FTP port.
    :param username: Username for login.
    :param password: Password for login.
    """
    try:
        import ftplib
    except ImportError:
        print("[-] ftplib module is missing. This should not happen in Python3.")
        sys.exit(1)
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=5)
        ftp.login(user=username, passwd=password)
        print(f"[+] FTP on {target}:{port} login successful as '{username}'")
        try:
            files = ftp.nlst()
            print("[*] Directory listing:")
            for f in files:
                print(f"  - {f}")
        except Exception as e:
            print("[-] Could not retrieve directory listing.")
        ftp.quit()
    except Exception as e:
        print(f"[-] FTP enumeration failed on {target}:{port}: {e}")

# =============================================================================
#                              SSH MODULE
# =============================================================================

def ssh_enumerate(target, port, username=None, password=None):
    """
    Enumerate an SSH server by obtaining its host key fingerprint and optionally testing credentials.
    :param target: Target IP.
    :param port: SSH port.
    :param username: Username (optional).
    :param password: Password (optional).
    """
    try:
        import paramiko
    except ImportError:
        print("Error: The paramiko library is required for SSH functionality. (pip install paramiko)")
        sys.exit(1)
    try:
        # First, retrieve the host key fingerprint without full authentication.
        transport = paramiko.Transport((target, port))
        transport.start_client(timeout=5)
        remote_key = transport.get_remote_server_key()
        fingerprint = remote_key.get_fingerprint().hex()
        print(f"[+] SSH server on {target}:{port} is up. Host key fingerprint: {fingerprint}")
        if username and password:
            try:
                transport.auth_password(username, password)
                print(f"[+] SSH authentication successful with {username}:{password}")
            except Exception as auth_e:
                print(f"[-] SSH authentication failed with {username}:{password}: {auth_e}")
        transport.close()
    except Exception as e:
        print(f"[-] SSH enumeration failed on {target}:{port}: {e}")

# =============================================================================
#                         MAIN SUB-COMMAND HANDLERS
# =============================================================================

def main_scan(args):
    """Handler for the 'scan' sub-command."""
    targets = parse_targets(args.targets)
    if not targets:
        logging.error("No valid targets found. Exiting.")
        sys.exit(1)
    ports = parse_port_range(args.ports)
    if not ports:
        logging.error("No valid ports found. Exiting.")
        sys.exit(1)
    scanner = AdvancedPortScanner(
        targets=targets,
        ports=ports,
        max_threads=args.threads,
        timeout=args.timeout,
        grab_banner=args.banner,
        protocol=args.protocol,
        rate_limit=args.rate_limit
    )
    start_time = time.time()
    results = scanner.run()
    end_time = time.time()
    print_results(results, show_banner=args.banner)
    elapsed = end_time - start_time
    print(f"\n[*] Scan completed in {elapsed:.2f} seconds.")
    if args.os_detect:
        unique_hosts = {result[0] for result in results if result[3] in ("open", "open|filtered")}
        if unique_hosts:
            print("\n[*] Performing OS Detection:")
            for ip in sorted(unique_hosts):
                os_info = detect_os(ip)
                print(f"[*] {ip} - {os_info}")
        else:
            print("[*] No open hosts found for OS detection.")

def main_smb(args):
    """Handler for the 'smb' sub-command."""
    if args.action == "enum":
        smb_enumerate(args.target, args.port, args.username or "", args.password or "")
    elif args.action == "spray":
        if not args.user_file or not args.pass_file:
            print("For credential spraying, both --user-file and --pass-file are required.")
            sys.exit(1)
        smb_spray(args.target, args.port, args.user_file, args.pass_file)

def main_dns(args):
    """Handler for the 'dns' sub-command."""
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    dns_lookup(targets)

def main_ldap(args):
    """Handler for the 'ldap' sub-command."""
    ldap_enumerate(args.target, args.port, args.bind_dn, args.password,
                   args.search_base, args.search_filter)

def main_rdp(args):
    """Handler for the 'rdp' sub-command."""
    rdp_enumerate(args.target, args.port)

def main_ftp(args):
    """Handler for the 'ftp' sub-command."""
    ftp_enumerate(args.target, args.port, args.username, args.password)

def main_ssh(args):
    """Handler for the 'ssh' sub-command."""
    ssh_enumerate(args.target, args.port, args.username, args.password)

# =============================================================================
#                                   MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Network Tool (Swiss Army Knife)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True,
                                       help="Sub-command to run: scan, smb, dns, ldap, rdp, ftp, ssh")

    # ----------------- SCAN SUB-COMMAND -----------------
    parser_scan = subparsers.add_parser("scan", help="Perform advanced port scanning")
    parser_scan.add_argument("--targets", required=True,
                             help="Comma-separated list of targets (IP or CIDR), e.g. '192.168.1.1,10.0.0.0/24'")
    parser_scan.add_argument("--ports", required=True,
                             help="Port range(s), e.g. '22,80,443' or '1-1024'")
    parser_scan.add_argument("--threads", type=int, default=100,
                             help="Maximum number of concurrent threads (default=100)")
    parser_scan.add_argument("--timeout", type=float, default=2.0,
                             help="Socket timeout in seconds (default=2.0)")
    parser_scan.add_argument("--banner", action="store_true",
                             help="Attempt to grab service banners")
    parser_scan.add_argument("--protocol", choices=["tcp", "udp", "both"], default="tcp",
                             help="Scanning protocol (default=tcp)")
    parser_scan.add_argument("--rate-limit", type=float, default=0,
                             help="Max scan operations per second (0 for unlimited)")
    parser_scan.add_argument("--os-detect", action="store_true",
                             help="Perform OS detection on hosts with open ports")
    parser_scan.add_argument("--log-file", default=None,
                             help="Path to log file (default: log to console)")
    parser_scan.add_argument("--log-level", default="INFO",
                             help="Logging level (DEBUG, INFO, WARNING, ERROR; default=INFO)")

    # ----------------- SMB SUB-COMMAND -----------------
    parser_smb = subparsers.add_parser("smb", help="Perform SMB operations (enumeration or credential spraying)")
    parser_smb.add_argument("--action", choices=["enum", "spray"], default="enum",
                            help="SMB action: 'enum' to enumerate shares, 'spray' for credential spraying")
    parser_smb.add_argument("--target", required=True, help="Target IP address for SMB operations")
    parser_smb.add_argument("--port", type=int, default=445, help="SMB port (default=445)")
    parser_smb.add_argument("--username", help="Username for SMB login (optional for enum)")
    parser_smb.add_argument("--password", help="Password for SMB login (optional for enum)")
    parser_smb.add_argument("--user-file", help="File with list of usernames (for spray)")
    parser_smb.add_argument("--pass-file", help="File with list of passwords (for spray)")
    parser_smb.add_argument("--log-file", default=None,
                            help="Path to log file (default: log to console)")
    parser_smb.add_argument("--log-level", default="INFO",
                            help="Logging level (DEBUG, INFO, WARNING, ERROR; default=INFO)")

    # ----------------- DNS SUB-COMMAND -----------------
    parser_dns = subparsers.add_parser("dns", help="Perform reverse DNS lookups")
    parser_dns.add_argument("--targets", required=True,
                            help="Comma-separated list of IP addresses, e.g. '8.8.8.8,8.8.4.4'")
    parser_dns.add_argument("--log-file", default=None,
                            help="Path to log file (default: log to console)")
    parser_dns.add_argument("--log-level", default="INFO",
                            help="Logging level (DEBUG, INFO, WARNING, ERROR; default=INFO)")

    # ----------------- LDAP SUB-COMMAND -----------------
    parser_ldap = subparsers.add_parser("ldap", help="Perform LDAP enumeration")
    parser_ldap.add_argument("--target", required=True, help="LDAP server IP address")
    parser_ldap.add_argument("--port", type=int, default=389, help="LDAP port (default=389)")
    parser_ldap.add_argument("--bind-dn", default="", help="Bind DN (optional, for authenticated bind)")
    parser_ldap.add_argument("--password", default="", help="Password (optional, for authenticated bind)")
    parser_ldap.add_argument("--search-base", default="", help="Search base DN (e.g. 'dc=example,dc=com')")
    parser_ldap.add_argument("--search-filter", default="(objectClass=*)",
                             help="LDAP search filter (default: (objectClass=*))")
    parser_ldap.add_argument("--log-file", default=None, help="Path to log file")
    parser_ldap.add_argument("--log-level", default="INFO", help="Logging level")

    # ----------------- RDP SUB-COMMAND -----------------
    parser_rdp = subparsers.add_parser("rdp", help="Perform RDP enumeration")
    parser_rdp.add_argument("--target", required=True, help="Target IP address for RDP")
    parser_rdp.add_argument("--port", type=int, default=3389, help="RDP port (default=3389)")
    parser_rdp.add_argument("--log-file", default=None, help="Path to log file")
    parser_rdp.add_argument("--log-level", default="INFO", help="Logging level")

    # ----------------- FTP SUB-COMMAND -----------------
    parser_ftp = subparsers.add_parser("ftp", help="Perform FTP enumeration")
    parser_ftp.add_argument("--target", required=True, help="Target IP address for FTP")
    parser_ftp.add_argument("--port", type=int, default=21, help="FTP port (default=21)")
    parser_ftp.add_argument("--username", default="anonymous",
                            help="Username for FTP login (default: anonymous)")
    parser_ftp.add_argument("--password", default="anonymous@",
                            help="Password for FTP login (default: anonymous@)")
    parser_ftp.add_argument("--log-file", default=None, help="Path to log file")
    parser_ftp.add_argument("--log-level", default="INFO", help="Logging level")

    # ----------------- SSH SUB-COMMAND -----------------
    parser_ssh = subparsers.add_parser("ssh", help="Perform SSH enumeration")
    parser_ssh.add_argument("--target", required=True, help="Target IP address for SSH")
    parser_ssh.add_argument("--port", type=int, default=22, help="SSH port (default=22)")
    parser_ssh.add_argument("--username", help="Username for SSH authentication (optional)")
    parser_ssh.add_argument("--password", help="Password for SSH authentication (optional)")
    parser_ssh.add_argument("--log-file", default=None, help="Path to log file")
    parser_ssh.add_argument("--log-level", default="INFO", help="Logging level")

    args = parser.parse_args()

    # Configure logging based on sub-command common options.
    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        print(f"Invalid log level: {args.log_level}")
        sys.exit(1)
    logging.basicConfig(level=numeric_level,
                        filename=args.log_file,
                        format="%(asctime)s [%(levelname)s] %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")

    # Dispatch sub-command handler.
    if args.command == "scan":
        main_scan(args)
    elif args.command == "smb":
        main_smb(args)
    elif args.command == "dns":
        main_dns(args)
    elif args.command == "ldap":
        main_ldap(args)
    elif args.command == "rdp":
        main_rdp(args)
    elif args.command == "ftp":
        main_ftp(args)
    elif args.command == "ssh":
        main_ssh(args)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user.")
    except Exception as e:
        logging.exception("An unexpected error occurred:")
        print(f"\n[!] An unexpected error occurred: {e}")
