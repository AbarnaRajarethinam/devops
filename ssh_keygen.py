#!/usr/bin/env python3
"""
Python-based SSH key generator - Alternative to ssh-keygen command
Generates RSA, ECDSA, or Ed25519 SSH key pairs
"""

import os
import sys
import argparse
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
import base64
import hashlib

def generate_rsa_key(key_size=2048):
    """Generate RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    return private_key

def generate_ecdsa_key(curve_name='secp256r1'):
    """Generate ECDSA key pair"""
    curves = {
        'secp256r1': ec.SECP256R1(),
        'secp384r1': ec.SECP384R1(),
        'secp521r1': ec.SECP521R1(),
    }
    curve = curves.get(curve_name, ec.SECP256R1())
    private_key = ec.generate_private_key(curve)
    return private_key

def generate_ed25519_key():
    """Generate Ed25519 key pair"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key

def format_openssh_public_key(public_key, key_type, comment=""):
    """Format public key in OpenSSH format"""
    public_key_obj = public_key.public_key()
    
    # Use OpenSSH format for public key
    openssh_public_key = public_key_obj.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    
    # Add comment if provided
    if comment:
        openssh_public_key = openssh_public_key.decode('utf-8').strip() + f" {comment}"
        return openssh_public_key.encode('utf-8')
    
    return openssh_public_key

def format_private_key(private_key, password=None):
    """Format private key in OpenSSH format"""
    encryption_algorithm = serialization.NoEncryption()
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
    
    # Use OpenSSH format for private key with PEM encoding
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=encryption_algorithm
    )
    return private_bytes

def generate_ssh_key(key_type='rsa', key_size=2048, output_file='id_rsa', comment="", password=None):
    """Generate SSH key pair and save to files"""
    
    # Generate key pair based on type
    if key_type == 'rsa':
        private_key = generate_rsa_key(key_size)
        key_algorithm = 'rsa'
    elif key_type == 'ecdsa':
        private_key = generate_ecdsa_key()
        key_algorithm = 'ecdsa'
    elif key_type == 'ed25519':
        private_key = generate_ed25519_key()
        key_algorithm = 'ed25519'
    else:
        raise ValueError(f"Unsupported key type: {key_type}")
    
    # Format keys
    private_key_data = format_private_key(private_key, password)
    public_key_data = format_openssh_public_key(private_key, key_algorithm, comment)
    
    # Write private key
    with open(output_file, 'wb') as f:
        f.write(private_key_data)
    os.chmod(output_file, 0o600)  # Set secure permissions
    
    # Write public key
    public_key_file = f"{output_file}.pub"
    with open(public_key_file, 'wb') as f:
        f.write(public_key_data)
    os.chmod(public_key_file, 0o644)
    
    return output_file, public_key_file

def main():
    parser = argparse.ArgumentParser(description='Generate SSH key pairs (alternative to ssh-keygen)')
    parser.add_argument('-t', '--type', choices=['rsa', 'ecdsa', 'ed25519'], 
                       default='rsa', help='Key type (default: rsa)')
    parser.add_argument('-b', '--bits', type=int, default=2048,
                       help='Key size in bits (for RSA keys, default: 2048)')
    parser.add_argument('-f', '--file', default='id_rsa',
                       help='Output file name (default: id_rsa)')
    parser.add_argument('-C', '--comment', default='',
                       help='Comment for the key')
    parser.add_argument('-N', '--passphrase', default=None,
                       help='Passphrase for the private key')
    parser.add_argument('--show-fingerprint', action='store_true',
                       help='Show key fingerprint after generation')
    
    args = parser.parse_args()
    
    try:
        # Check if files already exist
        if os.path.exists(args.file) or os.path.exists(f"{args.file}.pub"):
            response = input(f"Files {args.file} or {args.file}.pub already exist. Overwrite? (y/N): ")
            if response.lower() != 'y':
                print("Key generation cancelled.")
                return
        
        print(f"Generating {args.type.upper()} key pair...")
        
        private_file, public_file = generate_ssh_key(
            key_type=args.type,
            key_size=args.bits,
            output_file=args.file,
            comment=args.comment,
            password=args.passphrase
        )
        
        print(f"Your identification has been saved in {private_file}")
        print(f"Your public key has been saved in {public_file}")
        
        # Show fingerprint if requested
        if args.show_fingerprint:
            with open(public_file, 'r') as f:
                public_key_content = f.read().strip()
            
            # Extract the key part (between the algorithm and comment)
            parts = public_key_content.split()
            if len(parts) >= 2:
                key_data = parts[1]
                # Calculate SHA256 fingerprint
                key_bytes = base64.b64decode(key_data)
                fingerprint = hashlib.sha256(key_bytes).digest()
                fingerprint_b64 = base64.b64encode(fingerprint).decode().rstrip('=')
                print(f"The key fingerprint is:")
                print(f"SHA256:{fingerprint_b64}")
        
    except Exception as e:
        print(f"Error generating key: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
