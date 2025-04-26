#Libraries
import argparse
from ssh_honeypot import *

#Parse Arguments

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--address', type=str, required=True)
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-u', '--username', type=str)
    parser.add_argument('-pw', '--password', type=str)
    parser.add_argument('--creds', type=str, help='Path to file with username:password list')

    parser.add_argument('-s', '--ssh', action="store_true")
    parser.add_argument('-w', '--http', action="store_true")

    args = parser.parse_args()

    creds_dict = {}
    if args.creds:
        with open(args.creds, 'r') as f:
            for line in f:
                if ':' in line:
                    user, pw = line.strip().split(':', 1)
                    creds_dict[user] = pw

    try:
        if args.ssh:          
            print('[-] Running SSH Honeypot...')
            honey_pot(args.address, args.port, args.username, args.password, creds_dict)

            if not args.username:
                username = None
            if not args.password:
                password = None

        elif args.http:
            print('[-] Running HTTP WordPress Honeypot...')
            pass
        else:
            print('[!] Choose  a honeypot type (SSH) or (HTTP).')
    except Exception as e: 
        print(f"\n Existing honeypot!!! {e}")
