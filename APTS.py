import argparse
from Nmap_scan import Nmap_main

def scan_command(args):
    exploitable_csv, non_exploitable_csv, complete_results_csv = Nmap_main(args.ip_address)
    if exploitable_csv:
        print("Exploitable Results:")
        print_csv(exploitable_csv)
    if non_exploitable_csv:
        print("Non-Exploitable Results:")
        print_csv(non_exploitable_csv)
    if complete_results_csv:
        print("Complete Results:")
        print_csv(complete_results_csv)

def open_command(args):
    try:
        with open(args.file_name, 'r') as file:
            print(file.read())
    except FileNotFoundError:
        print(f"File '{args.file_name}' not found.")
    except Exception as e:
        print(f"Error opening file: {e}")

def open_all_command(args):
    print("Exploitable Results:")
    print_csv('Exploitable.csv')
    print("Non-Exploitable Results:")
    print_csv('Non_Exploitable.csv')
    print("Complete Results:")
    print_csv('complete_results.csv')

def print_csv(file_name):
    try:
        with open(file_name, 'r') as file:
            print(file.read())
    except FileNotFoundError:
        print(f"File '{file_name}' not found.")
    except Exception as e:
        print(f"Error printing CSV file: {e}")

def main():
    parser = argparse.ArgumentParser(description='Nmap CLI')

    parser.add_argument('--Sc', '--Scan', dest='ip_address', help='IP address to scan')
    parser.add_argument('--O', '--Open', dest='file_name', choices=['Exploitable.csv', 'Non_Exploitable.csv', 'complete_results.csv'], help='Open a specific CSV file')
    parser.add_argument('--Oa', '--OpenAll', dest='OpenAll', action='store_true', help='Open all CSV files')

    args = parser.parse_args()

    if args.ip_address:
        scan_command(args)
    elif args.file_name:
        open_command(args)
    elif args.OpenAll:
        open_all_command(args)
    else:
        print("No arguments provided. Please provide an IP address to scan.")
        parser.print_help()

if __name__ == '__main__':
    main()
