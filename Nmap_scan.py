import os
import subprocess
import csv
from libnmap.parser import NmapParser
from rich.console import Console

console = Console()

def execute_nmap_scan(target):
    """
    Execute an Nmap scan with the vulners script enabled.
    
    Args:
    - target: IP address or hostname of the target system
    
    Returns:
    - xml_file: Path to the XML file containing the Nmap scan results
    """
    console.print("[bold green]-> Executing Nmap scan...[/bold green]🔍")
    print('\n')
    console.print('[green]********************************************** Nmap Scan Results ********************************************[/green]')
    print('\n')
    xml_file = "scan_results.xml"
    command = f"nmap -sV --script=vulners -oX {xml_file} {target}"
    try:
        subprocess.run(command, shell=True, check=True)
        print('\n')
        console.print('[green]*******************************************************************************************************************[/green]')
        print('\n')
        console.print("[green]-> Nmap scan completed successfully.[/green] ")
        return xml_file
    except subprocess.CalledProcessError as e:
        console.print("[red]-> Error ❌  executing Nmap scan:[/red] [i]{}[/i]".format(e))
        return None

def parse_nmap_scan_results(xml_file):
    """
    Parse the raw Nmap scan results in XML format using libnmap.
    
    Args:
    - xml_file: Path to the XML file containing the Nmap scan results
    
    Returns:
    - parsed_results: Dictionary containing parsed scan results
    """
    console.print("[green]-> Parsing Nmap scan results... [/green]🕵️‍♂️")
    parsed_results = {}
        
    try:
        if os.path.exists(xml_file):  # Check if the XML file exists
            nmap_report = NmapParser.parse_fromfile(xml_file)
            for host in nmap_report.hosts:
                ip_address = host.address
                ports = []
                for service in host.services:
                    port_number = service.port
                    service_name = service.service
                    service_version = service.banner
                    vulnerabilities = []
                    for script in service.scripts_results:
                        if script.get('id') == 'vulners':
                            output = script.get('output')
                            # Extract vulnerabilities from the output
                            vulnerabilities.extend(parse_vulnerabilities(output))
                    ports.append({
                        'port': port_number,
                        'service': service_name,
                        'version': service_version,
                        'vulnerabilities': vulnerabilities
                    })
                parsed_results[ip_address] = ports
            console.print("[green]-> Nmap scan results parsed successfully.[/green] 👍")
            return parsed_results
        else:
            console.print(f"[red]-> Error:[i] {xml_file} not found[i].[/red] ❌ ")
            return None
    except Exception as e:
        console.print(f"[red]-> Error ❌  parsing Nmap scan results: [/red][i{e}[/i]")
        return None

def parse_vulnerabilities(output):
    """
    Parse the vulnerabilities from the Nmap vulners script output.
    
    Args:
    - output: Output string containing vulnerabilities
    
    Returns:
    - vulnerabilities: List of dictionaries containing vulnerabilities
    """
    vulnerabilities = []
    lines = output.split('\n')
    for line in lines:
        if "*EXPLOIT*" in line:  # Check if exploit keyword is present
            parts = line.strip().split('\t')
            if len(parts) >= 4:
                vulnerabilities.append({
                    'Vulnerability ID': parts[0],
                    'Severity Score': parts[1],
                    'Keyword': parts[3]  # Use the description as keyword
                })
    return vulnerabilities

def save_scan_results_to_csv(parsed_results, exploitable_csv_file, non_exploitable_csv_file):
    """
    Save the parsed scan results to CSV files.
    
    Args:
    - parsed_results: Dictionary containing parsed scan results
    - exploitable_csv_file: Path to the CSV file to save exploitable results
    - non_exploitable_csv_file: Path to the CSV file to save non-exploitable results
    
    Returns:
    - Tuple containing paths of the saved CSV files
    """
    
    console.print("[green]-> Saving scan results to CSV...[/green] ")
    try:
        exploitable_fieldnames = ['IP Address', 'Port', 'Service', 'Version', 'Vulnerability IDs']
        non_exploitable_fieldnames = ['IP Address', 'Port', 'Service', 'Version', 'Vulnerability IDs']

        with open(exploitable_csv_file, mode='w', newline='') as exploitable_csvfile, \
                open(non_exploitable_csv_file, mode='w', newline='') as non_exploitable_csvfile:

            exploitable_writer = csv.DictWriter(exploitable_csvfile, fieldnames=exploitable_fieldnames)
            non_exploitable_writer = csv.DictWriter(non_exploitable_csvfile, fieldnames=non_exploitable_fieldnames)

            exploitable_writer.writeheader()
            non_exploitable_writer.writeheader()

            for ip_address, ports in parsed_results.items():
                for port_info in ports:
                    exploitable_vulns = []
                    non_exploitable_vulns = []
                    for vuln in port_info['vulnerabilities']:
                        if "*EXPLOIT*" in vuln['Keyword']:
                            exploitable_vulns.append(vuln['Vulnerability ID'])
                        non_exploitable_vulns.append(vuln['Vulnerability ID'])  # Include all vulnerability IDs


                    exploitable_writer.writerow({
                        'IP Address': ip_address,
                        'Port': port_info['port'],
                        'Service': port_info['service'],
                        'Version': port_info['version'],
                        'Vulnerability IDs': ','.join(exploitable_vulns)
                    })

                    if non_exploitable_vulns:  
                     	non_exploitable_writer.writerow({
                            'IP Address': ip_address,
                            'Port': port_info['port'],
                            'Service': port_info['service'],
                            'Version': port_info['version'],
                            'Vulnerability IDs': ','.join(non_exploitable_vulns)
                        })

        console.print(f"[green]-> Scan results saved to {exploitable_csv_file} and {non_exploitable_csv_file}[/green] 👍")
        return exploitable_csv_file, non_exploitable_csv_file
    except Exception as e:
        console.print(f"❌[red]-> Error saving scan results to CSV:[red][i] {e}[/i]")
        return None, None

def save_complete_results_to_csv(xml_file, complete_csv_file):
    """
    Save the output from Nmap scan scripts to a CSV file.
    
    Args:
    - xml_file: Path to the XML file containing the Nmap scan results
    - complete_csv_file: Path to the CSV file to save the output
    
    Returns:
    - Path of the saved CSV file
    """
    console.print(f"[green]-> Saving output to CSV...[/green]")
    try:
        with open(complete_csv_file, mode='w', newline='') as csv_file:
            writer = csv.writer(csv_file)
            p = NmapParser.parse_fromfile(xml_file)
            for host in p.hosts:
                for svc in host.services:
                    for script in svc.scripts_results:
                        output = script.get("output")
                        writer.writerow([output])

        console.print(f"[green]-> Output saved to {complete_csv_file}[/green]👍")
        return complete_csv_file
    except Exception as e:
        console.print(f"❌ [red]-> Error saving output to CSV: [red][i]{e}[/i]")
        return None

def Nmap_main(target):
    # Execute Nmap scan
    xml_file = execute_nmap_scan(target)

    # Check if Nmap scan was successful
    if xml_file:
        # Parse Nmap scan results from XML file
        parsed_results = parse_nmap_scan_results(xml_file)
        
        # Save parsed scan results to CSV files
        if parsed_results:
            exploitable_csv_file = 'Exploitable.csv'
            non_exploitable_csv_file = 'Non_Exploitable.csv'
            complete_csv_file = 'complete_results.csv'
            save_scan_results_to_csv(parsed_results, exploitable_csv_file, non_exploitable_csv_file)
            save_complete_results_to_csv(xml_file, complete_csv_file)
            return exploitable_csv_file, non_exploitable_csv_file, complete_csv_file
    else:
        console.print("❌ [red]-> Nmap scan failed. Please check your input and try again.[red]")
        return None, None, None

if __name__ == "__main__":
    Nmap_main()
