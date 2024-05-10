import argparse
import csv
from rich.table import Table
from rich.console import Console
from Nmap_scan import Nmap_main
from rich.theme import Theme

console = Console()


def print_ascii_art():
    ascii_art = """
                                                                                               
                                                                                               
               AAA               PPPPPPPPPPPPPPPPP   TTTTTTTTTTTTTTTTTTTTTTT   SSSSSSSSSSSSSSS 
              A:::A              P::::::::::::::::P  T:::::::::::::::::::::T SS:::::::::::::::S
             A:::::A             P::::::PPPPPP:::::P T:::::::::::::::::::::TS:::::SSSSSS::::::S
            A:::::::A            PP:::::P     P:::::PT:::::TT:::::::TT:::::TS:::::S     SSSSSSS
           A:::::::::A             P::::P     P:::::PTTTTTT  T:::::T  TTTTTTS:::::S            
          A:::::A:::::A            P::::P     P:::::P        T:::::T        S:::::S            
         A:::::A A:::::A           P::::PPPPPP:::::P         T:::::T         S::::SSSS         
        A:::::A   A:::::A          P:::::::::::::PP          T:::::T          SS::::::SSSSS    
       A:::::A     A:::::A         P::::PPPPPPPPP            T:::::T            SSS::::::::SS  
      A:::::AAAAAAAAA:::::A        P::::P                    T:::::T               SSSSSS::::S 
     A:::::::::::::::::::::A       P::::P                    T:::::T                    S:::::S
    A:::::AAAAAAAAAAAAA:::::A      P::::P                    T:::::T                    S:::::S
   A:::::A             A:::::A   PP::::::PP                TT:::::::TT      SSSSSSS     S:::::S
  A:::::A               A:::::A  P::::::::P                T:::::::::T      S::::::SSSSSS:::::S
 A:::::A                 A:::::A P::::::::P                T:::::::::T      S:::::::::::::::SS 
AAAAAAA                   AAAAAAAPPPPPPPPPP                TTTTTTTTTTT       SSSSSSSSSSSSSSS                                                                    
                               
"""
    print(ascii_art)
    console.rule()
    print("\n")


def scan_command(args):
    exploitable_csv, non_exploitable_csv, complete_results_csv = Nmap_main(args.ip_address)
    

# Define a custom theme with colors and styles
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "highlight": "bold magenta",
    "title": "bold blue",
    "table.header": "bold white on blue",
    "table.odd_row": "white",
    "table.even_row": "cyan",
})

# Create a console with the custom theme
console = Console(theme=custom_theme)

def print_csv_as_table(file_name):
    try:
        with open(file_name, 'r') as file:
            csv_reader = csv.DictReader(file)
            table = Table(title=f"[bold green]Results from {file_name}[/bold green]", show_header=True, header_style="table.header")

            # Add columns to the table
            table.add_column("IP Address", style="white")
            table.add_column("Port", style="white")
            table.add_column("Service", style="white")
            table.add_column("Version", style="white")
            table.add_column("Vulnerability IDs", style="white")

            # Add rows to the table
            for index, row in enumerate(csv_reader):
                style = "highlight" if index % 2 == 0 else "info"  # Alternate row styles
                table.add_row(
                    row["IP Address"],
                    row["Port"],
                    row["Service"],
                    row["Version"],
                    row["Vulnerability IDs"],
                    style=style
                )

            console.print(table)
    except FileNotFoundError:
        console.print(f"[error]File '{file_name}' not found.[/error]")
    except Exception as e:
        console.print(f"[error]Error opening file: {e}[/error]")


def open_command(args):
    if (args.file_name == 'Exploitable.csv' or args.file_name == 'Non_Exploitable.csv' ):
        print_csv_as_table(args.file_name)
    elif args.file_name == 'complete_results.csv':
        print_csv(args.file_name)
    else:
        console.print(f"[error]Invalid file name '{args.file_name}'.[/error]")
        console.print("[info]Please provide a valid file name: 'Exploitable.csv', 'Non_Exploitable.csv', or 'complete_results.csv'[/info]")


def open_all_command(args):
    print_csv_as_table('Exploitable.csv')
    console.rule()
    print("\n")
    print_csv_as_table('Non_Exploitable.csv')
    console.rule()
    print("\n")
    console.print("[bold magenta]Complete results[/bold magenta]")
    print_csv('complete_results.csv')

def print_csv(file_name):
    try:
        with open(file_name, 'r') as file:
            console.print(file.read())
    except FileNotFoundError:
        console.print(f"\n[bold red]File '{file_name}' not found.[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]Error printing CSV file: {e}[/bold red]")

def main():
    parser = argparse.ArgumentParser(description='Nmap CLI')
    parser.add_argument('--Sc', '--Scan', dest='ip_address', help='IP address to scan')
    parser.add_argument('--O', '--Open', dest='file_name', choices=['Exploitable.csv', 'Non_Exploitable.csv', 'complete_results.csv'], help='Open a report file [.csv]')
    parser.add_argument('--Oa', '--OpenAll', dest='OpenAll', action='store_true', help='Open all CSV files')

    args = parser.parse_args()

    if args.ip_address:   
        scan_command(args)
        console.rule()
        print("\n")
    if args.file_name:
        open_command(args)
        console.rule()
        print("\n")
    if args.OpenAll:
        open_all_command(args)
        console.rule()
        print("\n")
    if not args.ip_address and not args.file_name and not args.OpenAll:
        console.print("[bold red]No arguments provided. [/bold red]")
        parser.print_help()

   

if __name__ == '__main__':
    print_ascii_art()
    main()
