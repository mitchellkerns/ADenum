import os
import pandas as pd
import argparse
from jinja2 import Template
from scripts.drone import Drone

def parse_nessus_csv(file_path):
    print("Parsing Nessus CSV file...")
    df = pd.read_csv(file_path)
    
    dns_servers = df[df['Name'].str.contains('DNS Server Detection', na=False)]['Host'].unique()
    kerberos_servers = df[df['Name'].str.contains('Kerberos Information Disclosure', na=False)]['Host'].unique()
    ldap_servers = df[df['Name'].str.contains('LDAP Server Detection', na=False)]['Host'].unique()
    smb_hosts = df[df['Port'] == 445]['Host'].unique()
    smb_not_signed_ips = df[df['Name'].str.contains('SMB Signing not required', na=False)]['Host'].unique()
    
    # Find hosts that have both port 445 and 443 open
    hosts_with_443 = df[df['Port'] == 443]['Host'].unique()
    hosts_with_445_and_443 = list(set(smb_hosts) & set(hosts_with_443)) 

    return dns_servers, kerberos_servers, ldap_servers, smb_hosts, smb_not_signed_ips, hosts_with_445_and_443


def save_smb_not_signed_ips(smb_not_signed_ips, output_dir):
    print("Saving SMB not signed IPs to file...")
    smb_not_signed_file = os.path.join(output_dir, "smb_not_signed.txt")
    with open(smb_not_signed_file, "w") as file:
        file.write("\n".join(smb_not_signed_ips))
    return smb_not_signed_file

def generate_html_report(dns_servers, kerberos_servers, ldap_servers, domains, domain_controllers, smb_not_signed_ips, output_file):
    template = """
    <html>
    <head>
        <title>AD Report</title>
        <style>
            body {
                background-color: #121212;
                color: #ffffff;
                font-family: Arial, sans-serif;
                font-size: 16px;
                line-height: 1.6;
                margin: 0;
                padding: 0;
            }
            .collapsible {
                background-color: #777;
                color: white;
                cursor: pointer;
                padding: 10px;
                width: 100%;
                border: none;
                text-align: left;
                outline: none;
                font-size: 15px;
            }

            .active, .collapsible:hover {
                background-color: #555;
            }

            .content {
                padding: 0 18px;
                display: none;
                overflow: hidden;
                background-color: #f1f1f1;
            }
        </style>
    </head>
    <body>
        <h1>Active Directory Initial Enumeration Report</h1>
        
        <h2>DNS Servers</h2>
        <ul>
        {% for server in dns_servers %}
            <li>{{ server }}</li>
        {% endfor %}
        </ul>
        
        <h2>Kerberos Servers</h2>
        <ul>
        {% for server in kerberos_servers %}
            <li>{{ server }}</li>
        {% endfor %}
        </ul>
        
        <h2>LDAP Servers</h2>
        <ul>
        {% for server in ldap_servers %}
            <li>{{ server }}</li>
        {% endfor %}
        </ul>

        <h2>Domains</h2>
        <ul>
        {% for domain in domains %}
            <li>{{ domain }}</li>
        {% endfor %}
        </ul>

        <h2>Domain Controllers</h2>
        <ul>
        {% for dc in domain_controllers %}
            <li>{{ dc }}</li>
        {% endfor %}
        </ul>

        <h2>SMB Signing Not Required</h2>
        <button class="collapsible">Show IPs</button>
        <div class="content">
            <ul>
            {% for ip in smb_not_signed_ips %}
                <li>{{ ip }}</li>
            {% endfor %}
            </ul>
        </div>

        <script>
            var coll = document.getElementsByClassName("collapsible");
            for (var i = 0; i < coll.length; i++) {
                coll[i].addEventListener("click", function() {
                    this.classList.toggle("active");
                    var content = this.nextElementSibling;
                    if (content.style.display === "block") {
                        content.style.display = "none";
                    } else {
                        content.style.display = "block";
                    }
                });
            }
        </script>
    </body>
    </html>
    """
    
    html_template = Template(template)
    html_content = html_template.render(
        dns_servers=dns_servers, 
        kerberos_servers=kerberos_servers, 
        ldap_servers=ldap_servers, 
        domains=domains,
        domain_controllers=domain_controllers,
        smb_not_signed_ips=smb_not_signed_ips
    )
    
    with open(output_file, 'w') as f:
        f.write(html_content)
    

def display_table(headers, rows, service_separators):
    """Helper function to display tables with properly adjusted separators."""
    # Calculate the width for each column based on the longest item in each column
    col_widths = [max(len(str(item)) for item in col) for col in zip(*([headers] + rows))]

    # Function to create a separator line with dashes based on column width
    def create_separator():
        return '+' + '+'.join(['-' * (width + 2) for width in col_widths]) + '+'

    # Function to format a row with borders
    def format_row(row):
        return '| ' + ' | '.join([f"{str(item).ljust(width)}" for item, width in zip(row, col_widths)]) + ' |'

    # Print the table
    print(create_separator())
    print(format_row(headers))
    print(create_separator())
    for i, row in enumerate(rows):
        print(format_row(row))
        # Add a separator if the current row index matches a service separator
        if service_separators and (i + 1 in service_separators):
            print(create_separator())

def display_output(dns_servers, domains, ad_infrastructure):
    print("\nDisplaying results...\n")

    # Display DNS Servers separately as they are not domain-specific
    if dns_servers.size > 0:
        display_table(['DNS Servers'], [[server] for server in dns_servers], service_separators=[])
    print()

    # Prepare the headers for the consolidated table (one for each domain)
    domain_headers = ['Service/Component'] + domains
    consolidated_rows = []
    service_separators = []

    for component, domain_results in ad_infrastructure.items():
        service_rows = []

        # Find unique entries for each domain and component to avoid duplicates
        unique_results = {domain: list(set(domain_results[domain])) for domain in domains}

        # Check if any domain has results for the current component
        has_results = any(unique_results[domain] for domain in domains)

        if has_results:
            # Find the maximum number of entries across all domains for this component
            max_entries = max(len(unique_results[domain]) for domain in domains)

            for i in range(max_entries):
                row = [component if i == 0 else '']  # Component name only for the first row

                for domain in domains:
                    if i < len(unique_results[domain]):
                        row.append(unique_results[domain][i])
                    else:
                        row.append('')  # Empty space if no more entries

                service_rows.append(row)
        else:
            # If no results were found for this component, mark as "N/A" only once
            service_rows.append([component] + ['N/A'] * len(domains))

        # Add the service rows to the final result
        consolidated_rows.extend(service_rows)

        # Mark where the divider should go
        service_separators.append(len(consolidated_rows))  # Adds a separator after each service/component

    # Display the consolidated table for all components across all domains
    display_table(domain_headers, consolidated_rows, service_separators)
    print()



def enumerate_domains(drone, smb_hosts):
    print("Enumerating domains...")
    remote_file_path = "/tmp/smb-ips.txt"
    with open("smb-ips.txt", "w") as file:
        file.write("\n".join(smb_hosts))
    
    drone.upload("smb-ips.txt")
    os.remove("smb-ips.txt")
    
    cmd = (
        #f"~/.local/bin/netexec smb {remote_file_path} | "
        f"netexec smb {remote_file_path} | "
        f"awk -F'[() ]' '{{name=\"\"; domain=\"\"; for (i=1; i<=NF; i++) {{if ($i ~ /^name:/) name=substr($i,6); if ($i ~ /^domain:/) domain=substr($i,8);}} if (name != domain) print domain;}}' | "
        "sort | uniq"
    )
    output = drone.execute(cmd)
    domains = output.strip().splitlines()
    
    # Delete the tmp file after processing
    drone.execute("rm -f /tmp/smb-ips.txt")
    
    return domains

def query_dns_for_domain_controllers(drone, dns_servers, domains):
    print("Querying DNS for domain controllers...")
    domain_controllers = []

    for dns_server in dns_servers:
        for domain in domains:
            query = f"dig @{dns_server} _ldap._tcp.dc._msdcs.{domain} SRV"
            dig_output = drone.execute(query)

            lines = dig_output.splitlines()
            
            additional_section_found = False
            
            for line in lines:
                if ";; ADDITIONAL SECTION:" in line:
                    additional_section_found = True
                    continue
                
                if additional_section_found:
                    parts = line.split()
                    if len(parts) >= 5 and "IN" in parts and "A" in parts:
                        hostname = parts[0].strip('.')
                        ip_address = parts[-1]
                        domain_controllers.append(f"{hostname} {ip_address}")
                        
                    additional_section_found = False

    return domain_controllers


def query_dns_for_ad_infrastructure(drone, dns_servers, domains):
    print("Querying DNS for AD infrastructure components...")
    
    # Add new AD-related DNS queries
    infrastructure = {
        "Domain Controllers": "_ldap._tcp.dc._msdcs.",
        "Global Catalog Servers": "_gc._tcp.",
        "Kerberos Servers": "_kerberos._tcp.dc._msdcs.",
        "AD Lightweight Directory Services": "_ldap._tcp.",
        "AD Rights Management Services": "_rms._tcp.",
        "Certificate Authorities": "_vlmcs._tcp.",
        "SQL Servers": "_mssql._tcp.",
        "Management Point (SCCM)": "_mps._tcp.",
        "Distribution Point (SCCM)": "_msdp._tcp.",
        "Web Server (IIS)": "_http._tcp.",
        "Windows Server Update Services": "_wsus._tcp.",
        "File Replication Service (FRS)": "_ldap._tcp.pdc._msdcs.",
        "File and Storage Services": "_file._tcp.",
        "Host Guardian Service": "_hgs._tcp.",
        "Hyper-V": "_hyperv._tcp.",
        "Print and Document Services": "_print._tcp.",
        "Remote Access": "_remote._tcp.",
        "PDC Emulator (FRS)": "_ldap._tcp.pdc._msdcs.",
        "Remote Desktop Services": "_rdp._tcp.",
        "Volume Activation Services": "_vlmcs._tcp.",
        "Device Health Attestation": "_dha._tcp.",
        "DHCP Servers": "_dhcp._udp."
    }

    results = {component: {domain: [] for domain in domains} for component in infrastructure}

    for component, srv_query in infrastructure.items():
        for dns_server in dns_servers:
            for domain in domains:
                query = f"dig @{dns_server} {srv_query}{domain} SRV"
                dig_output = drone.execute(query)
                lines = dig_output.splitlines()

                additional_section_found = False
                current_hostnames = []
                current_ips = []

                for line in lines:
                    if ";; ADDITIONAL SECTION:" in line:
                        additional_section_found = True
                        continue

                    if additional_section_found:
                        parts = line.split()
                        if len(parts) >= 5 and "IN" in parts and "A" in parts:
                            hostname = parts[0].strip('.')
                            ip_address = parts[-1]
                            current_hostnames.append(hostname)
                            current_ips.append(ip_address)
                
                # Combine hostname and IPs in the format "IP / Hostname"
                combined_results = [f"{ip} / {hostname}" for ip, hostname in zip(current_ips, current_hostnames)]
                
                # Ensure there is something to add
                if combined_results:
                    results[component][domain].extend(combined_results)

    return results

def main():
    parser = argparse.ArgumentParser(description="Analyze Nessus CSV and enumerate basic info on Active Directory.")
    parser.add_argument("csv_file", help="Path to the Nessus CSV file.")
    parser.add_argument("--html", help="Generate HTML report.", action="store_true")
    parser.add_argument("--hostname", help="Hostname or IP address of the remote system.")
    parser.add_argument("--username", help="Username for SSH connection.")
    parser.add_argument("--password", help="Password for SSH connection.")
    
    args = parser.parse_args()

    print("Starting analysis...")

    output_dir = os.path.dirname(args.csv_file)
    
    dns_servers, kerberos_servers, ldap_servers, smb_hosts, smb_not_signed_ips, hosts_with_445_and_443 = parse_nessus_csv(args.csv_file)
    
    domains = []
    ad_infrastructure = {}

    if args.hostname and args.username and args.password:
        drone = Drone(args.hostname, args.username, args.password)
        domains = enumerate_domains(drone, smb_hosts)
        
        # Query for AD infrastructure (Domain Controllers, ADCS, SQL, SCCM, etc.)
        ad_infrastructure = query_dns_for_ad_infrastructure(drone, dns_servers, domains)
    
    # Display the output in table format
    display_output(dns_servers, domains, ad_infrastructure)
    
    if args.html:
        output_file = os.path.join(output_dir, "AD_Report.html")
        generate_html_report(dns_servers, kerberos_servers, ldap_servers, domains, [], smb_not_signed_ips, output_file)
        print(f"HTML report generated: {output_file}")

    smb_not_signed_file = save_smb_not_signed_ips(smb_not_signed_ips, output_dir)
    print(f"Hosts with SMB signing not enabled saved to: {smb_not_signed_file}")


if __name__ == "__main__":
    main()
