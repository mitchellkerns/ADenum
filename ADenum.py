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
    
    return dns_servers, kerberos_servers, ldap_servers, smb_hosts, smb_not_signed_ips

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
    
def display_output(dns_servers, kerberos_servers, ldap_servers, domains, domain_controllers):
    print("\nDisplaying results...")
    print("\nDNS Servers:")
    for server in dns_servers:
        print(f" - {server}")
    
    print("\nKerberos Servers:")
    for server in kerberos_servers:
        print(f" - {server}")
    
    print("\nLDAP Servers:")
    for server in ldap_servers:
        print(f" - {server}")

    print("\nDomains:")
    for domain in domains:
        print(f" - {domain}")
    
    print("\nDomain Controllers:")
    for dc in domain_controllers:
        print(f" - {dc}")
    
    print()

def enumerate_domains(drone, smb_hosts):
    print("Enumerating domains using crackmapexec...")
    remote_file_path = "/tmp/smb-ips.txt"
    with open("smb-ips.txt", "w") as file:
        file.write("\n".join(smb_hosts))
    
    drone.upload("smb-ips.txt")
    os.remove("smb-ips.txt")
    
    cmd = (
        f"crackmapexec smb {remote_file_path} | "
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
                        domain_controllers.append(f"{hostname}     {ip_address}")
                        
                    additional_section_found = False

    return domain_controllers

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
    
    dns_servers, kerberos_servers, ldap_servers, smb_hosts, smb_not_signed_ips = parse_nessus_csv(args.csv_file)
    
    domains = []
    domain_controllers = []
    if args.hostname and args.username and args.password:
        drone = Drone(args.hostname, args.username, args.password)
        domains = enumerate_domains(drone, smb_hosts)
        domain_controllers = query_dns_for_domain_controllers(drone, dns_servers, domains)
    
    display_output(dns_servers, kerberos_servers, ldap_servers, domains, domain_controllers)
    
    if args.html:
        output_file = os.path.join(output_dir, "AD_Report.html")
        generate_html_report(dns_servers, kerberos_servers, ldap_servers, domains, domain_controllers, smb_not_signed_ips, output_file)
        print(f"HTML report generated: {output_file}")

    smb_not_signed_file = save_smb_not_signed_ips(smb_not_signed_ips, output_dir)
    print(f"Hosts with SMB signing not enabled saved to: {smb_not_signed_file}")

if __name__ == "__main__":
    main()
