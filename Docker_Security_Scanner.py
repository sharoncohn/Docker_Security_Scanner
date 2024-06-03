import docker
import os
import json
import subprocess
import argparse
import logging as log
import zipfile
import sys

CURRENT_DIR = os.path.dirname(__file__)
OUTPUT_DIR = os.path.join(CURRENT_DIR, "container_assessment_results_new")
TRIVY_DIR = os.path.join(CURRENT_DIR, "trivy")
TRIVY_ZIP = "trivy_0.51.4_Windows-64bit.zip"

def assessment_check_attributes(container):

    try:
        findings = []
        hostname = container.attrs['Config']['Hostname']
        username = container.attrs['Config']['User']
        attrs_data = container.attrs

        if container.attrs['State']['Status'] != 'running':
            findings.append(f" [X] Container {hostname} is not running, consider having regular cleanup.")
        else:
            findings.append(f" [V] Container {hostname} is running.")
            
        # Check on which user the container is running
        if username == '' or username == '0':
            findings.append(f" [X] Container {hostname} is running as root.")
            
        else:
            findings.append(f" [V] Container {hostname} is running as user {username}.")

        # Check if the container is running in a privileged state
        if container.attrs['HostConfig']['Privileged']:
            findings.append(f" [X] Container {hostname} is running in privileged mode.")
            
        else:
            findings.append(f" [V] Container {hostname} is not running in privileged mode.")

        # Check if the container has memory and cpu limits
        memory_limit = container.attrs['HostConfig']['Memory']
        cpu_shares = container.attrs['HostConfig']['CpuShares']
        
        if memory_limit == 0 or cpu_shares == 0:
            findings.append(f" [X] Container {hostname} does not have resource limit.")
            
        else:
            findings.append(f" [V] Container {hostname} has resource limit set: Memory {memory_limit}, CPU {cpu_shares}.")
            
        # Check if the users's container has read-only permissions on the docker file system
        if not container.attrs['HostConfig']['ReadonlyRootfs']:
            findings.append(f" [X] Container {hostname} does not have a read-only file system.")
            
        else:
            findings.append(f" [V] Container {hostname} has a read-only file system.")

        # Check container open ports
        try:
            exposed_ports = list(container.attrs['Config']['ExposedPorts'].keys())
            findings.append(f" [X] Container {hostname} has these open ports {exposed_ports}")

        except:
            findings.append(f" [V] Container {hostname} has no open ports.")

        # Check for mounted volumes
        volumes = container.attrs['HostConfig']['Binds']
        if volumes:
            findings.append(f" [X] Container {hostname} has mounted volumes: {volumes}, check for sensitive information")
        else:
            findings.append(f" [V] Container {hostname} has no mounted volumes.")
            
        return attrs_data, findings
    
    except Exception as e:
        log.error(f"[-] Could not parse the data - {e}")

def scan_image(image_name):

    vulnerability_scan = []
    data = []
    trivy_file = extract_Trivy()

    if not trivy_file:
        return 0
    
    result = subprocess.run([trivy_file, 'image', '--format', 'json', image_name], capture_output=True, text=True, encoding='utf-8')

    if result:
        vulnerabilities = json.loads(result.stdout)
        
        if vulnerabilities['Results']:

            for result in vulnerabilities['Results']:

                if result['Vulnerabilities']:

                    for vulnerability in result['Vulnerabilities']:

                        if vulnerability['VulnerabilityID'] not in data:
                            data.append(vulnerability['VulnerabilityID'])
                            
                            try:
                                vulnerability_scan.append(f" [X] {vulnerability['VulnerabilityID']}: \n\tSeverity - {vulnerability['Severity']}. \n\tDescription - {vulnerability['Title']}\n")

                            except:  
                                vulnerability_scan.append(f" [X] {vulnerability['VulnerabilityID']}: \n\tSeverity - {vulnerability['Severity']}.\n\tDescription - {vulnerability['Description']}\n")
                
        else:
            log.error("Error finding vulnerabilities {image_name}: {result.stderr}")    
            
    else:
        log.error(f"Error scanning image {image_name}: {result.stderr}")

    return vulnerability_scan

def get_container_logs(container):
        
    logs = container.logs().decode("utf-8")
    return logs

def extract_Trivy():

    zip_file_path = os.path.join(CURRENT_DIR, TRIVY_ZIP)
    trivy_file = os.path.join(TRIVY_DIR, "trivy.exe")

    if not os.path.isfile(zip_file_path):
        
        if os.path.isfile(trivy_file):
            return trivy_file
        
        else:
            return None
            
    os.makedirs(TRIVY_DIR, exist_ok=True)

    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(TRIVY_DIR)
    
    return os.path.join(TRIVY_DIR, "trivy.exe")


def export_data(data, path):

    with open (path, 'a', encoding='utf-8') as file:
        file.write(''.join([f"{str(item)}\n" for item in data]) if isinstance(data, list) else str(data))


def main(args):
    
    client = None 
    log.info("Connecting to Docker...")

    try:
        client = docker.from_env()
        log.info("Successfuly connected to Docker")

    except:
        log.error("Cannot conect to docker, please open your Docker and try again")
        sys.exit()
        
    docker_containers = client.containers.list(all = True)
    if docker_containers:

        log.info("Found containers in Docker")
        for container in docker_containers:

            if args.output:
                OUTPUT_DIR = args.output

            log.info(f"Analyzing {container.name}")
            folder_path = os.path.join(OUTPUT_DIR, container.short_id)

            if not os.path.exists(folder_path):
                os.makedirs(folder_path)

            output_assessment_path = os.path.join(folder_path, f"report_{container.short_id}.txt")
            if args.assessment:
                
                log.info("Starting running the security assessment")
                attributes_path = os.path.join(folder_path, f"attrs_{container.short_id}.txt")
                attrs_data, findings = assessment_check_attributes(container)

                with open(output_assessment_path, 'w') as output_assessment_file:
                    output_assessment_file.write(f"Security Assessment for Container: {container.short_id} | {container.name} \n")
                    output_assessment_file.write(f"Docker Image: {container.image} \n")

                export_data(findings, output_assessment_path)
                export_data(attrs_data, attributes_path)
                log.info(f"Assessment completed for container {container.name}. Findings written to {output_assessment_path}")
            
            if args.logs:
                logs = get_container_logs(container)
                output_log_path = os.path.join(folder_path, f"log_{container.short_id}.txt")
                export_data(logs, output_log_path)
                log.info("Successfuly exported the logs to file")
            
            if args.scan_image:
                log.info("Starting scanning the images for security vulnerabilities")
                image_name = container.image.tags[0] if container.image.tags else None

                if image_name:
                    vulnerability_scan = scan_image(image_name)
                    vul_scan = export_data(vulnerability_scan, output_assessment_path)
                    if vul_scan == 0:
                        log.error("No Trivy file/zip was found")
                        sys.exit()
                    log.info(f"Successfuly scan the image - {container.name}")
                
                else:
                    log.info("No images were found in Docker")

        else:
            log.info(f"Container {container.name} does not have a tagged image.")
            

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Docker Container Security Assessment')
    parser.add_argument('-v', '--verbose', dest='verbose', default=None, action='store_true')
    parser.add_argument('--output', type=str, default=OUTPUT_DIR, help='Directory to save assessment results, if not provided the output will be exported to this python file location')
    parser.add_argument('--scan_image', action='store_true', default=None, help= "Scan every image in Docker with Trivy")
    parser.add_argument('--assessment', action='store_true', default=None, help = "Scan for security misconfiguration in Docker containers, Notice - This function would download Trivy from https://github.com/aquasecurity/trivy")
    parser.add_argument('--logs', action='store_true', default=None, help = "Export log files from the containers")
    parser.add_argument('--all', action='store_true', default=None, help = "Run all three functions - logs, assessment and scan_image")
    args = parser.parse_args()

    if args.all:
        args.assessment = True
        args.logs = True
        args.scan_image = True

    if (args.verbose or args.output) and not (args.all or args.scan_image or args.assessment or args.logs) or not any(vars(args).values()):
        parser.print_help()
        print("\nError: No arguments provided.")
        sys.exit(1)

    if not os.path.isdir(args.output):
        print(f"Error: The specified path {args.output} is not a directory.")
        sys.exit(1)

    if args.verbose:
        log.basicConfig(format="%(levelname)s: %(message)s", level=log.INFO)
        log.info("Verbose output.")

    else:
        log.basicConfig(format="%(levelname)s: %(message)s")
    
    main(args)