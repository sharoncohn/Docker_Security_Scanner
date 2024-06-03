# Docker Security Scanner

A security configuration scanner for Docker containers.

## Features:
- Container configuration file security scanner, like open ports, running in privilege mode, root user configured and more.
- Dump log file of each container.
- Scan container images for security vulnerabilities using `Trivy` ([Trivy Repository](https://github.com/aquasecurity/trivy/tree/main)).

## Usage:
``` docker_scanner.py --all --verbose ```

## Note:
- Docker client needs to be started in order to connect the python script.
- Trivy Windows zip is included in the repository, if you have another version - download from [Trivy release](https://github.com/aquasecurity/trivy/releases/tag/v0.52.0) and extract the executable file into a folder called `Trivy` in this folder.

## Additional inforamtion:
- For more information about docker security, I recommend reading [Owasp Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

## Credits:
[aquasecurity/trivy](https://www.aquasec.com/products/trivy/)
