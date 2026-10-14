import subprocess
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory(prefix="secureops-fingerprint-") as directory:
    target = "172.16.2.3"
    output = Path(directory) / f"fingerprint-{target.replace('.', '-')}.xml"
    print(f"Directory: {directory}")
    print(f"Output: {output}")
    print(f"Output str: {str(output)}")
    
    command = ["nmap", "-sV", "--version-light", "--top-ports", "75", "-T4", "--max-retries", "0", "--host-timeout", "20s", "-oX", str(output), target]
    print(f"Command: {' '.join(command)}")
    
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    print(f"Return code: {process.returncode}")
    print(f"Stdout: {stdout}")
    print(f"Stderr: {stderr}")
    
    # Check if output file exists
    print(f"Output exists: {output.exists()}")
    if output.exists():
        print(f"Output size: {output.stat().st_size}")