import subprocess
import tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

def fingerprint(target: str, directory: Path):
    output = Path(directory) / f"fingerprint-{target.replace('.', '-')}.xml"
    command = ["nmap", "-sV", "--version-light", "--top-ports", "75", "-T4", "--max-retries", "0", "--host-timeout", "20s", "-oX", str(output), target]
    print(f"[{target}] Command: {' '.join(command)}")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    print(f"[{target}] Return code: {process.returncode}")
    if stderr:
        print(f"[{target}] Stderr: {stderr}")
    print(f"[{target}] Output exists: {output.exists()}")
    return output

with tempfile.TemporaryDirectory(prefix="secureops-fingerprint-") as directory:
    print(f"Directory: {directory}")
    targets = ["172.16.2.1", "172.16.2.3"]
    
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {pool.submit(fingerprint, t, Path(directory)): t for t in targets}
        for fut in futures:
            try:
                result = fut.result()
                print(f"Result: {result}")
            except Exception as e:
                print(f"Exception: {e}")
                import traceback
                traceback.print_exc()