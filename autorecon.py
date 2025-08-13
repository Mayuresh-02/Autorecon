import subprocess

network = input("Enter your network range: ")
output_file = "scan_results.txt"

print("[+] Scanning the network, please wait...")

# Nmap scan command
result = subprocess.run(
    ["nmap", "-A", "-T4", network],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

# Save results to file
with open(output_file, "w") as f:
    f.write(result.stdout)

print(f"[+] Scan complete! Results saved to {output_file}")

