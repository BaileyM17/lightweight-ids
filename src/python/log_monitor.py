import re
import argparse

def scan_log(log_file, alert_file):
    rules = [
        (re.compile(r"failed\s+login", re.IGNORECASE), "Possible brute force attack"),
        (re.compile(r"unauthorized\s+access", re.IGNORECASE), "Unauthorized access attempt"),
        (re.compile(r"port\s+scan", re.IGNORECASE), "Port scanning activity detected"),
        (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "IP address detected"),
    ]

    with open(log_file, "r") as f, open(alert_file, "w") as out:
        for line_num, line in enumerate(f, 1):
            matched = False
            for pattern, alert_msg in rules:
                if pattern.search(line):
                    alert_text = f"[ALERT] {alert_msg} at line {line_num}: {line.strip()}"
                    print(alert_text)
                    out.write(alert_text + "\n")
                    matched = True
            if not matched:
                ok_text = f"[OK] {line.strip()}"
                print(ok_text)
                out.write(ok_text + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lightweight IDS Log Scanner")
    parser.add_argument("--file", required=True, help="Path to the log file")
    parser.add_argument("--out", default="alerts.log", help="Where to save alerts")
    args = parser.parse_args()

    scan_log(args.file, args.out)
