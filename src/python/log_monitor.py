import re

def scan_log(log_file):
    # Define regex rules: pattern + message
    rules = [
        (re.compile(r"failed\s+login", re.IGNORECASE), "Possible brute force attack"),
        (re.compile(r"unauthorized\s+access", re.IGNORECASE), "Unauthorized access attempt"),
        (re.compile(r"port\s+scan", re.IGNORECASE), "Port scanning activity detected"),
        (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "IP address detected"),
    ]
    
    with open(log_file, "r") as f:
        for line_num, line in enumerate(f, 1): # keep track of line numbers
            matched = False # track if any rule matches
            
            for pattern, alert_msg in rules:
                if pattern.search(line):
                    print(f"[ALERT] {alert_msg} at line {line_num}: {line}")
                    matched = True
                    # don't break - lines can trigger multiple alerts
                
            if not matched:
                print(f"[OK] {line.strip()}")
            
if __name__ == "__main__":
    scan_log("examples/sample.log")