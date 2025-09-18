def scan_log(log_file):
    # Define some simple rules (just keyword checks)
    rules = {
        "failed login": "Possible brute force attack",
        "unauthorized access": "Unauthorized access attempt",
        "port scan": "Port scanning activity detected"
    }
    
    with open(log_file, "r") as f:
        for line_num, line in enumerate(f, 1): # keep track of line numbers
            line = line.strip().lower() # normalize to lowercase
            matched = False # track if any rule matches
            
            for keyword, alert_msg in rules.items():
                if keyword in line:
                    print(f"[ALERT] {alert_msg} at line {line_num}: {line}")
                    matched = True
                    break # stop after first match
                
            if not matched:
                print(f"[OK] {line}")
            
if __name__ == "__main__":
    scan_log("examples/sample.log")