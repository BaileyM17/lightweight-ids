import re
import argparse
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_file, rules, alert_file):
        self.log_file = os.path.abspath(log_file)
        self.rules = rules
        self.alert_file = alert_file
        self.position = 0  # track last read position

    def on_modified(self, event):
        if os.path.abspath(event.src_path) == self.log_file:
            with open(self.log_file, "r") as f:
                f.seek(self.position)  # jump to where we left off
                new_lines = f.readlines()
                self.position = f.tell()  # update marker

            if new_lines:  # only if something was added
                with open(self.alert_file, "a") as out:
                    for line in new_lines:
                        matched = False
                        for pattern, alert_msg in self.rules:
                            if pattern.search(line):
                                alert_text = f"[ALERT] {alert_msg}: {line.strip()}"
                                print(alert_text)
                                out.write(alert_text + "\n")
                                matched = True
                        if not matched:
                            ok_text = f"[OK] {line.strip()}"
                            print(ok_text)
                            out.write(ok_text + "\n")


# class LogFileHandler(FileSystemEventHandler):
#     def __init__(self, log_file, rules, alert_file):
#         self.log_file = os.path.abspath(log_file)
#         self.rules = rules
#         self.alert_file = alert_file
#         self.position = 0 # track where we last read
        
#     def on_modified(self, event):
#         if os.path.abspath(event.src_path) == self.log_file:  # only react to our log
#             print(f"[DEBUG] File modified: {event.src_path}")
#             with open(self.log_file, "r") as f, open(self.alert_file, "w") as out:
#                 f.seek(self.position)   # go to where we left off
#                 for line_num, line in enumerate(f, 1):
#                     matched = False
#                     for pattern, alert_msg in rules:
#                         if pattern.search(line):
#                             alert_text = f"[ALERT] {alert_msg} at line {line_num}: {line.strip()}"
#                             print(alert_text)
#                             out.write(alert_text + "\n")
#                             matched = True
#                     if not matched:
#                         ok_text = f"[OK] {line.strip()}"
#                         print(ok_text)
#                         out.write(ok_text + "\n")
#                 self.position = f.tell()

def load_rules(file_path):
    with open(file_path, "r") as f:
        data = json.load(f)
        rules = []
        for rule in data:
            flags = re.IGNORECASE if rule.get("ignore_case", False) else 0
            rules.append((re.compile(rule["pattern"], flags), rule["message"]))
        return rules

def scan_log(log_file, alert_file, rules):
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
    parser.add_argument("--rules", default="rules.json", help="Path to rules config")
    parser.add_argument("--follow", action="store_true", help="Enable real-time monitoring")
    args = parser.parse_args()

    rules = load_rules(args.rules)
    
    if args.follow:
        abs_log = os.path.abspath(args.file)
        log_dir = os.path.dirname(abs_log)
        
        event_handler = LogFileHandler(abs_log, rules, args.out)
        observer = Observer()
        observer.schedule(event_handler, path=log_dir, recursive=False)
        observer.start()
        print(f"[INFO] Monitoring {args.file} in real time...")
        try:
            while True:
                time.sleep(1) # keep script alive
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
    else:
        scan_log(args.file, args.out, rules)
                