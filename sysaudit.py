import argparse
import os
import hashlib
import time
import subprocess
import datetime
import json
import logging
from logging.handlers import SysLogHandler
import fnmatch

logger = logging.getLogger("sysaudit")
logger.setLevel(logging.INFO)
handler = SysLogHandler(address='/dev/log')
logger.addHandler(handler)

severity_levels = {
    '/etc/sudoers': 'HIGH',
    '/etc/shadow': 'HIGH',
    '/home/user/.bashrc': 'LOW',
}

def get_severity(path):
    for p, s in severity_levels.items():
        if path.startswith(p):
            return s
    return 'LOW'

def init_repo(repo_path, baseline_branch='main'):
    if not os.path.exists(repo_path):
        os.makedirs(repo_path)
    os.chdir(repo_path)
    subprocess.run(["git", "init"], check=True, capture_output=True)
    subprocess.run(["git", "checkout", "-b", baseline_branch], check=True, capture_output=True)

def copy_file_to_repo(original_path, repo_path, watch_dir):
    relative = os.path.relpath(original_path, watch_dir)
    repo_file = os.path.join(repo_path, relative)
    os.makedirs(os.path.dirname(repo_file), exist_ok=True)
    with open(original_path, 'rb') as src, open(repo_file, 'wb') as dst:
        dst.write(src.read())
    return relative

def commit_changes(repo_path, changes, gpg_sign=False):
    os.chdir(repo_path)
    message_parts = []
    for path, op in changes:
        timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
        process = "unknown process"
        severity = get_severity(path)
        msg = f"{op} {path} at {timestamp} by {process} severity {severity}"
        message_parts.append(msg)
        if severity == 'HIGH':
            logger.critical(f"Critical change: {msg}")
    full_msg = "\n".join(message_parts)
    for path, op in changes:
        relative = os.path.relpath(path, changes[0][0].split('/')[0])
        if op == 'deleted':
            subprocess.run(["git", "rm", relative], check=True, capture_output=True)
        else:
            subprocess.run(["git", "add", relative], check=True, capture_output=True)
    sign_flag = ["-S"] if gpg_sign else []
    subprocess.run(["git", "commit"] + sign_flag + ["-m", full_msg], check=True, capture_output=True)

def monitor(watch_dirs, repo_path, blacklist_patterns, batch_time=5, gpg_sign=False):
    init_repo(repo_path)
    previous_state = {}
    last_commit_time = time.time()
    changes = []
    while True:
        current_state = {}
        for watch_dir in watch_dirs:
            for root, _, files in os.walk(watch_dir):
                for f in files:
                    path = os.path.join(root, f)
                    if any(fnmatch.fnmatch(f, pat) for pat in blacklist_patterns):
                        continue
                    try:
                        current_state[path] = hashlib.sha256(open(path, 'rb').read()).hexdigest()
                    except FileNotFoundError:
                        pass
        for path, h in current_state.items():
            if path not in previous_state or previous_state[path] != h:
                try:
                    copy_file_to_repo(path, repo_path, os.path.commonpath(watch_dirs))
                    changes.append((path, "modified" if path in previous_state else "created"))
                except FileNotFoundError:
                    pass
        for path in list(previous_state):
            if path not in current_state:
                changes.append((path, "deleted"))
        if changes and time.time() - last_commit_time > batch_time:
            commit_changes(repo_path, changes, gpg_sign)
            changes = []
            last_commit_time = time.time()
        previous_state = current_state
        time.sleep(1)

def drift_check(repo_path, baseline='main'):
    os.chdir(repo_path)
    output = subprocess.run(["git", "diff", baseline, "HEAD", "--name-only"], capture_output=True, text=True).stdout
    print("Drift files:")
    print(output)

def compliance_report(dirs, output_file=None):
    issues = []
    for d in dirs:
        for root, _, files in os.walk(d):
            for f in files:
                path = os.path.join(root, f)
                st = os.stat(path)
                if st.st_mode & 0o002:
                    issues.append({"severity": "HIGH", "desc": "World-writable file", "path": path})
                if st.st_mode & 0o4000:
                    issues.append({"severity": "MEDIUM", "desc": "SUID file", "path": path})
                if 'shadow' in path:
                    with open(path, 'r') as shadow:
                        if any(line.split(':')[1] == '' for line in shadow):
                            issues.append({"severity": "HIGH", "desc": "Empty password", "path": path})
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(issues, f, indent=4)
    else:
        print(json.dumps(issues, indent=4))

def rollback(repo_path, commit, path):
    os.chdir(repo_path)
    relative = os.path.relpath(path, os.path.commonpath([path]))
    subprocess.run(["git", "checkout", commit, "--", relative], check=True)
    repo_file = os.path.join(repo_path, relative)
    with open(repo_file, 'rb') as src, open(path, 'wb') as dst:
        dst.write(src.read())

def load_blacklist(config_file):
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return ["*.tmp", "*.swp", "*~", "*.log"]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SysAudit")
    subparsers = parser.add_subparsers(dest="command")

    init_p = subparsers.add_parser("init")
    init_p.add_argument("--repo", required=True)
    init_p.add_argument("--baseline", default="main")

    monitor_p = subparsers.add_parser("monitor")
    monitor_p.add_argument("--watch", action='append', required=True)
    monitor_p.add_argument("--repo", required=True)
    monitor_p.add_argument("--config", default=".sysauditrc")
    monitor_p.add_argument("--daemon", action="store_true")
    monitor_p.add_argument("--gpg", action="store_true")

    drift_p = subparsers.add_parser("drift-check")
    drift_p.add_argument("--repo", required=True)
    drift_p.add_argument("--baseline", default="main")

    comp_p = subparsers.add_parser("compliance-report")
    comp_p.add_argument("--watch", action='append', required=True)
    comp_p.add_argument("--output", default=None)
    comp_p.add_argument("--format", default="json")

    roll_p = subparsers.add_parser("rollback")
    roll_p.add_argument("--repo", required=True)
    roll_p.add_argument("--to", dest="commit", required=True)
    roll_p.add_argument("--path", required=True)

    args = parser.parse_args()

    if args.command == "init":
        init_repo(args.repo, args.baseline)
    elif args.command == "monitor":
        blacklist = load_blacklist(args.config)
        monitor(args.watch, args.repo, blacklist, gpg_sign=args.gpg)
    elif args.command == "drift-check":
        drift_check(args.repo, args.baseline)
    elif args.command == "compliance-report":
        compliance_report(args.watch, args.output)
    elif args.command == "rollback":
        rollback(args.repo, args.commit, args.path)