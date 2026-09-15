"""Safely stop services started by start.py on Windows.

Only processes listening on the SIEM ports are targeted. Other Python jobs are
left alone. Docker services are stopped only when --docker is supplied.
"""
import argparse
import subprocess
import sys
import time

import requests


def listeners(port):
    try:
        import psutil
        return {conn.pid for conn in psutil.net_connections(kind='tcp')
                if conn.laddr and conn.laddr.port == port and conn.status == psutil.CONN_LISTEN
                and conn.pid}
    except Exception:
        # Fall back to the built-in Windows command if psutil cannot inspect a process.
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             f"(Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue).OwningProcess"],
            capture_output=True, text=True,
        )
        return {int(line.strip()) for line in result.stdout.splitlines() if line.strip().isdigit()}


def is_dashboard(port):
    try:
        response = requests.get(f'http://127.0.0.1:{port}/health', timeout=1)
        return response.status_code == 200 and response.json().get('storage') == 'sqlite'
    except Exception:
        return False


def stop_pid(pid):
    try:
        import psutil
        process = psutil.Process(pid)
        process.terminate()
        try:
            process.wait(timeout=4)
        except psutil.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        print(f'[OK] stopped PID {pid}')
    except (ImportError, psutil.NoSuchProcess):
        return
    except (psutil.AccessDenied, PermissionError) as exc:
        print(f'[!!] cannot stop PID {pid}: {exc}', file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description='Stop the local NCU-PDCLAB mini SIEM services')
    parser.add_argument('--docker', action='store_true', help='also stop the WAF gateways and protected service containers')
    args = parser.parse_args()

    targets = set()
    dashboard = is_dashboard(8000)
    if dashboard:
        targets |= listeners(8000)
    # Port 8002 is reserved by this project for the LINE webhook. Only stop a
    # listener that answers the webhook route; arbitrary services are skipped.
    if listeners(8002):
        try:
            response = requests.get('http://127.0.0.1:8002/webhook', timeout=1)
            if response.status_code in (404, 405):
                targets |= listeners(8002)
        except requests.RequestException:
            pass

    if targets:
        for pid in sorted(targets):
            stop_pid(pid)
    else:
        print('[--] No local SIEM dashboard or LINE webhook was found.')

    if args.docker:
        result = subprocess.run(['docker', 'compose', 'down'], text=True)
        if result.returncode:
            print('[!!] Docker stop failed; check Docker Desktop.', file=sys.stderr)
        else:
            print('[OK] Docker WAF gateways and protected services stopped')

    time.sleep(.3)
    print('SIEM services stopped.')


if __name__ == '__main__':
    main()
