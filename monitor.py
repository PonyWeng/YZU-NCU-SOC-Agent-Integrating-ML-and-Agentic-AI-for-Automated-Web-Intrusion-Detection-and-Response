# Continuously tails ACCESS_LOG and runs batch predictions on new lines.
#
# Setup (one-time):
#   1. Create a "store-logs" directory alongside the Apache log directory.
#   2. Create empty access2.log and access3.log inside store-logs/.
#   3. Copy .env.example to .env and set ACCESS_LOG / ACCESS2_LOG / ACCESS3_LOG.
#   4. Run: python monitor.py

import os
import subprocess
import sys
import time

import psutil

from config import ACCESS_LOG, ACCESS2_LOG, ACCESS3_LOG, MODEL_PATH

PYTHON = sys.executable  # always use the same interpreter that launched monitor.py
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

OFFSET_FILE = 'last_offset.txt'

# Load persisted offset so we resume after a restart
last_offset: int = 0
if os.path.exists(OFFSET_FILE):
    try:
        with open(OFFSET_FILE, 'r') as _f:
            raw = _f.read().strip().strip('\x00')
        if raw:
            last_offset = int(raw)
    except (ValueError, OSError):
        last_offset = 0


def _is_predict_running() -> bool:
    for proc in psutil.process_iter(['name', 'cmdline']):
        try:
            if (
                proc.info['name'] and 'python' in proc.info['name'].lower()
                and 'predict.py' in ' '.join(proc.info['cmdline'] or [])
            ):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return False


def _append_new_logs() -> None:
    global last_offset

    # Detect log rotation / truncation (file smaller than saved offset)
    current_size = os.path.getsize(ACCESS_LOG)
    if current_size < last_offset:
        print(f'[monitor] Log file truncated ({last_offset} → {current_size}). Resetting offset.')
        last_offset = 0

    with open(ACCESS_LOG, 'r', encoding='utf-8', errors='replace') as fp:
        fp.seek(last_offset)
        new_lines = fp.readlines()
        last_offset = fp.tell()

    if new_lines:
        with open(ACCESS2_LOG, 'a') as f2:
            f2.writelines(new_lines)

    with open(OFFSET_FILE, 'w') as f:
        f.write(str(last_offset))


def _batch_predict() -> None:
    if not os.path.exists(ACCESS2_LOG):
        return
    with open(ACCESS2_LOG, 'r') as f2:
        lines = f2.readlines()
    if not lines:
        return

    if _is_predict_running():
        print('[monitor] predict.py already running — skipping this round.')
        return

    print(f'[monitor] Predicting {len(lines)} new lines...')
    subprocess.run(
        [PYTHON, "predict.py", "-l", ACCESS2_LOG, "-m", MODEL_PATH],
        cwd=SCRIPT_DIR,
    )

    # Archive processed lines then clear the buffer
    with open(ACCESS2_LOG, 'r') as f2, open(ACCESS3_LOG, 'a') as f3:
        f3.writelines(f2.readlines())
    open(ACCESS2_LOG, 'w').close()
    print('[monitor] Done — access2.log cleared.')


if __name__ == '__main__':
    print(f'[monitor] Watching {ACCESS_LOG}')
    while True:
        try:
            _append_new_logs()
            _batch_predict()
            time.sleep(0.5)
        except Exception as exc:
            print(f'[monitor] Error: {exc}', file=sys.stderr)
            time.sleep(1)
