# Warning:
# log will be reload when server restart since list can't store permanently 
# ===============================================================
# Procedure description:
# Step 1:add a new dircectory named "store-logs" as same as Apache log directory
# Step 2:Then, add two files named "access2.log" and "access3.log" in "store-logs" respectively
# Step 3: Modify model_path to your model path
# Step 4:Run server => python monitory.py for starting monitor
# ===============================================================

import os, sys, time
import psutil

OFFSET_FILE = 'last_offset.txt'
ACCESS_LOG = r'C:\xampp\apache\logs\access.log'
ACCESS2_LOG = r'C:\xampp\apache\logs\store-logs\access2.log'
ACCESS3_LOG = r'C:\xampp\apache\logs\store-logs\access3.log'
MODEL_PATH = '.\\MODELS\\model_RandomForestClassifier.pkl'

# 取得目前 offset
if os.path.exists(OFFSET_FILE):
    with open(OFFSET_FILE, 'r') as f:
        last_offset = int(f.read())
else:
    last_offset = 0

last_processed_lines = 0

def is_predict_running():
    for proc in psutil.process_iter(['name', 'cmdline']):
        try:
            if 'python' in proc.info['name'] and 'predict.py' in ' '.join(proc.info['cmdline']):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return False

def append_new_logs():
    global last_offset, last_processed_lines
    with open(ACCESS_LOG, 'r') as fp:
        fp.seek(last_offset)
        new_lines = fp.readlines()
        new_offset = fp.tell()
    if new_lines:
        with open(ACCESS2_LOG, 'a') as f2:
            for line in new_lines:
                f2.write(line)
        #print(f'Processed {len(new_lines)} new lines.')
    last_processed_lines = len(new_lines)
    last_offset = new_offset
    with open(OFFSET_FILE, 'w') as f:
        f.write(str(last_offset))

def batch_predict():
    if not os.path.exists(ACCESS2_LOG):
        return
    with open(ACCESS2_LOG, 'r') as f2:
        lines = f2.readlines()
    if lines:
        if not is_predict_running():
            print(f'[batch_predict] Predicting {len(lines)} lines...')
            os.system(f'python predict.py -l "{ACCESS2_LOG}" -m "{MODEL_PATH}"')
            with open(ACCESS2_LOG, 'r') as f2, open(ACCESS3_LOG, 'a') as f3:
                for line in f2:
                    f3.write(line)
            open(ACCESS2_LOG, 'w').close()
            print(f'[batch_predict] Done and cleared access2.log.')
        else:
            print("[batch_predict] predict.py is already running, skip this round.")

if __name__ == "__main__":
    print(f'Monitoring {ACCESS_LOG}...')
    while True:
        try:
            append_new_logs()
            batch_predict()
            time.sleep(0.5)
        except Exception as e:
            print(f"[monitor.py] Error: {e}")
            time.sleep(1)