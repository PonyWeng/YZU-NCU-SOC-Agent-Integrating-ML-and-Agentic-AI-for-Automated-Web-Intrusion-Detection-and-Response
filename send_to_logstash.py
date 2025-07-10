import time
import json
import requests
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler 

# 用來記錄已經處理過的log的ID
processed_ids_file = "processed_ids.txt"
processed_ids = set()

def load_processed_ids():
    """載入已經處理過的ID"""
    global processed_ids
    if os.path.exists(processed_ids_file):
        try:
            with open(processed_ids_file, "r") as f:
                for line in f:
                    processed_ids.add(line.strip())
        except:
            processed_ids = set()
    else:
        processed_ids = set()

def save_processed_ids():
    """儲存已處理的ID到檔案"""
    with open(processed_ids_file, "w") as f:
        for id in processed_ids:
            f.write(f"{id}\n")

class FileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        # 只監控 prediction_output.json 檔案
        if event.src_path.endswith("prediction_output.json"):
            try:
                with open("prediction_output.json", "r") as file:
                    data = json.load(file)
                
                # 過濾掉已經處理過的資料
                new_data = [item for item in data if item['id'] not in processed_ids]
                
                # 如果有新的資料，就發送給 Logstash
                if new_data:
                    response = requests.post('http://localhost:5044', json=new_data)
                    if response.status_code == 200:
                        print(f"成功發送 {len(new_data)} 筆新資料到 Logstash")
                        # 記錄已處理過的 ID
                        for item in new_data:
                            processed_ids.add(item['id'])
                        # 儲存到檔案
                        save_processed_ids()
                    else:
                        print("發送失敗:", response.text)
                else:
                    print("沒有新資料需要發送。")
            
            except Exception as e:
                print("讀取或發送過程中發生錯誤:", e)

if __name__ == "__main__":
    # 載入已經處理過的ID
    load_processed_ids()
    print(f"已載入 {len(processed_ids)} 個已處理的ID")
    
    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, path='.', recursive=False)
    observer.start()
    print("開始監控 prediction_output.json ...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
