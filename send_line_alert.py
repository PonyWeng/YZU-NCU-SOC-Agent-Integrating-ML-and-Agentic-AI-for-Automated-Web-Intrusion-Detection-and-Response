import time
import requests
from elasticsearch import Elasticsearch
import os
import pickle
import json


print("開始偵測網路攻擊警報...")

# 連接 Elasticsearch
es = Elasticsearch(
    "http://localhost:9200",
    basic_auth=("elastic", "vEo4PSW2yMiHIMMTxAHk")
)

# LINE BOT 的 Channel access token
CHANNEL_ACCESS_TOKEN = "dfjxLksUSufbYXjRqkXAP5LqFVziOH+8MMb3EozPs3mP6CMZOCvw7SjadUpM/tLF1T5w6bXPBjB/fZEpZ4wf4PjOCOxIiTYXR3Jup9gs9S6vAaXvNceQggfaDA0yK9GrHrfdyNxgkwS5Hb1Lr1jN7AdB04t89/1O/w1cDnyilFU="
# 要推播的 userId（可多個）
USER_ID = ["U2e642dee7dae809c499064ee2ed747bb", #Elaine
           "U82da93337694fdb592ad9eaf8d2cafc7"] #John

# 讀取已通知過的 id
if os.path.exists("notified_ids.pkl"):
    with open("notified_ids.pkl", "rb") as f:
        notified_ids = pickle.load(f)
else:
    notified_ids = set()

while True:
    res = es.search(index="alert-log", sort="@timestamp:desc", size=10)
    for doc in res['hits']['hits']:
        doc_id = doc['_id']
        if doc_id not in notified_ids:
            notified_ids.add(doc_id)
            # 每次新增後即時寫回檔案
            with open("notified_ids.pkl", "wb") as f:
                pickle.dump(notified_ids, f)
            
            # 提取所有相關欄位
            source = doc['_source']
            # print("🔍 來源文件：", json.dumps(source, indent=2, ensure_ascii=False))
            attack_prediction = source.get('attack_prediction', 'Unknown')
            description = source.get('description', 'No description')
            timestamp = source.get('@timestamp', 'Unknown')
            debug = source.get('debug', 'No debug info')

            # 需要深入取得 nested 欄位（event.original、host.ip）
            event_original = source.get('event', {}).get('original', 'No event')
            host_ip = source.get('host', {}).get('ip', 'Unknown')

            # 組合完整的警報訊息
            full_message = f"""🚨 網路攻擊警報 🚨

攻擊類型: SQL Injection
事件摘要: {event_original}
主機IP: {host_ip}
描述: {description}
時間: {timestamp}
{attack_prediction}
debug: {debug}
"""

            
            # 為每個用戶分別發送訊息
            for user_id in USER_ID:
                headers = {
                    "Authorization": f"Bearer {CHANNEL_ACCESS_TOKEN}",
                    "Content-Type": "application/json"
                }
                data = {
                    "to": user_id,
                    "messages": [{"type": "text", "text": full_message}]
                }
                r = requests.post(
                    "https://api.line.me/v2/bot/message/push",
                    headers=headers,
                    json=data
                )
                print(f"已通知用戶 {user_id},  狀態: {r.status_code}") #, 回應: {r.text}
            
            print("--------------------------------------------------------------------------")
    time.sleep(0.1)  # 每次查詢間隔 0.1 秒，避免過於頻繁的請求