import time
import requests
from elasticsearch import Elasticsearch
import os
import pickle
from datetime import datetime, timedelta
from dateutil import parser
import json

def utc_to_tw(utc_str):
    dt = parser.isoparse(utc_str)
    dt_tw = dt + timedelta(hours=8)
    return dt_tw.strftime("%Y-%m-%d %H:%M:%S.%f")

print("開始偵測網路攻擊警報...")

# 連接 Elasticsearch
es = Elasticsearch(
    "http://localhost:9200",
    basic_auth=("elastic", "vEo4PSW2yMiHIMMTxAHk")
)

# LINE BOT 的 Channel access token
CHANNEL_ACCESS_TOKEN = "+YOKjJXfTzqXkBN+oBf0y8SjGugAXenUjIE30G6rfwzisSlAGLeVdFv86p8EdkLDmS45q+DrAU0eNhJW5/eExuVcgdq4ZvcIuGArAntzf2SlRzAkmhcXhz/qO0wqtLajCJxflOyyKFp63k7MI9PQtwdB04t89/1O/w1cDnyilFU="
#CHANNEL_ACCESS_TOKEN = "dfjxLksUSufbYXjRqkXAP5LqFVziOH+8MMb3EozPs3mP6CMZOCvw7SjadUpM/tLF1T5w6bXPBjB/fZEpZ4wf4PjOCOxIiTYXR3Jup9gs9S6vAaXvNceQggfaDA0yK9GrHrfdyNxgkwS5Hb1Lr1jN7AdB04t89/1O/w1cDnyilFU="
# 要推播的 userId（可多個）
USER_ID = ["U2e642dee7dae809c499064ee2ed747bb"] #, #Elaine
           #"U82da93337694fdb592ad9eaf8d2cafc7"] #John
# "U54834239a18fb4a58f563d78e3e914e0", 
# 讀取已通知過的 alert-log id
if os.path.exists("notified_alert_ids.pkl"):
    with open("notified_alert_ids.pkl", "rb") as f:
        notified_alert_ids = pickle.load(f)
else:
    notified_alert_ids = set()

while True:
    res = es.search(index="alert-log", sort="@timestamp:desc", size=10)
    for doc in res['hits']['hits']:
        alert_id = doc['_id']
        if alert_id not in notified_alert_ids:
            notified_alert_ids.add(alert_id)
            with open("notified_alert_ids.pkl", "wb") as f:
                pickle.dump(notified_alert_ids, f)
            # 取出 alert 的時間範圍
            source = doc['_source']
            date_start = source.get('dateStart')
            date_end = source.get('dateEnd')
            if not date_start or not date_end:
                print("alert-log 缺少時間範圍，略過")
                continue
            # 回查 prediction-logs-* 這段時間的資料
            pred_res = es.search(
                index="prediction-logs-*",
                body={
                    "query": {
                        "range": {
                            "@timestamp": {
                                "gte": date_start,
                                "lte": date_end
                            }
                        }
                    },
                    "sort": [
                        {"@timestamp": "asc"}
                    ]
                },
                size=1  # (發幾個告警)
            )
            for pred_doc in pred_res['hits']['hits']:
                source = doc['_source']
                pred = pred_doc['_source']
                ip = pred.get('host', {}).get('ip', 'Unknown')
                desc = pred.get('description', 'No description')
                attack = pred.get('attack_prediction', 'Unknown')
                message = source.get('message', 'Unknown')
                risk = source.get('risk', 'Unknown')
                ts = pred.get('@timestamp', 'Unknown')
                if ts != 'Unknown':
                    ts = utc_to_tw(ts)
                    
                full_message = f"""[Warning] NIDS Alert\n\n[Event Name]: {message}\n[Risk Level]: {risk}\n[Desciption]: {desc}\n[Source IP]: {ip}\n[Starting Time]: {ts}\n\nThe observed behavior has triggered an alert and requires further investigation."""
                
                rag_api_url = "http://localhost:8001/summary"  # RAG API 端點
                try:
                    rag_response = requests.post(rag_api_url, json={"text": full_message}, timeout=60)
                    summary = rag_response.json().get("summary", "（AI摘要失敗）")
                except Exception as e:
                    summary = f"（AI摘要失敗: {e}）"

                # 組合要推播的訊息
                line_message = f"{full_message}\n\n【AI Summary】\n{summary}"
                
                # 發送 LINE
                for user_id in USER_ID:
                    headers = {
                        "Authorization": f"Bearer {CHANNEL_ACCESS_TOKEN}",
                        "Content-Type": "application/json"
                    }
                    data = {
                        "to": user_id,
                        "messages": [{"type": "text", "text": line_message}]
                    }
                    r = requests.post(
                        "https://api.line.me/v2/bot/message/push",
                        headers=headers,
                        json=data
                    )
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"[{now}] 已通知用戶 {user_id},  狀態: {r.status_code}")
            print("--------------------------------------------------------------------------")
    time.sleep(1)