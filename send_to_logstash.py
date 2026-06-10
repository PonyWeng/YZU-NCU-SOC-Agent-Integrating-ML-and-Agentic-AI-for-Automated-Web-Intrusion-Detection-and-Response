# Watches prediction_output.json for changes and forwards new records to Logstash.
# Run: python send_to_logstash.py

import json
import os
import time

import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

PREDICTION_FILE = "prediction_output.json"
PROCESSED_IDS_FILE = "processed_ids.txt"
LOGSTASH_URL = "http://localhost:5044"

processed_ids: set[str] = set()


def load_processed_ids() -> None:
    global processed_ids
    if os.path.exists(PROCESSED_IDS_FILE):
        try:
            with open(PROCESSED_IDS_FILE, "r") as fh:
                processed_ids = {line.strip() for line in fh if line.strip()}
        except OSError:
            processed_ids = set()


def save_processed_ids() -> None:
    with open(PROCESSED_IDS_FILE, "w") as fh:
        fh.write('\n'.join(processed_ids))


class FileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event) -> None:
        if not event.src_path.endswith(PREDICTION_FILE):
            return
        try:
            with open(PREDICTION_FILE, "r") as fh:
                data: list[dict] = json.load(fh)

            new_data = [item for item in data if item['id'] not in processed_ids]
            if not new_data:
                return

            # Send in batches of 50 to avoid Logstash body size limits
            BATCH = 50
            sent = 0
            for i in range(0, len(new_data), BATCH):
                batch = new_data[i:i + BATCH]
                resp = requests.post(LOGSTASH_URL, json=batch, timeout=30)
                if resp.status_code == 200:
                    for item in batch:
                        processed_ids.add(item['id'])
                    sent += len(batch)
                else:
                    print(f"Logstash returned {resp.status_code}: {resp.text}")
                    break
            if sent:
                save_processed_ids()
                print(f"Sent {sent} new record(s) to Logstash.")

        except Exception as exc:
            print(f"Error while sending to Logstash: {exc}")


if __name__ == "__main__":
    load_processed_ids()
    print(f"Loaded {len(processed_ids)} already-processed IDs.")

    handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(handler, path='.', recursive=False)
    observer.start()
    print(f"Watching {PREDICTION_FILE} for changes...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
