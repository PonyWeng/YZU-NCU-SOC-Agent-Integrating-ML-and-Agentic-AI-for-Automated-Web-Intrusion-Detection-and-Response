"""Classify an Apache log file and persist events without alerting on historical data."""
import argparse
import hashlib
from pathlib import Path
from siem.collector import Classifier
from siem import store

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l','--log_file',required=True)
    parser.add_argument('-m','--model',required=True)
    args = parser.parse_args()
    store.init_db()
    classifier = Classifier(args.model)
    path = Path(args.log_file).resolve()
    batch=[]
    total=0
    with path.open('rb') as f:
        while True:
            offset=f.tell()
            line=f.readline()
            if not line:
                break
            event_id=hashlib.sha256(str(path).encode()+str(offset).encode()+line).hexdigest()
            batch.append(classifier.event(line.decode('utf-8',errors='replace').rstrip(),event_id))
            if len(batch)==200:
                total+=store.insert_events(batch)
                batch=[]
    total+=store.insert_events(batch)
    print(f'Imported {total} new events into SIEM')

if __name__ == '__main__':
    main()
