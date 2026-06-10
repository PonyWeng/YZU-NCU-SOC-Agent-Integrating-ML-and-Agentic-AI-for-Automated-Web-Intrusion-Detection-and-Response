# About: predict.py
# Author: walid.daboubi@gmail.com  (refactored for Python 3.10)
# Usage: python predict.py -l DATA/raw_data/predict.log -m MODELS/model_RandomForestClassifier.pkl

import csv
import hashlib
import json
import os
import pickle
import re
import time

from urllib.parse import unquote_plus

from utilities import FEATURES, _LOG_REGEX, encode_single_log_line

parser = __import__('argparse').ArgumentParser()
parser.add_argument('-l', '--log_file', help='The log file to process', required=True)
parser.add_argument('-m', '--model', help='The trained model (.pkl)', required=True)
args = vars(parser.parse_args())

log_file_name: str = args['log_file']
model_file: str = args['model']

# Load existing predictions (append-mode across runs)
if os.path.exists("prediction_output.json"):
    with open("prediction_output.json", "r") as fh:
        data_from_json: list[dict] = json.load(fh)
else:
    data_from_json = []

# Load model once — not per line
model = pickle.load(open(model_file, 'rb'))

# Load regex rules once — not inside the loop
with open('regex_4_labels.csv', 'r') as fh:
    regex_rules: list[list[str]] = list(csv.reader(fh))

with open(log_file_name, 'r') as log_file:
    for log_line in log_file:
        desc = 'there is no attack to be described'
        log_line = unquote_plus(log_line)
        url, encoded, return_code = encode_single_log_line(log_line)

        if encoded is None:
            continue

        formatted = [encoded[feature] for feature in FEATURES]
        prediction: int = int(model.predict([formatted])[0])

        for row in regex_rules:
            if re.search(row[2], url):
                desc = row[1]

        unique_str = log_line + str(time.time())
        log_id = hashlib.sha256(unique_str.encode('utf-8')).hexdigest()

        # Extract source IP from the log line (first capture group of the regex)
        m = _LOG_REGEX.match(log_line)
        src_ip = m.group(1) if m else "unknown"

        new_result = {
            "id": log_id,
            "attack_prediction": prediction,
            "URL": url,
            "description": desc,
            "return_code": return_code,
            "src_ip": src_ip,
            "log_record": log_line,
            "Source": "Machine Learning Model",
        }
        data_from_json.append(new_result)
        print(new_result)

# Write all results at once after the loop
with open("prediction_output.json", "w") as fh:
    json.dump(data_from_json, fh, indent=2)
