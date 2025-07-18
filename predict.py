# About: predict.py
# Author: walid.daboubi@gmail.com
# Version: 1.3 - 2021/10/30
#python3 predict.py -l DATA/raw_data/predict.log -m MODELS/model_RandomForestClassifier.pkl
import json
import hashlib
#import datetime
import os
from filelock import FileLock, Timeout ##沒用到

from utilities import * 

parser = argparse.ArgumentParser()
parser.add_argument('-l', '--log_file', help = 'The log file  you want to access',  required=True)
parser.add_argument('-m', '--model', help = 'The trained model',required=True )

args = vars(parser.parse_args())

log_file_name = args['log_file']
model_file=args['model']

# 讀檔
if os.path.exists("prediction_output.json"):
    with open("prediction_output.json", "r") as read_file:
        data_from_json = json.load(read_file)
else:
    data_from_json = []

log_file = open(log_file_name,'r')
index=0

for log_line in log_file:
    index += 1
    desc='there is no attack to be described'
    log_line=unquote_plus(log_line)
    url,encoded,return_code = encode_single_log_line(log_line)


    # print(url)
    # print(encoded)
    # print(return_code)

    if encoded !=None:
        formatte_encoded = []
        for feature in FEATURES:
            formatte_encoded.append(encoded[feature])
        model = pickle.load(open(model_file, 'rb')) #載入模型

        print("---------------------------------------------------------------")

        print("log_line:",log_line)
        print("format:",[formatte_encoded])
        prediction = int(model.predict([formatte_encoded])[0]) #模型判斷攻擊類型

        print("Result:",prediction)
        csv_file = open(r'regex_4_labels.csv', 'r')
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            if re.search(row[2], url):
                attack = row[0]
                desc = row[1]

        print("--------------------------------------------------------------------------")
        # 產生唯一 id：log_line + 高精度時間
        unique_str = log_line + str(time.time())
        log_id = hashlib.sha256(unique_str.encode('utf-8')).hexdigest()
        #current_time = datetime.datetime.now().isoformat()
        new_result = {
            "id": log_id,
            #"timestamp": current_time,
            "attack_prediction": prediction,
            "URL": url,
            "description": desc,
            "return_code": return_code,
            "log_record": log_line,
            "Source": "Machine Learning Model"
        }
        data_from_json.append(new_result)
        print({"id": log_id, "attack_prediction": prediction, "URL": url,"description":desc,"return_code":return_code,"log_record":log_line,"Source":"Machine Learning Model"})
        print("-------------------------------The End--------------------------------------")
        import time
        time.sleep(0.1)

# for 迴圈結束後一次性寫檔
with open("prediction_output.json", "w") as write_file:
    json.dump(data_from_json, write_file, indent=2)

