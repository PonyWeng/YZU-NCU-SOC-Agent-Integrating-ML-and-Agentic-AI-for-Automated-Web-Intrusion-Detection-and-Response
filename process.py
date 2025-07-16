
# About: Artificailly generate labeled data starting form raw http log file by adding rule based tags
# Author: walid.daboubi@gmail.com
# Version: 1.3 - 2021/10/30

#	A sample of lableled data:
# 	url_length,param_number,return_code,label, http_query
# 	49,1,404,1,GET /honeypot/bsidesdfw%20-%202014.ipynb HTTP/1.1
#       Label could be 1 (attack detected) or 0 (no attack detected)

# A HTTP LOG LINE SAMPLE
# 182.74.246.198 - - [01/Mar/2017:02:18:36 -0800] "GET /bootstrap/img/favicon.ico HTTP/1.1" 200 589 "http://www.secrepo.com/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"

from utilities import *

parser = argparse.ArgumentParser()
parser.add_argument('-l', '--log_file', help = 'The raw http log file', required = True)
parser.add_argument('-d', '--dest_file', help = 'Destination to store the resulting csv file', required = True)

args = vars(parser.parse_args())

log_file = args['log_file']
dest_file =args['dest_file']


# Encode all the data in http log file (access_log)
def encode_log_file(log_file):
	data = {}
	log_file = open(log_file,'r')
	lines_count = 0
	count_log_line_data = 0
	for log_line in log_file:
		lines_count += 1
		log_line=unquote_plus(log_line) # convert "+" to " "    # urllib.parse 從 utilities.py import
		url, log_line_data, return_code = encode_single_log_line(log_line)

		if log_line_data != None:

			# new code
			if url in data:
				data[url].append(log_line_data)
			elif url not in data:
				log_line_data_list = []
				log_line_data_list.append(log_line_data)
				data[url] = log_line_data_list
	
	return data

# 把每一筆 log 的特徵資料，轉成像這樣的格式: 589,1,49,404,0,10,2,3,
# 方便直接寫進 CSV 檔案，讓後續訓練模型或分析時可以直接讀取
# 就是把一筆 log 的特徵字典，依照欄位順序轉成一行 CSV 字串
def encode_single_line(single_line,features):
	encoded = ""
	for feature in features:
		encoded += str(single_line[feature]) + ','
	return encoded


def save_encoded_data(data,encoded_data_file):
	# 統計不同攻擊類型（1、2、3）的數量
	count_1 = 0
	count_2 = 0
	count_3 = 0

	# 自動標註攻擊類型
	# 用正則表達式比對 URL，自動決定 label
	for keys, values in data.items():
		for inner_dict in values:
			#determine category by using regular expression (判斷攻擊類型)
			attack='0'
			with open('regex_4_labels.csv') as csv_file:
				csv_reader = csv.reader(csv_file, delimiter=',')
				for row in csv_reader:
					if re.search(row[2], keys.lower()):
						attack = row[0]
			if attack == '1':
				count_1 += 1
			elif attack == '2':
				count_2 += 1
			elif attack == '3':
				count_3 += 1
			# attack = '3'

			# 組合成一行資料並寫入檔案
			data_row = encode_single_line(inner_dict, FEATURES) + attack + ',' + keys + '\n'
			encoded_data_file.write(data_row)
	print (str(len(data)) + ' rows have successfully saved to ' + dest_file)

# 把剛剛判斷出來的 attack（label）加到每一行資料裡，寫進 CSV (我這邊是放 0830.log)
print(len(encode_log_file(log_file)))
save_encoded_data(encode_log_file(log_file),open(dest_file, 'w', encoding='utf-8'))




