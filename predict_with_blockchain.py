import json
from web3 import Web3
from utilities import *


##Configs about Smart Contracts

w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))
contract_address = "0x4dF07BC4a763B41216c005E100fDa10549EB6C16"

# 更新合約 ABI
contract_abi = [
    {
        "constant": True,
        "inputs": [],
        "name": "owner",
        "outputs": [{"name": "", "type": "address"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [{"name": "logEntry", "type": "string"}],
        "name": "addLog",
        "outputs": [],
        "payable": False,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "getLogsCount",
        "outputs": [{"name": "", "type": "uint256"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [{"name": "index", "type": "uint256"}],
        "name": "getLog",
        "outputs": [{"name": "", "type": "string"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    }
]

contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# 合約的擁有者帳戶私鑰
account_private_key = "73dae8dc390dbc2776a878462efa0ebb4483ec7bba910db7d63181f588539ca4"

# 將私鑰解鎖以進行交易
owner_account = w3.eth.account.privateKeyToAccount(account_private_key)


owner_address="0x6648d64c00eb5bb8723b7E426E0afC7647F4Eaf3"
account_address = w3.toChecksumAddress("0x6648d64c00eb5bb8723b7E426E0afC7647F4Eaf3")






###################################################################################################


parser = argparse.ArgumentParser()
parser.add_argument('-l', '--log_file', help = 'The log file  you want to assess',  required=True)
parser.add_argument('-m', '--model', help = 'The trained model',required=True )

args = vars(parser.parse_args())

log_file_name = args['log_file']
model_file=args['model']

with open("prediction_output.json", "r") as read_file:
    data_from_json = json.load(read_file)

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
        model = pickle.load(open(model_file, 'rb'))

        print("---------------------------------------------------------------")

        print("log_line:",log_line)
        print("format:",[formatte_encoded])
        prediction = int(model.predict([formatte_encoded])[0])

        print("Result:",prediction)
        csv_file = open(r'regex_4_labels.csv', 'r')
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            if re.search(row[2], url):
                attack = row[0]
                desc = row[1]


        #####
        

        new_log ={"attack_prediction": prediction, "URL": url,"description":desc,"return_code":return_code,"log_record":log_line,"Source":"Machine Learning Model"}

        new_log=str(new_log)

        transaction = contract.functions.addLog(new_log).buildTransaction({
            'chainId': 1337,  # Ganache 鏈的 ID
            'gas': 2000000,   # 手續費上限
            'gasPrice': w3.toWei('20', 'gwei'),
            'nonce': w3.eth.getTransactionCount(account_address),
        })

        signed_transaction = w3.eth.account.signTransaction(transaction, private_key=account_private_key)
        transaction_hash = w3.eth.sendRawTransaction(signed_transaction.rawTransaction)


        print(transaction_hash)
        print(transaction_hash.hex())
        transaction_hash_str= str(transaction_hash.hex())

        
        ####
        print("Transaction Hash:", transaction_hash.hex())
        print("--------------------------------------------------------------------------")
        data_from_json.append({"attack_prediction": prediction, "URL": url,"description":desc,"return_code":return_code,"log_record":log_line,"Source":"Machine Learning Model","TxHash":transaction_hash_str,"Contracts_Address":contract_address,"Owner_Address":owner_address})
        print({"attack_prediction": prediction, "URL": url,"description":desc,"return_code":return_code,"log_record":log_line,"Source":"Machine Learning Model"})
        print("-------------------------------The End--------------------------------------")

with open("prediction_output.json", "w") as write_file:
    json.dump(data_from_json, write_file, indent=2)

