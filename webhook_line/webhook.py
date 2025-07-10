##拿userId
# webhook_line/webhook.py
from flask import Flask, request

app = Flask(__name__)
    
@app.route("/callback", methods=['POST'])
def callback():
    body = request.get_json()
    print("收到的 body:", body) 
    events = body.get("events", []) if body else []
    for event in events:
        user_id = event["source"]["userId"]
        print("新 userId:", user_id)
    return "OK" 

if __name__ == "__main__":
    app.run(port=5000)