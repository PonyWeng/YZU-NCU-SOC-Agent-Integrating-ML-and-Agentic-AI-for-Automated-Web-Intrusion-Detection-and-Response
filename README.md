# YZU_NIDS_project


* **本專案使用的環境與套件版本：**
    * Python 3.8.13
        * scikit-learn 1.3.2  (本來是1.3.0改成1.3.2) 
        * yellowbrick 1.5
        * uvicorn 0.30.6
        * seaborn 0.13.2
        * fastapi 0.112.2

* **建立Anaconda 虛擬環境**
`conda create -n YZU_IDS python==3.8.13`

## 本專案所需Python 套件
* **安裝Dependencies**
```
conda install scikit-learn
conda install seaborn
conda install -c conda-forge yellowbrick
conda install -c conda-forge uvicorn
conda install -c conda-forge fastapi
```

### 或直接用 pip 安裝所有需要的套件：
```
pip install scikit-learn==1.3.2
pip install seaborn==0.13.2
pip install yellowbrick==1.5
pip install uvicorn==0.30.6
pip install fastapi==0.112.2
pip install elasticsearch
pip install requests
pip install python-dateutil
pip install pandas
pip install psutil
pip install flask
```

> **說明：**
> - `psutil`：監控系統程序（monitor.py 會用到）
> - `flask`：LINE webhook 服務（webhook_line/webhook.py 會用到）
> - 其餘套件依各程式需求安裝

## 本專案所使用的幾個程式 (機器學習、監控部分)

1. process.py
2. train.py
3. predict.py
4. monitor.py

* **訓練資料前處理指令  (需要手動改成自己的檔案路徑)：**
`python process.py -l C:\Users\sensh\Desktop\學長的\yzu_nids_project\DATA\raw_data\access.log -d C:\Users\sensh\Desktop\學長的\yzu_nids_project\DATA\raw_data\0830.log`

* **模型訓練指令 (需要手動改成自己的檔案路徑)**
`python train.py -l C:\Users\sensh\Desktop\學長的\yzu_nids_project\DATA\labeled_data\dataset-data-imblance.csv`

* **模型預測指令 (需要手動改成自己的檔案路徑) -> 這個是批次處理，動態監測可以不用管**
`python predict.py -l ./DATA/raw_data/predict.log -m ./MODELS/model_RandomForestClassifier.pkl`

* **啟動API Server**
`python -m uvicorn api:app --reload --host 0.0.0.0 --port 8000`
此步驟須完成，前端畫面才會顯示得出攻擊的Log Data。

* **啟用攻擊監控器**
`python monitor.py`

## 啟動與建立Apache Server 測試靶機網站

* 請參照下列教學，來部署測試靶機的Apache Server
https://medium.com/@sui16783/%E6%95%99%E5%AD%B8-%E5%A6%82%E4%BD%95%E7%94%A8-xampp-%E5%9C%A8%E8%87%AA%E5%B7%B1%E7%9A%84%E9%9B%BB%E8%85%A6%E6%9E%B6%E8%A8%AD%E7%AC%AC%E4%B8%80%E5%80%8B%E7%B6%B2%E7%AB%99-d131ca1bd9e9

* 靶機測試網頁：將以下php程式碼用儲存為index.php，作為測試用的靶機頁面，請按照上述教學來建立。

```
<html>

<head>
  <title>IDS Testing</title>
</head>
<style>
  /* @import "bourbon"; */

  body {
    background: #eee !important;
  }

  .wrapper {
    margin-top: 80px;
    margin-bottom: 80px;
  }

  .form-signin {
    max-width: 380px;
    padding: 15px 35px 45px;
    margin: 0 auto;
    background-color: #fff;
    border: 1px solid rgba(0, 0, 0, 0.1);

    .form-signin-heading,
    .checkbox {
      margin-bottom: 30px;
    }

    .checkbox {
      font-weight: normal;
    }

    .form-control {
      position: relative;
      font-size: 16px;
      height: auto;
      padding: 10px;
      @include box-sizing(border-box);

      &:focus {
        z-index: 2;
      }
    }

    input[type="text"] {
      margin-bottom: -1px;
      border-bottom-left-radius: 0;
      border-bottom-right-radius: 0;
    }

    input[type="password"] {
      margin-bottom: 20px;
      border-top-left-radius: 0;
      border-top-right-radius: 0;
    }
  }
</style>

<body>
  <!-- 這裡是 HTML 語法的 主要資料區 -->
  <!-- <?php echo "IDS Testing System"; ?> -->
  <h1 style="text-align:center; margin-top:50px; margin-bottom:-50px">IDS Testing System</h1>
  <div class="wrapper">
    <form class="form-signin" method="GET">
      <h2 class="form-signin-heading">Search Items</h2>
      <input type="text" class="form-control" name="name" placeholder="Username" required="" autofocus="" />
      <!-- <input type="password" class="form-control" name="password" placeholder="Password" required=""/>       -->
      <label class="checkbox">
        <!-- <input type="checkbox" value="remember-me" id="rememberMe" name="rememberMe"> Remember me -->
      </label>
      <button class="btn btn-lg btn-primary btn-block" type="submit">Submit</button>

    </form>
  </div>
</body>

</html>
```

## 部署 ELK Stack 動態監測log資訊

跟這部分有關連的程式:
1. docker-compose.yml
2. logstash.conf
3. kibana.yml
4. send_to_logstash.py

### 安裝docker
* **啟動容器 (含有Elastic、Logstash、Kibana)：**
`docker-compose up -d`

* **查看運作狀況：**
`docker-compose ps -a`

#### 其他補充
* **使容器停止運行：**
`docker-compose down`

* **刪除容器：**
`docker-compose down -v`

### 機器學習模型與ELK Stack之間的橋樑
* **動態偵測prediction_output.json，若有更新會將資料推上Logstash**
`python send_to_logstash.py`


## 告警系統 (LINE BOT推播)

跟這部分有關連的程式：
1. alert_log_to_line.py
2. ./webhook_line/webhook.py
3. ./test_alert/attack_simulator.py

* **動態偵測ELK Stack，若告警產生，啟動並發送推播至LINE BOT**
`python alert_log_to_line.py`
該程式需替換`CHANNEL_ACCESS_TOKEN`及`USER_ID`。
`CHANNEL_ACCESS_TOKEN`請至https://developers.line.biz/console/ 後臺取得。

* **取得`USER_ID`流程**
下載：https://ngrok.com/ 並註冊取得金鑰

* **開啟ngrok終端：**
`.\ngrok.exe http 5000`
複製ngrok回應的連結，在連結結尾加上/callback，放至https://developers.line.biz/console/ 的 Webhook。

* **取得`USER_ID`：**
`python webhook.py`
傳任意訊息給LINE BOT，會得到`USER_ID`，請將其複製。

* **測試告警系統：**
`python attack_simulator.py`
自動化攻擊腳本，測試告警系統是否作用。

## 專案資料夾結構說明

```
學長的/
├── yzu_nids_project/         # 主體程式與ELK設定
│   ├── MODELS/               # 儲存訓練好的機器學習模型
│   ├── DATA/
│   │   ├── raw_data/         # 原始日誌檔案
│   │   └── labeled_data/     # 標記過的訓練資料
|   |
|   ├── webhook_line/             # LINE webhook 相關程式
│   │   ├── webhook.py            # 取得userId的Flask服務
│   │   └── ReadMe.md             # webhook簡易說明
│   │
│   ├── test_alert/               # 攻擊模擬腳本
│   │   └── attack_simulator.py   # 自動化攻擊腳本
│   │
│   ├── GanacheBlockChain/    # 區塊鏈相關（如有）
│   ├── ...                   # 其他Python程式、設定檔
│   ├── docker-compose.yml    # ELK Stack 容器設定
│   ├── logstash.conf         # Logstash 設定
│   ├── kibana.yml            # Kibana 設定
│   └── README.md             # 使用說明文件
│
├── testing.com/              # 靶機測試網頁
│   └── index.php             # 靶機用PHP頁面
```

> 各資料夾請依實際需求放置對應檔案，詳細用途請參考上方說明。