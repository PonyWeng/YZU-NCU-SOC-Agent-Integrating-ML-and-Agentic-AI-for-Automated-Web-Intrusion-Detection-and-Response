# YZU_NIDS_project


* **本專案使用的環境與套件版本：**
    * Python 3.8.13
        * scikit-learn 1.3.0
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

## 本專案所使用的幾個程式

1. process.py
2. train.py
3. predict.py
4. monitor.py

* **訓練資料前處理指令：**
`python process.py -l C:\Users\pony7\Desktop\IDS_yzu\yzu_nids_project\DATA\raw_data\access.log -d C:\Users\pony7\Desktop\IDS_yzu\yzu_nids_project\DATA\raw_data\0830.log`

* **模型訓練指令**
`python train.py -l C:\Users\pony7\Desktop\IDS_yzu\yzu_nids_project\DATA\labeled_data\dataset-data-imblance.csv`

* **模型預測指令**
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