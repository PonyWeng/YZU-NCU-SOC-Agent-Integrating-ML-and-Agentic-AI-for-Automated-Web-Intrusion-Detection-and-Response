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