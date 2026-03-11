import os
import json
import time
import requests
import pandas as pd
import matplotlib.pyplot as plt

# ---------------- НАСТРОЙКИ ----------------

LOG_FILE = "suricata_logs.json"
REPORT_FILE = "security_report.csv"
CHART_FILE = "threat_chart.png"

VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
MAX_IP_CHECKS = 10  # сколько IP проверять через API

API_KEY = os.getenv("VT_API_KEY")

if not API_KEY:
    raise ValueError("Не найден API ключ VirusTotal. Установите переменную VT_API_KEY.")

# ---------------- ЗАГРУЗКА ЛОГОВ ----------------

def load_logs():
    print("[INFO] Загрузка логов...")

    try:
        df = pd.read_json(LOG_FILE)
    except Exception as e:
        print("Ошибка чтения логов:", e)
        return None

    # если есть поле alert — раскрываем его
    if "alert" in df.columns:
        alert_data = pd.json_normalize(df["alert"])
        df = df.drop(columns=["alert"]).join(alert_data)

    # группировка по IP
    summary = df.groupby("src_ip").agg({
        "timestamp": "count",
        "severity": "min"
    }).reset_index()

    summary.rename(columns={"timestamp": "alert_count"}, inplace=True)

    # сортировка по количеству событий
    summary = summary.sort_values(by="alert_count", ascending=False)

    return summary


# ---------------- ПРОВЕРКА VIRUSTOTAL ----------------

def check_ip_virustotal(ip):

    url = VT_API_URL + ip
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:

            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            return malicious, suspicious

        else:
            return 0, 0

    except:
        return 0, 0


# ---------------- АНАЛИЗ ----------------

def analyze(df):

    results = []

    print(f"[INFO] Проверяем максимум {MAX_IP_CHECKS} IP")

    for _, row in df.head(MAX_IP_CHECKS).iterrows():

        ip = row["src_ip"]

        print(f"[INFO] Проверка IP {ip}")

        malicious, suspicious = check_ip_virustotal(ip)

        alert_count = row["alert_count"]
        severity = row["severity"]

        # имитация реагирования
        if malicious > 0 or severity <= 1:
            print(f"[ALERT] Возможная угроза! IP {ip} -> имитация блокировки")

        results.append({
            "ip": ip,
            "alerts": alert_count,
            "severity": severity,
            "vt_malicious": malicious,
            "vt_suspicious": suspicious
        })

        time.sleep(15)  # чтобы не превысить лимит API

    return pd.DataFrame(results)


# ---------------- ОТЧЁТ ----------------

def create_report(df):

    df.to_csv(REPORT_FILE, index=False)

    print("[INFO] Отчёт сохранён:", REPORT_FILE)


# ---------------- ГРАФИК ----------------

def create_chart(df):

    top = df.sort_values(by="alerts", ascending=False).head(5)

    plt.figure(figsize=(8,5))

    plt.bar(top["ip"], top["alerts"])

    plt.title("Top IP по количеству событий")
    plt.xlabel("IP адрес")
    plt.ylabel("Количество событий")

    plt.xticks(rotation=45)

    plt.tight_layout()

    plt.savefig(CHART_FILE)

    print("[INFO] График сохранён:", CHART_FILE)


# ---------------- MAIN ----------------

def main():

    logs = load_logs()

    if logs is None or logs.empty:
        print("Нет данных для анализа")
        return

    analyzed = analyze(logs)

    create_report(analyzed)

    create_chart(analyzed)


if __name__ == "__main__":
    main()