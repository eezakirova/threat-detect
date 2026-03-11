import os
import json
import time
import requests
import pandas as pd
import matplotlib.pyplot as plt

# --- НАСТРОЙКИ ---
LOG_FILE = 'suricata_logs.json'
REPORT_FILE = 'security_report.csv'
CHART_FILE = 'threat_analysis.png'
VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

# Получаем ключ из переменной окружения
API_KEY = os.getenv('VT_API_KEY')

if not API_KEY:
    raise ValueError("ОШИБКА: Переменная окружения VT_API_KEY не найдена. Установите её перед запуском.")


# 1. ЗАГРУЗКА И ПОДГОТОВКА ЛОГОВ
def load_and_process_logs():
    print(f"[INFO] Чтение логов из {LOG_FILE}...")
    try:
        df = pd.read_json(LOG_FILE)
    except ValueError as e:
        print(f"[ERROR] Не удалось прочитать JSON: {e}")
        return None
    except FileNotFoundError:
        print(f"[ERROR] Файл {LOG_FILE} не найден.")
        return None

    # Нормализация данных (извлечение данных из вложенного поля 'alert')
    # Если в логах есть поле alert, раскрываем его в отдельные колонки
    if 'alert' in df.columns:
        alerts_df = pd.json_normalize(df['alert'])
        df = df.drop(columns=['alert']).join(alerts_df)

    # Группируем по IP-адресу источника
    # Считаем количество запросов и берем последнюю сигнатуру и категорию
    summary = df.groupby('src_ip').agg({
        'timestamp': 'count',
        'signature': 'last',
        'severity': 'min'  # берем самую критичную оценку (обычно 1 - самая высокая)
    }).reset_index()

    summary.rename(columns={'timestamp': 'alert_count'}, inplace=True)
    return summary


# 2. ПРОВЕРКА ЧЕРЕЗ API VIRUSTOTAL
def check_virustotal(ip):
    """
    Отправляет запрос к VirusTotal API v3 для проверки IP.
    """
    url = f"{VT_API_URL}{ip}"
    headers = {
        "x-apikey": API_KEY
    }

    print(f"[API] Проверка IP: {ip} ...", end=" ")

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            attributes = data['data']['attributes']

            # Извлекаем статистику
            stats = attributes['last_analysis_stats']
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            country = attributes.get('country', 'Unknown')

            print(f"OK (Malicious: {malicious_count})")
            return {
                "vt_malicious": malicious_count,
                "vt_suspicious": suspicious_count,
                "country": country
            }

        elif response.status_code == 429:
            print("LIMIT EXCEEDED (Слишком много запросов)")
            return {"vt_malicious": 0, "vt_suspicious": 0, "country": "RateLimit"}
        elif response.status_code == 404:
            print("NOT FOUND (IP не найден в базе)")
            return {"vt_malicious": 0, "vt_suspicious": 0, "country": "Unknown"}
        else:
            print(f"ERROR: {response.status_code}")
            return {"vt_malicious": 0, "vt_suspicious": 0, "country": "Error"}

    except Exception as e:
        print(f"EXCEPTION: {e}")
        return {"vt_malicious": 0, "vt_suspicious": 0, "country": "Error"}


# 3. АНАЛИЗ И РЕАГИРОВАНИЕ
def analyze_threats(df):
    results = []

    # VirusTotal Free API имеет ограничение запросов в минуту.
    # Добавляем задержку, чтобы скрипт не падал с ошибкой 429.
    print("[INFO] Начало проверки IP через VirusTotal (с задержкой для Free API)...")

    for index, row in df.iterrows():
        ip = row['src_ip']
        vt_data = check_virustotal(ip)

        # Объединяем данные из логов и API
        row_data = row.to_dict()
        row_data.update(vt_data)
        results.append(row_data)
        # ПРОСТОЕ РЕАГИРОВАНИЕ
        is_high_risk_log = row['severity'] <= 1
        is_malicious_api = vt_data['vt_malicious'] > 0

        if is_malicious_api or is_high_risk_log:
            print(
                f"   >>> [ALERT] БЛОКИРОВКА ТРАФИКА: {ip} (VT Score: {vt_data['vt_malicious']}, Log Severity: {row['severity']})")

        # Пауза 15 секунд между запросами
        time.sleep(15)

    return pd.DataFrame(results)


# 4. ВИЗУАЛИЗАЦИЯ
def create_report(df):
    # Сохранение CSV
    df.to_csv(REPORT_FILE, index=False)
    print(f"\n[INFO] Отчет сохранен в {REPORT_FILE}")

    # Построение графика
    plt.figure(figsize=(10, 6))

    # Данные для графика
    ips = df['src_ip']
    counts = df['alert_count']
    malicious_scores = df['vt_malicious']

    # Цвет столбца: Красный, если VT нашел угрозу, иначе Синий
    colors = ['red' if score > 0 else 'skyblue' for score in malicious_scores]

    bars = plt.bar(ips, counts, color=colors)

    plt.title('Активность IP-адресов и статус угроз VirusTotal')
    plt.xlabel('Source IP')
    plt.ylabel('Количество событий в логах')
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Добавляем легенду вручную для цветов
    from matplotlib.patches import Patch
    legend_elements = [Patch(facecolor='skyblue', label='Clean/Unknown'),
                       Patch(facecolor='red', label='Malicious (VirusTotal)')]
    plt.legend(handles=legend_elements)

    plt.savefig(CHART_FILE)
    print(f"[INFO] График сохранен в {CHART_FILE}")


# --- ЗАПУСК ---
if __name__ == "__main__":
    # 1. Загрузка
    logs_summary = load_and_process_logs()

    if logs_summary is not None and not logs_summary.empty:
        # 2 & 3. Анализ API и Реагирование
        final_df = analyze_threats(logs_summary)

        # 4. Отчет
        create_report(final_df)
    else:
        print("[WARN] Нет данных для анализа.")