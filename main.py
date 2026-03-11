import os
import pandas as pd

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