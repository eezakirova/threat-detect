import os


# --- НАСТРОЙКИ ---
LOG_FILE = 'suricata_logs.json'
REPORT_FILE = 'security_report.csv'
CHART_FILE = 'threat_analysis.png'
VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

# Получаем ключ из переменной окружения
API_KEY = os.getenv('VT_API_KEY')

if not API_KEY:
    raise ValueError("ОШИБКА: Переменная окружения VT_API_KEY не найдена. Установите её перед запуском.")
