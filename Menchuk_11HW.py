import pandas as pd
import json
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

file_path = r'C:\Users\idmit\Downloads\botsv1.json'

try:
    # Попытка чтения как JSON lines 
    df = pd.read_json(file_path, lines=True)
except ValueError:
    try:
        
        df = pd.read_json(file_path)
    except ValueError:
        df = pd.DataFrame()

if df.empty:
    print("В файле не найдено корректных JSON-объектов.")
else:
    
    if 'result' in df.columns:
        df = pd.json_normalize(df['result'].tolist())

    print("Первые строки DataFrame:")
    print(df.head())

    # Этап 2. Анализ данных

    if 'EventCode' in df.columns:
        suspicious_event_ids = [4625, 4648, 4672, 4673, 4674, 4688, 4720, 4732, 4738, 4768, 4769, 4770, 4771, 4776]
        suspicious_events = df[df['EventCode'].isin(suspicious_event_ids)]
        print("\nПодозрительные события WinEventLog:")
        print(suspicious_events.head())
    else:
        print("\nКолонка EventCode не найдена в данных.")

    # Анализ DNS-логов
    if 'query' in df.columns:
        domain_counts = Counter(df['query'].dropna())
        rare_domains = {domain: count for domain, count in domain_counts.items() if count < 5}
        print("\nРедкие домены:")
        for domain, count in list(rare_domains.items())[:10]:
            print(f"{domain}: {count}")

        suspicious_subdomains = df[df['query'].str.contains(r'\.\w+\.\w+', regex=True, na=False)]
        print("\nПодозрительные поддомены:")
        print(suspicious_subdomains['query'].head(10))
    else:
        print("\nКолонка query не найдена в данных.")

    # Этап 3. Визуализация данных

    # Визуализация топ-10 подозрительных событий WinEventLog
    if 'EventCode' in df.columns:
        event_counts = df['EventCode'].value_counts().head(10)
        plt.figure(figsize=(10, 6))
        sns.barplot(x=event_counts.index, y=event_counts.values, palette='viridis')
        plt.title('Топ-10 событий WinEventLog')
        plt.xlabel('EventCode')
        plt.ylabel('Количество событий')
        plt.show()

    # Визуализация топ-10 редких доменов
    if 'query' in df.columns:
        domain_counts = pd.Series(domain_counts)
        rare_domains_series = domain_counts.sort_values().head(10)
        plt.figure(figsize=(10, 6))
        sns.barplot(x=rare_domains_series.index, y=rare_domains_series.values, palette='rocket')
        plt.title('Топ-10 редких доменов')
        plt.xlabel('Домен')
        plt.ylabel('Количество запросов')
        plt.xticks(rotation=45)
        plt.show()
