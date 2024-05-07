import json
import requests
import re
import time
import threading
import logging

# Nastavení logování
logging.basicConfig(filename='monitoring.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(json_path):
    """Načte konfigurační data z JSON souboru."""
    with open(json_path, 'r') as file:
        data = json.load(file)
    return data['monitoring_rules']

def process_rules(rules):
    """Zpracuje pravidla a hledá logy pro každého hostitele."""
    for rule in rules:
        for host in rule['hosts']:
            print(f"Processing {rule['name']} on {host}")
            found_logs = search_logs(rule['log_path'], rule['log_condition'])
            if found_logs:
                print(f"Alert for {host}: {rule['message']}")


def search_logs(log_path, search_conditions):
    """Prohledá log soubor na základě seznamu hledaných podmínek, které mohou být termíny nebo regulární výrazy."""
    try:
        with open(log_path, 'r', encoding='utf-8') as file:
            logs = file.readlines()
    except FileNotFoundError:
        print(f"Log file not found: {log_path}")
        return []
    
    results = []
    for condition in search_conditions:
        pattern = re.compile(condition)
        results.extend([line for line in logs if pattern.search(line)])
    return results

def monitor_rule(rule):
    """Vyhodnotí, zda podmínky pro odeslání alertu byly splněny."""
    alert_history = []
    while True:
        start_time = time.time()
        found_logs = search_logs(rule['log_path'], rule['search_conditions'])
        current_time = time.time()
        alert_needed = False

        if rule['alerting_strategy']['type'] == "immediate":
            alert_needed = bool(found_logs)
        elif rule['alerting_strategy']['type'] == "delayed":
            alert_history.extend([(log, current_time) for log in found_logs])
            alert_history = [(log, timestamp) for log, timestamp in alert_history if current_time - timestamp < rule['alerting_strategy']['delay']]
            if found_logs and any(current_time - timestamp < rule['alerting_strategy']['delay'] for _, timestamp in alert_history):
                alert_needed = True
        elif rule['alerting_strategy']['type'] == "cumulative":
            alert_history.extend([(log, current_time) for log in found_logs])
            alert_history = [(log, timestamp) for log, timestamp in alert_history if current_time - timestamp < rule['alerting_strategy']['delay']]
            if len(alert_history) >= rule['alerting_strategy']['threshold']:
                alert_needed = True

        if alert_needed:
            print(f"ALERT: {rule['name']} on {rule['hosts']}: {rule['message']} - Priority: {rule['priority']}")
        else:
            print(f"No alert triggered for {rule['name']} on {rule['hosts']}")

        elapsed = time.time() - start_time
        time.sleep(max(1 - elapsed, 0))  # Ensure that we wait at least 1 second

def send_to_opsgenie(rule, found_logs, api_key):
    url = "https://api.opsgenie.com/v2/alerts"
    headers = {
        "Authorization": "GenieKey " + api_key,
        "Content-Type": "application/json"
    }

    if found_logs:  # Only send alert if there are logs
        message = f"Alert for {rule['name']}: {len(found_logs)} occurrences found."
        post_data = {
            "message": message,
            "alias": rule['name'],
            "description": "\n".join(found_logs),
            "priority": rule['priority']  # Nasetovana priorina na urovni JSONu
        }
        response = requests.post(url, headers=headers, json=post_data, timeout=5)
        logging.info(f"Sent alert for {rule['name']}. Status Code: {response.status_code}")
    else:
        logging.info(f"No logs found to trigger alert for {rule['name']}.")       

def main():
    json_path = 'config.json'
    rules = load_config(json_path)
    threads = []
    for rule in rules:
        thread = threading.Thread(target=monitor_rule, args=(rule,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
