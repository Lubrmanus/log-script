import json
import re
import requests

def load_terms_and_patterns(json_path):
    """ Načte hledané termíny a regulární výrazy z JSON souboru. """
    with open(json_path, 'r') as file:
        data = json.load(file)
    search_terms = data['search_terms']
    search_patterns = data['search_patterns']
    return search_terms, search_patterns

def search_logs(log_path, search_terms, search_patterns):
    """ Prohledá log soubor na základě seznamu hledaných termínů a regulárních výrazů. """
    with open(log_path, 'r', encoding='utf-8') as file:
        logs = file.readlines()
    
    results = {term: [] for term in search_terms}
    for term in search_terms:
        results[term] = [line for line in logs if term in line]
    
    for pattern in search_patterns:
        compiled_pattern = re.compile(pattern)
        results[pattern] = [line for line in logs if compiled_pattern.search(line)]
    
    return results

def send_to_opsgenie(alerts, api_key):
    url = "https://api.opsgenie.com/v2/alerts"
    headers = {
        "Authorization": "GenieKey " + api_key,
        "Content-Type": "application/json"
    }
    
    for alert, messages in alerts.items():
        if messages:  # Only send alert if there are messages
            message = f"Alert for {alert}: {len(messages)} occurrences found."
            post_data = {
                "message": message,
                "alias": alert,
                "description": "\n".join(messages),
                "priority": "P3"  # Set priority as needed
            }
            response = requests.post(url, headers=headers, json=post_data)
            print(f"Sent alert for {alert}. Status Code: {response.status_code}")

def main():
    json_path = 'search_config.json'
    log_path = 'example.log'
    api_key = 'your_opsgenie_api_key_here'
    
    search_terms, search_patterns = load_terms_and_patterns(json_path)
    search_results = search_logs(log_path, search_terms, search_patterns)
    
    send_to_opsgenie(search_results, api_key)

if __name__ == "__main__":
    main()
