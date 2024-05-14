import json
import aiohttp 
import asyncio
import re
import logging
from watchdog.observers import Observer 
from watchdog.events import FileSystemEventHandler 
import aiofiles 
import time

# Nastavení logování
logging.basicConfig(
    filename='monitoring.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Vytvoření loggeru
logger = logging.getLogger()

# Příklad použití různých úrovní logování
logger.info('Toto je informační zpráva.')
logger.warning('Toto je varování.')
logger.error('Toto je chyba.')

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, rule, api_key):
        self.rule = rule
        self.api_key = api_key
        self.logs = []

    async def on_modified(self, event):
        """Asynchronní handler, který reaguje na změny v souboru."""
        if not event.is_directory and event.src_path == self.rule['log_path']:
            await self.process_logs()

    async def process_logs(self):
        """Asynchronně zpracuje logy a vyhodnotí, zda je třeba poslat alert."""
        async with aiofiles.open(self.rule['log_path'], mode='r') as file:
            async for line in file:
                if re.search(self.rule['search_conditions'], line):
                    self.logs.append(line)
        alert_needed = await evaluate_alert_needed(self.rule, self.logs)
       # if alert_needed:
            #await send_to_opsgenie(self.rule, self.logs, self.api_key)

def evaluate_alert_needed(self, found_logs):
    """Prohledá log soubor na základě seznamu hledaných podmínek, které mohou být termíny nebo regulární výrazy."""
    while True:
        found_logs = (self.rule['log_path'], self.rule['search_conditions'])
        current_time = time.time()
        alert_needed = False

        if self.rule['alerting_strategy']['type'] == "immediate": # Find an error and trigger an alert.
            alert_needed = bool(found_logs)
        elif self.rule['alerting_strategy']['type'] == "delayed": # Find an error and wait (specified time in JSON), if another error occurs, trigger an alert
            alert_history.extend([(log, current_time) for log in found_logs])
            alert_history = [(log, timestamp) for log, timestamp in alert_history if current_time - timestamp < self.rule['alerting_strategy']['delay']]
            if found_logs and any(current_time - timestamp < self.rule['alerting_strategy']['delay'] for _, timestamp in alert_history):
                alert_needed = True
        elif self.rule['alerting_strategy']['type'] == "cumulative": # Find an error and if (specified number in JSON) errors arrive within (specified time in JSON), trigger an alert.
            alert_history.extend([(log, current_time) for log in found_logs])
            alert_history = [(log, timestamp) for log, timestamp in alert_history if current_time - timestamp < self.rule['alerting_strategy']['delay']]
            if len(alert_history) >= self.rule['alerting_strategy']['threshold']:
                alert_needed = True

        if alert_needed:
            print(f"ALERT: {self.rule['name']} on {self.rule['hosts']}: {self.rule['message']} - Priority: {self.rule['priority']}")
        else:
            print(f"No alert triggered for {self.rule['name']} on {self.rule['hosts']}")


async def send_to_opsgenie(rule, found_logs, api_key):
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
            "priority": rule['priority']  # Priority set at the JSON level.

        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=post_data, timeout=30) as response:
                logging.info(f"Sent alert for {rule['name']}. Status Code: {await response.status()}")
    else:
        logging.info(f"No logs found to trigger alert for {rule['name']}.")       

async def monitor():
    """Hlavní monitorovací funkce."""
    json_path = 'matice.json'
    with open(json_path, 'r') as file:
        data = json.load(file)
    rules = data['monitoring_rules']
    api_key = data['api_key']

    observers = []
    for rule in rules:
        handler = LogFileHandler(rule, api_key)
        observer = Observer()
        observer.schedule(handler, path=rule['log_path'], recursive=False)
        observer.start()
        observers.append(observer)

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        for observer in observers:
            observer.stop()
        for observer in observers:
            observer.join()


if __name__ == "__main__":
    asyncio.run(monitor())
