import os
import threading
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Callable
GLOBAL_CREDENTIALS: dict[str, str] = {}

def load_credentials(filepath:str) -> dict[str, str]:
    credentials = {}
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue # skip empty or comment
            if ':' not in line:
                continue # skip invalid line
            system_id,password = line.split(":",1)
            credentials[system_id.strip()] = password.strip()
    return credentials   

class CredentialFileHandler(FileSystemEventHandler):
    def __init__(self, filepath: str, update_callback: Callable[[dict], None]):
        super().__init__()
        self.filepath = os.path.abspath(filepath)
        self.update_callback = update_callback

    def on_modified(self, event):
        if not event.is_directory and os.path.abspath(event.src_path) == self.filepath:
            try:
                new_creds = load_credentials(self.filepath)
                self.update_callback(new_creds)
                logging.getLogger("demo").info("✅ Credentials reloaded from %s", self.filepath)
            except Exception as e:
                logging.getLogger("demo").error("❌ Failed to reload credentials: %s", e)



def start_credential_watcher(filepath: str, update_callback: Callable[[dict], None]):
    observer = Observer()
    handler = CredentialFileHandler(filepath, update_callback)
    observer.schedule(handler, path=os.path.dirname(filepath) or ".", recursive=False)
    observer_thread = threading.Thread(target=observer.start, daemon=True)
    observer_thread.start()
    logging.getLogger("demo").info("Started credential watcher for %s", filepath)