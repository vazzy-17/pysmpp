# credential.py
import asyncio
import logging
from typing import Dict
from server.db import DB

GLOBAL_CREDENTIALS: Dict[str,str] = {}

async def load_credentials(db:DB) -> Dict[str,str]:
    credentials = {}
    async with db.pool.acquire()as conn:
        rows = await conn.fetch("select username, password from account where active = true")
        for row in rows:
            try:
                credentials[row["username"]] = row["password"]
            except Exception as e:
                logging.warning(f"Gagal decode password dari akun {row['username']}:{e}")
                print("✅ Loaded credentials from DB:", credentials)
    return credentials

def apply_new_credentials(new_creds: dict):
    GLOBAL_CREDENTIALS.clear()
    GLOBAL_CREDENTIALS.update(new_creds)
    logging.getLogger("demo").info("Credentials reloaded from DB")


























# # credential_watcher.py
# import os
# import threading
# import logging
# from watchdog.observers import Observer
# from watchdog.events import FileSystemEventHandler
# from typing import Callable
# GLOBAL_CREDENTIALS: dict[str, str] = {}



# def load_credentials(filepath:str) -> dict[str, str]:
#     credentials = {}
#     with open(filepath, "r", encoding="utf-8") as f:
#         for line in f:
#             line = line.strip()
#             if not line or line.startswith("#"):
#                 continue # skip empty or comment
#             if ':' not in line:
#                 continue # skip invalid line
#             system_id,password = line.split(":",1)
#             credentials[system_id.strip()] = password.strip()
#     return credentials   

# class CredentialFileHandler(FileSystemEventHandler):
#     def __init__(self, filepath: str, update_callback: Callable[[dict], None]):
#         super().__init__()
#         self.filepath = os.path.abspath(filepath)
#         self.update_callback = update_callback

#     def on_modified(self, event):
#         if not event.is_directory and os.path.abspath(event.src_path) == self.filepath:
#             try:
#                 new_creds = load_credentials(self.filepath)
#                 self.update_callback(new_creds)
#                 logging.getLogger("demo").info("✅ Credentials reloaded from %s", self.filepath)
#             except Exception as e:
#                 logging.getLogger("demo").error("❌ Failed to reload credentials: %s", e)



# def start_credential_watcher(filepath: str, update_callback: Callable[[dict], None]):
#     observer = Observer()
#     handler = CredentialFileHandler(filepath, update_callback)
#     observer.schedule(handler, path=os.path.dirname(filepath) or ".", recursive=False)
#     observer_thread = threading.Thread(target=observer.start, daemon=True)
#     observer_thread.start()
#     logging.getLogger("demo").info("Started credential watcher for %s", filepath)