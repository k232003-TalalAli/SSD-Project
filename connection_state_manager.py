import queue
import threading
import time
import builtins
from typing import Dict, List, Optional

import database_helper


class ConnectionStateManager:
    """Thread-safe shared state manager for two-user chat lifecycle."""

    def __init__(
        self,
        poll_interval_seconds: float = 0.75,
        stale_session_timeout_seconds: float = 300.0,
    ) -> None:
        self._user_ips: Dict[str, Optional[str]] = {}
        self._user_session_ids: Dict[str, Optional[str]] = {}
        self._last_seen: Dict[str, float] = {}
        self._chat_in_progress = False
        self._poll_interval_seconds = poll_interval_seconds
        self._stale_session_timeout_seconds = stale_session_timeout_seconds
        self._lock = threading.Lock()
        self._events: Dict[str, queue.Queue[str]] = {}
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start_monitor(self) -> None:
        with self._lock:
            if self._monitor_thread and self._monitor_thread.is_alive():
                return
            self._stop_event.clear()
            self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._monitor_thread.start()

    def stop_monitor(self) -> None:
        self._stop_event.set()

    def register_event_consumer(self, username: str) -> None:
        with self._lock:
            if username not in self._events:
                self._events[username] = queue.Queue()

    def connect_user(self, username: str, ip_address: str, session_id: str) -> None:
        with self._lock:
            self._user_ips[username] = ip_address
            self._user_session_ids[username] = session_id
            self._last_seen[username] = time.time()

    def heartbeat(self, username: str, session_id: str) -> None:
        with self._lock:
            tracked_session_id = self._user_session_ids.get(username)
            if tracked_session_id != session_id:
                return
            self._last_seen[username] = time.time()

    def disconnect_user(self, username: str, session_id: str) -> None:
        account_id = database_helper.get_account_id_by_username(username)
        with self._lock:
            tracked_session_id = self._user_session_ids.get(username)
            if tracked_session_id != session_id:
                return
            self._user_ips[username] = None
            self._user_session_ids[username] = None
            self._last_seen[username] = 0.0
            if not any(ip for ip in self._user_ips.values()):
                self._chat_in_progress = False

        if account_id is not None:
            database_helper.update_ip_address(account_id, None)

    def force_disconnect_user(self, username: str) -> None:
        account_id = database_helper.get_account_id_by_username(username)
        with self._lock:
            self._user_ips[username] = None
            self._user_session_ids[username] = None
            self._last_seen[username] = 0.0

        if account_id is not None:
            database_helper.update_ip_address(account_id, None)

    def consume_events(self, username: str) -> List[str]:
        pending: List[str] = []
        with self._lock:
            event_queue = self._events.get(username)
            if event_queue is None:
                return pending

            while not event_queue.empty():
                pending.append(event_queue.get_nowait())
        return pending

    def get_snapshot(self) -> Dict[str, Dict[str, Optional[str]]]:
        with self._lock:
            return {
                "ips": dict(self._user_ips),
                "session_ids": dict(self._user_session_ids),
                "chat_in_progress": self._chat_in_progress,
            }

    def _emit_to_user(self, username: str, event_name: str) -> None:
        event_queue = self._events.get(username)
        if event_queue is not None:
            event_queue.put_nowait(event_name)

    def _emit_to_all(self, event_name: str) -> None:
        for username in self._events:
            self._emit_to_user(username, event_name)

    def _monitor_loop(self) -> None:
        while not self._stop_event.is_set():
            users_to_expire: List[str] = []
            with self._lock:
                now = time.time()
                for username, session_id in self._user_session_ids.items():
                    if not session_id:
                        continue
                    last_seen = self._last_seen.get(username, 0.0)
                    if now - last_seen > self._stale_session_timeout_seconds:
                        self._user_ips[username] = None
                        self._user_session_ids[username] = None
                        self._last_seen[username] = 0.0
                        users_to_expire.append(username)

                active_users = [user for user, ip in self._user_ips.items() if ip]
                active_count = len(active_users)

                if active_count < 2:
                    if self._chat_in_progress:
                        self._chat_in_progress = False
                    pass

                elif not self._chat_in_progress:
                    self._chat_in_progress = True
                    self._emit_to_all("show_chat")

                else:
                    pass

            for username in users_to_expire:
                account_id = database_helper.get_account_id_by_username(username)
                if account_id is not None:
                    database_helper.update_ip_address(account_id, None)

            time.sleep(self._poll_interval_seconds)


def get_connection_manager() -> ConnectionStateManager:
    singleton_name = "_streamlit_chat_connection_manager_singleton"
    manager = getattr(builtins, singleton_name, None)
    if manager is None:
        manager = ConnectionStateManager()
        setattr(builtins, singleton_name, manager)
    return manager
