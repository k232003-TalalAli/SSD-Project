import queue
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class SharedConnectionState:
    user1_ip: Optional[str] = None
    user2_ip: Optional[str] = None
    user1_session_id: Optional[str] = None
    user2_session_id: Optional[str] = None
    chat_in_progress: bool = False


class ConnectionStateManager:
    """Thread-safe shared state manager for two-user chat lifecycle."""

    def __init__(self, poll_interval_seconds: float = 0.75) -> None:
        self._state = SharedConnectionState()
        self._poll_interval_seconds = poll_interval_seconds
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
            if username == "user1":
                self._state.user1_ip = ip_address
                self._state.user1_session_id = session_id
            elif username == "user2":
                self._state.user2_ip = ip_address
                self._state.user2_session_id = session_id

    def disconnect_user(self, username: str, session_id: str) -> None:
        with self._lock:
            if username == "user1" and self._state.user1_session_id == session_id:
                self._state.user1_ip = None
                self._state.user1_session_id = None
            elif username == "user2" and self._state.user2_session_id == session_id:
                self._state.user2_ip = None
                self._state.user2_session_id = None

    def consume_events(self, username: str) -> List[str]:
        pending: List[str] = []
        with self._lock:
            event_queue = self._events.get(username)
            if event_queue is None:
                return pending

            while not event_queue.empty():
                pending.append(event_queue.get_nowait())
        return pending

    def get_snapshot(self) -> SharedConnectionState:
        with self._lock:
            return SharedConnectionState(
                user1_ip=self._state.user1_ip,
                user2_ip=self._state.user2_ip,
                user1_session_id=self._state.user1_session_id,
                user2_session_id=self._state.user2_session_id,
                chat_in_progress=self._state.chat_in_progress,
            )

    def _emit_to_user(self, username: str, event_name: str) -> None:
        event_queue = self._events.get(username)
        if event_queue is not None:
            event_queue.put_nowait(event_name)

    def _emit_to_all(self, event_name: str) -> None:
        for username in self._events:
            self._emit_to_user(username, event_name)

    def _monitor_loop(self) -> None:
        while not self._stop_event.is_set():
            with self._lock:
                user1_ip = self._state.user1_ip
                user2_ip = self._state.user2_ip
                chat_in_progress = self._state.chat_in_progress

                both_none = user1_ip is None and user2_ip is None
                both_present = user1_ip is not None and user2_ip is not None
                one_missing = (user1_ip is None) != (user2_ip is None)

                # Both are None -> do nothing
                if both_none:
                    pass

                # Both are not None and chatInProgress=False -> start chat
                elif both_present and not chat_in_progress:
                    self._state.chat_in_progress = True
                    self._emit_to_all("show_chat")

                # Both are not None and chatInProgress=True -> do nothing
                elif both_present and chat_in_progress:
                    pass

                # One is None and chatInProgress=True -> close chat for both
                elif one_missing and chat_in_progress:
                    self._state.chat_in_progress = False
                    self._state.user1_ip = None
                    self._state.user2_ip = None
                    self._state.user1_session_id = None
                    self._state.user2_session_id = None
                    self._emit_to_all("close_chat")

                # One is None and chatInProgress=False -> do nothing
                else:
                    pass

            time.sleep(self._poll_interval_seconds)


_manager_singleton = ConnectionStateManager()


def get_connection_manager() -> ConnectionStateManager:
    return _manager_singleton
