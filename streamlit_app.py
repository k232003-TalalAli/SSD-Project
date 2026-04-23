import atexit
import builtins
import hmac
import importlib
import ipaddress
import secrets
import socket
import threading
import time

import streamlit as st

from connection_state_manager import get_connection_manager
import database_helper
import msg_security

try:
    _autorefresh_module = importlib.import_module("streamlit_autorefresh")
    st_autorefresh = _autorefresh_module.st_autorefresh
except ImportError:
    st_autorefresh = None


_SYNC_THREAD_ATTR = "_cache_sync_thread"
def _all_ips_active() -> bool:
    """True if every known account has a non-null IP in the local cache."""
    try:
        ids = database_helper.get_all_account_ids()
        if not ids:
            return False
        return all(database_helper.get_ip_address(aid) for aid in ids)
    except Exception:
        return False


def _active_ip_count() -> int:
    """
    Always refresh cache from DB first, then count active IPs from local temp.
    This avoids per-process stale cache causing one user to stay in waiting.
    """
    try:
        database_helper.cache_data()
    except Exception:
        pass

    try:
        return sum(
            1
            for aid in database_helper.get_all_account_ids()
            if database_helper.get_ip_address(aid)
        )
    except Exception:
        return 0


def is_other_user_connected() -> bool:
    """
    Fetch fresh data from the database, then check whether the other user
    (everyone except the currently logged-in user) has a non-null IP address.

    Returns True  — other user is still connected.
    Returns False — other user's IP is None (disconnected or never joined).

    Intended use: call this before allowing a message to be sent so we never
    write into a chat session where the other side has already gone away.
    """
    try:
        database_helper.cache_data()
    except Exception:
        return False

    my_account_id = st.session_state.get("account_id", "")

    try:
        all_ids = database_helper.get_all_account_ids()
    except Exception:
        return False

    for account_id in all_ids:
        if account_id == my_account_id:
            continue  # skip ourselves
        ip = database_helper.get_ip_address(account_id)
        if not ip:
            return False  # other user has no active IP
    return True


def _start_cache_sync_thread() -> None:
    """
    Spawn a daemon thread (once per process) that refreshes the local
    temp-file cache from Firebase every second until both users have active IPs.
    Safe to call on every Streamlit rerun — no-op if already running.
    """
    existing: threading.Thread | None = getattr(builtins, _SYNC_THREAD_ATTR, None)
    if existing is not None and existing.is_alive():
        return  # already running

    def _sync_loop() -> None:
        while True:
            try:
                if _all_ips_active():
                    break  # both connected — stop hitting Firebase
                database_helper.cache_data()
            except Exception:
                pass
            time.sleep(1.0)
        setattr(builtins, _SYNC_THREAD_ATTR, None)  # allow restart later

    t = threading.Thread(target=_sync_loop, daemon=True, name="cache-sync")
    setattr(builtins, _SYNC_THREAD_ATTR, t)
    t.start()


def _stop_cache_sync_thread() -> None:
    """Clear the thread reference (daemon will die on its own)."""
    setattr(builtins, _SYNC_THREAD_ATTR, None)


# ─────────────────────────────────────────────────────────────────────────────

def apply_blue_dark_theme() -> None:
    st.markdown(
        """
        <style>
            :root {
                --bg-main: #1a2f4d;
                --bg-panel: #2a4066;
                --bg-input: #3a5580;
                --text-main: #f0f4ff;
                --text-muted: #b8cde8;
                --accent: #4a8fff;
                --accent-2: #7ab5ff;
                --border: #4a6fa3;
            }

            .stApp {
                background:
                    radial-gradient(1200px 500px at 20% -10%, #2d5a8f 0%, transparent 60%),
                    radial-gradient(900px 420px at 95% 0%, #234a75 0%, transparent 58%),
                    linear-gradient(180deg, #1a2f4d 0%, #1d3a54 100%);
                color: var(--text-main);
            }

            [data-testid="stHeader"] {
                background: rgba(26, 47, 77, 0.8);
                border-bottom: 1px solid rgba(74, 143, 255, 0.25);
            }

            h1, h2, h3, p, label {
                color: var(--text-main) !important;
            }

            .stTextInput > div > div > input {
                background-color: var(--bg-input) !important;
                color: var(--text-main) !important;
                border: 1px solid var(--border) !important;
            }

            .stTextInput > label {
                color: var(--text-muted) !important;
            }

            .stButton > button {
                background: linear-gradient(135deg, var(--accent), var(--accent-2)) !important;
                color: #ffffff !important;
                border: 1px solid #8ab4ff !important;
                border-radius: 10px !important;
                font-weight: 600 !important;
            }

            .stButton > button:hover {
                filter: brightness(1.12);
            }

            .stSuccess, .stInfo, .stWarning, .stError {
                background-color: rgba(42, 64, 102, 0.9) !important;
                border: 1px solid var(--border) !important;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def get_local_ip_address() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
    ipaddress.ip_address(ip)
    return ip


def secure_username_check(username: str) -> bool:
    return database_helper.get_account_id_by_username(username) is not None


def secure_password_check(account_id: str, chat_password: str) -> bool:
    if len(chat_password) < 1 or len(chat_password) > 128:
        return False
    stored_hash = database_helper.get_password(account_id)
    if not stored_hash:
        return False
    entered_hash = msg_security.hash_data(chat_password)
    return hmac.compare_digest(entered_hash, stored_hash)


def show_chat_screen() -> None:
    st.session_state["chat_open"] = True
    st.session_state["status_message"] = ""


def close_chat() -> None:
    st.session_state["chat_open"] = False


def init_session_state() -> None:
    defaults = {
        "connected": False,
        "chat_open": False,
        "username": "",
        "account_id": "",
        "status_message": "",
        "login_error": "",
        "session_id": secrets.token_hex(16),
        "manager_started": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def process_events() -> bool:
    """Process queued events. Returns True if a rerun is needed."""
    username = st.session_state.get("username", "")
    if not username:
        return False
    manager = get_connection_manager()
    events = manager.consume_events(username)
    needs_rerun = False
    for event_name in events:
        if event_name == "show_chat":
            show_chat_screen()
            needs_rerun = True
        elif event_name == "close_chat":
            close_chat()
            needs_rerun = True
    return needs_rerun


def render_waiting_state() -> None:
    st.markdown(
        """
        <style>
            .wait-wrap {
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                margin-top: 2rem;
            }
            .loader {
                width: 72px;
                height: 72px;
                border: 7px solid #d8e2f0;
                border-top: 7px solid #1f77b4;
                border-radius: 50%;
                animation: spin 1.1s linear infinite;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            .wait-text {
                margin-top: 1rem;
                font-size: 1.15rem;
                font-weight: 600;
            }
        </style>
        <div class="wait-wrap">
            <div class="loader"></div>
            <div class="wait-text">Waiting for other user...</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_chat_screen() -> None:
    st.success("Secure chat is connected")
    st.write("Chat UI placeholder: hook your existing encrypted socket chat screen here.")

    if st.button("Disconnect", type="secondary"):
        manager = get_connection_manager()
        account_id = st.session_state.get("account_id")
        if account_id:
            try:
                database_helper.update_ip_address(account_id, None)
            except Exception:
                pass
        manager.disconnect_user(st.session_state["username"], st.session_state["session_id"])
        _stop_cache_sync_thread()
        close_chat()
        st.session_state["connected"] = False
        st.session_state["username"] = ""
        st.session_state["account_id"] = ""
        st.session_state["status_message"] = "You disconnected"
        st.rerun()


def connect_user(username: str, chat_password: str) -> None:
    st.session_state["login_error"] = ""
    username = username.strip()

    try:
        database_helper.cache_data()
    except Exception:
        st.session_state["login_error"] = "Could not load user data. Please try again."
        return

    if not secure_username_check(username):
        st.session_state["login_error"] = "Invalid username."
        return

    account_id = database_helper.get_account_id_by_username(username)
    if account_id is None:
        st.session_state["login_error"] = "Invalid username."
        return

    if not secure_password_check(account_id, chat_password):
        st.session_state["login_error"] = "Invalid chat password."
        return

    try:
        ip_address = get_local_ip_address()
    except (OSError, ValueError):
        st.session_state["login_error"] = "Could not resolve local IP address."
        return

    manager = get_connection_manager()
    manager.register_event_consumer(username)
    try:
        database_helper.update_ip_address(account_id, ip_address)
        manager.connect_user(username, ip_address, st.session_state["session_id"])
    except Exception:
        st.session_state["login_error"] = "Could not connect right now. Please try again."
        return

    st.session_state["username"] = username
    st.session_state["account_id"] = account_id
    st.session_state["connected"] = True
    st.session_state["status_message"] = ""
    st.session_state["login_error"] = ""


def render_welcome_page() -> None:
    st.title("Secure End-to-End Encrypted Chat")
    st.write("Enter your details to connect securely.")

    if st.session_state["status_message"]:
        st.info(st.session_state["status_message"])
    if st.session_state["login_error"]:
        st.error(st.session_state["login_error"])

    username_input = st.text_input("Username", max_chars=20, autocomplete="off")
    password_input = st.text_input("Chat Password", type="password", max_chars=128)

    if st.button("Connect", type="primary"):
        connect_user(username_input, password_input)
        st.rerun()


def refresh_for_connection_polling(key: str) -> None:
    if st_autorefresh is not None:
        st_autorefresh(interval=750, key=key)
        return

    st.markdown(
        """
        <script>
            setTimeout(function() {
                window.location.reload();
            }, 1000);
        </script>
        """,
        unsafe_allow_html=True,
    )


def render_waiting_refresh_button() -> None:
    if st.button("Refresh status", key="waiting_refresh_button"):
        st.rerun()


def cleanup_current_session() -> None:
    try:
        username = st.session_state.get("username")
        session_id = st.session_state.get("session_id")
        connected = st.session_state.get("connected", False)
        if not username or not session_id or not connected:
            return

        manager = get_connection_manager()
        account_id = st.session_state.get("account_id")
        if account_id:
            database_helper.update_ip_address(account_id, None)
        manager.disconnect_user(username, session_id)
        st.session_state["connected"] = False
        st.session_state["chat_open"] = False
    except Exception:
        return


def main() -> None:
    st.set_page_config(page_title="Secure Chat", page_icon="\U0001F512", layout="centered")
    apply_blue_dark_theme()
    init_session_state()

    manager = get_connection_manager()
    if not st.session_state["manager_started"]:
        try:
            database_helper.cache_data()
        except Exception:
            pass
        manager.start_monitor()
        atexit.register(cleanup_current_session)
        st.session_state["manager_started"] = True

    if st.session_state["connected"]:
        manager.heartbeat(
            st.session_state["username"],
            st.session_state["session_id"],
        )

    # While connected but not yet in chat, keep the local temp-file cache
    # continuously refreshed from Firebase so we see the other user's IP.
    if st.session_state["connected"] and not st.session_state["chat_open"]:
        _start_cache_sync_thread()

    # Process events FIRST — a close_chat event sets connected=False so the
    # IP-count block below is skipped, landing directly on the welcome page
    # with no "waiting" flash in between.
    needs_rerun = process_events()

    # Only run IP-count logic when still connected after event processing.
    if st.session_state["connected"]:
        active_ip_count = _active_ip_count()
        if active_ip_count >= 2:
            if not st.session_state["chat_open"]:
                show_chat_screen()
                needs_rerun = True

    if needs_rerun:
        st.rerun()

    if st.session_state["chat_open"]:
        render_chat_screen()
        refresh_for_connection_polling("chat_poll")
        return

    if st.session_state["connected"]:
        render_waiting_state()
        render_waiting_refresh_button()
        return

    render_welcome_page()


if __name__ == "__main__":
    main()