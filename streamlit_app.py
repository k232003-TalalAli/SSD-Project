import hmac
import importlib
import ipaddress
import os
import secrets
import socket

import streamlit as st

from connection_state_manager import get_connection_manager

try:
    _autorefresh_module = importlib.import_module("streamlit_autorefresh")
    st_autorefresh = _autorefresh_module.st_autorefresh
except ImportError:
    st_autorefresh = None


ALLOWED_USERS = ("user1", "user2")
DEFAULT_CHAT_PASSWORD = os.getenv("CHAT_PASSWORD", "change-this")


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
    """Return validated local IP used for outbound routing decisions."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
    ipaddress.ip_address(ip)
    return ip


def secure_username_check(username: str) -> bool:
    return username in ALLOWED_USERS


def secure_password_check(chat_password: str) -> bool:
    if len(chat_password) < 8 or len(chat_password) > 128:
        return False
    return hmac.compare_digest(chat_password, DEFAULT_CHAT_PASSWORD)


def show_chat_screen() -> None:
    st.session_state["chat_open"] = True
    st.session_state["status_message"] = ""


def close_chat() -> None:
    st.session_state["chat_open"] = False
    st.session_state["connected"] = False


def init_session_state() -> None:
    defaults = {
        "connected": False,
        "chat_open": False,
        "username": "",
        "status_message": "",
        "session_id": secrets.token_hex(16),
        "manager_started": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def process_events() -> None:
    username = st.session_state.get("username", "")
    if not username:
        return

    manager = get_connection_manager()
    for event_name in manager.consume_events(username):
        if event_name == "show_chat":
            show_chat_screen()
        elif event_name == "close_chat":
            close_chat()
            st.session_state["status_message"] = "The other user has disconnected"


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
        manager.disconnect_user(st.session_state["username"], st.session_state["session_id"])
        close_chat()
        st.session_state["status_message"] = "You disconnected"
        st.rerun()


def connect_user(username: str, chat_password: str) -> None:
    username = username.strip().lower()

    if not secure_username_check(username):
        st.error("Invalid username. Allowed usernames are user1 and user2.")
        return

    if not secure_password_check(chat_password):
        st.error("Invalid chat password.")
        return

    try:
        ip_address = get_local_ip_address()
    except (OSError, ValueError):
        st.error("Could not resolve local IP address.")
        return

    manager = get_connection_manager()
    manager.register_event_consumer(username)
    manager.connect_user(username, ip_address, st.session_state["session_id"])

    st.session_state["username"] = username
    st.session_state["connected"] = True
    st.session_state["status_message"] = ""


def render_welcome_page() -> None:
    st.title("Secure End-to-End Encrypted Chat")
    st.write("Enter your details to connect securely.")

    if st.session_state["status_message"]:
        st.info(st.session_state["status_message"])

    username_input = st.text_input("Username", max_chars=20, autocomplete="off")
    password_input = st.text_input("Chat Password", type="password", max_chars=128)

    if st.button("Connect", type="primary"):
        connect_user(username_input, password_input)
        st.rerun()


def refresh_for_connection_polling(key: str) -> None:
    if st_autorefresh is not None:
        st_autorefresh(interval=1000, key=key)
        return

    st.caption("Auto-refresh package not installed. Click to check connection status.")
    if st.button("Refresh status", key=f"refresh_{key}"):
        st.rerun()


def main() -> None:
    st.set_page_config(page_title="Secure Chat", page_icon="\U0001F512", layout="centered")
    apply_blue_dark_theme()
    init_session_state()

    manager = get_connection_manager()
    if not st.session_state["manager_started"]:
        manager.start_monitor()
        st.session_state["manager_started"] = True

    process_events()

    if st.session_state["chat_open"]:
        render_chat_screen()
        refresh_for_connection_polling("chat_poll")
        return

    if st.session_state["connected"]:
        render_waiting_state()
        refresh_for_connection_polling("waiting_poll")
        return

    render_welcome_page()


if __name__ == "__main__":
    main()
