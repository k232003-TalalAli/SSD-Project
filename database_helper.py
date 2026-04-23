import firebase_admin
from firebase_admin import credentials, firestore
import os
import subprocess
import platform

def _unhide(filepath):
    if platform.system() == "Windows":
        subprocess.run(["attrib", "-h", filepath], check=True)

def _hide(filepath):
    if platform.system() == "Windows":
        subprocess.run(["attrib", "+h", filepath], check=True)

# ── Init ──────────────────────────────────────────────────────────────────────
def _init_firebase():
    if not firebase_admin._apps:
        if not os.path.exists("serviceAccountKey.json"):
           print("service Key not found in the directory, please setup the serviceAccount key and try again")
        else:
           cred = credentials.Certificate("serviceAccountKey.json")
        firebase_admin.initialize_app(cred)

_init_firebase()
db = firestore.client()

TEMP_APP_DATA = "app_data_temp.txt"
TEMP_CHAT_DATA = "chat_data_temp.txt"

# ══════════════════════════════════════════════════════════════════════════════
#  INTERNAL DB HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _account_ref(account_id: str):
    return db.collection("app_data").document("accounts") \
             .collection("entries").document(str(account_id))

def _get_field(account_id: str, field: str):
    doc = _account_ref(account_id).get()
    return doc.to_dict().get(field) if doc.exists else None

def _update_field(account_id: str, field: str, value):
    _account_ref(account_id).set({field: value}, merge=True)

# ══════════════════════════════════════════════════════════════════════════════
#  CACHE: WRITE & READ TEMP FILES
# ══════════════════════════════════════════════════════════════════════════════

def _write_app_data_temp(data: dict):
    _unhide(TEMP_APP_DATA)
    lines = []
    lines.append(f"DES_KEY: {data.get('des_key', '')}")
    for acc_id, acc in sorted(data.get("accounts", {}).items()):
        lines.append(f"____________________________ Account ID: {acc_id} ____________________________")
        lines.append(f"Username: {acc.get('username', '')}")
        lines.append(f"Password: {acc.get('password', '')}")
        lines.append(f"IP_address: {acc.get('ip_address') or 'None'}")
        lines.append(f"Public Key: {acc.get('public_key', '')}")
        lines.append(f"Private Key: {acc.get('private_key', '')}")
    with open(TEMP_APP_DATA, "w") as f:
        f.write("\n".join(lines))
    _hide(TEMP_APP_DATA)

def _read_app_data_temp() -> dict:
    """Parse the temp file back into a dict."""
    if not os.path.exists(TEMP_APP_DATA):
        return {}
    with open(TEMP_APP_DATA, "r") as f:
        lines = f.read().splitlines()

    data = {"des_key": "", "accounts": {}}
    current_id = None

    for line in lines:
        if line.startswith("DES_KEY:"):
            data["des_key"] = line.split("DES_KEY:", 1)[1].strip()
        elif "Account ID:" in line:
            current_id = line.split("Account ID:")[1].split("_")[0].strip()
            data["accounts"][current_id] = {}
        elif current_id:
            acc = data["accounts"][current_id]
            if line.startswith("Username:"):
                acc["username"] = line.split("Username:", 1)[1].strip()
            elif line.startswith("Password:"):
                acc["password"] = line.split("Password:", 1)[1].strip()
            elif line.startswith("IP_address:"):
                val = line.split("IP_address:", 1)[1].strip()
                acc["ip_address"] = None if val == "None" else val
            elif line.startswith("Public Key:"):
                acc["public_key"] = line.split("Public Key:", 1)[1].strip()
            elif line.startswith("Private Key:"):
                acc["private_key"] = line.split("Private Key:", 1)[1].strip()
    return data

def _update_temp_field(account_id: str, field: str, value):
    """Update a single field in the temp file without re-fetching from DB."""
    data = _read_app_data_temp()
    if account_id not in data["accounts"]:
        data["accounts"][account_id] = {}
    data["accounts"][account_id][field] = value
    _write_app_data_temp(data)

# ══════════════════════════════════════════════════════════════════════════════
#  CACHE: POPULATE (call once at startup)
# ══════════════════════════════════════════════════════════════════════════════

def cache_data():
    """Fetch everything from Firebase and write to temp files."""

    # ── app_data ──────────────────────────────────────────────────────────────
    des_doc = db.collection("app_data").document("config").get()
    des_key = des_doc.to_dict().get("des_key", "") if des_doc.exists else ""

    account_refs = db.collection("app_data").document("accounts") \
                     .collection("entries").stream()
    accounts = {}
    for doc in account_refs:
        acc = doc.to_dict()
        accounts[doc.id] = {
            "username":    acc.get("username", ""),
            "password":    acc.get("password", ""),
            "ip_address":  acc.get("ip_address"),
            "public_key":  acc.get("public_key", ""),
            "private_key": acc.get("private_key", ""),
        }

    _write_app_data_temp({"des_key": des_key, "accounts": accounts})  # already hides itself

    # ── chatlogs ──────────────────────────────────────────────────────────────
    chat_doc = db.collection("chatlogs").document("data").get()
    raw = chat_doc.to_dict().get("content", "") if chat_doc.exists else ""

    _unhide(TEMP_CHAT_DATA)                                    # ← unhide first
    with open(TEMP_CHAT_DATA, "w", encoding="utf-8") as f:
        f.write(raw)
    _hide(TEMP_CHAT_DATA)                                      # ← then re-hide

# ══════════════════════════════════════════════════════════════════════════════
#  GET FROM CACHE (no DB traffic)
# ══════════════════════════════════════════════════════════════════════════════

def get_des_key() -> str | None:
    return _read_app_data_temp().get("des_key")

def get_username(account_id: str) -> str | None:
    return _read_app_data_temp()["accounts"].get(str(account_id), {}).get("username")

def get_account_id_by_username(username: str) -> str | None:
    accounts = _read_app_data_temp().get("accounts", {})
    for acc_id, acc in accounts.items():
        if acc.get("username") == username:
            return acc_id
    return None

def get_password(account_id: str) -> str | None:
    return _read_app_data_temp()["accounts"].get(str(account_id), {}).get("password")

def get_ip_address(account_id: str) -> str | None:
    return _read_app_data_temp()["accounts"].get(str(account_id), {}).get("ip_address")

def get_public_key(ip_address: str) -> str | None:
    accounts = _read_app_data_temp().get("accounts", {})
    for acc in accounts.values():
        if acc.get("ip_address") == ip_address:
            return acc.get("public_key")
    print("Critical Error: Could not find public key of user.")
    return None

def get_private_key(account_id: str) -> str | None:
    return _read_app_data_temp()["accounts"].get(str(account_id), {}).get("private_key")

def get_account(account_id: str) -> dict | None:
    acc = _read_app_data_temp()["accounts"].get(str(account_id))
    return acc if acc else None

def get_all_account_ids() -> list[str]:
    return list(_read_app_data_temp().get("accounts", {}).keys())

def get_chatlogs() -> str | None:
    if not os.path.exists(TEMP_CHAT_DATA):
        return None
    with open(TEMP_CHAT_DATA, "r", encoding="utf-8") as f:
        return f.read()
    
# ══════════════════════════════════════════════════════════════════════════════
#  UPDATE: DB + TEMP FILE
# ══════════════════════════════════════════════════════════════════════════════

def update_des_key(new_key: str):
    db.collection("app_data").document("config").set({"des_key": new_key}, merge=True)
    data = _read_app_data_temp()
    data["des_key"] = new_key
    _write_app_data_temp(data)

def update_username(account_id: str, new_username: str):
    _update_field(account_id, "username", new_username)
    _update_temp_field(account_id, "username", new_username)

def update_password(account_id: str, new_hash: str):
    _update_field(account_id, "password", new_hash)
    _update_temp_field(account_id, "password", new_hash)

def update_ip_address(account_id: str, ip: str | None):
    _update_field(account_id, "ip_address", ip)
    _update_temp_field(account_id, "ip_address", ip)

def update_public_key(account_id: str, new_key: str):
    _update_field(account_id, "public_key", new_key)
    _update_temp_field(account_id, "public_key", new_key)

def update_private_key(account_id: str, new_key: str):
    _update_field(account_id, "private_key", new_key)
    _update_temp_field(account_id, "private_key", new_key)

def update_account(account_id: str, account_dict: dict):
    _account_ref(account_id).set(account_dict, merge=True)
    data = _read_app_data_temp()
    if str(account_id) not in data["accounts"]:
        data["accounts"][str(account_id)] = {}
    data["accounts"][str(account_id)].update(account_dict)
    _write_app_data_temp(data)

def update_chatlogs(raw_content: str):
    db.collection("chatlogs").document("data").set({"content": raw_content})
    _unhide(TEMP_CHAT_DATA)
    with open(TEMP_CHAT_DATA, "w", encoding="utf-8") as f:
        f.write(raw_content)
    _hide(TEMP_CHAT_DATA)