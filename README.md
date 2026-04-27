# SSD-Project

Small Streamlit-based secure chat prototype.

## Requirements

- Python 3.10+
- A Firebase service account key file named `serviceAccountKey.json` in the project root

## Install Dependencies

```powershell
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
```

## Run

```powershell
py -m streamlit run streamlit_app.py
```

Then open the local URL shown in the terminal (usually `http://localhost:8501`).

## Quick Local Test (One PC)

- Open the app in two separate browser sessions (for example: normal window + incognito).
- Sign in with two different users.
- Verify messages send and appear on both screens.
