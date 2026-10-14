import json
import os
import re
from email import policy
from email.parser import BytesParser
from io import BytesIO

import streamlit as st
from openai import OpenAI


# -------------------------
# Application configuration
# -------------------------
APP_TITLE = "PhishGuard AI"
MAX_FILE_BYTES = 1_000_000
MAX_TEXT_CHARS = 30_000
DEFAULT_MODEL = "grok-3"
XAI_BASE_URL = "https://api.x.ai/v1"

st.set_page_config(
    page_title=APP_TITLE,
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
    .block-container {max-width: 1100px; padding-top: 2rem;}
    .risk-score {font-size: 3rem; font-weight: 750;}
    </style>
    """,
    unsafe_allow_html=True,
)


# -------------------------
# Helpers
# -------------------------
def get_api_key():
    """Read the API key from Streamlit secrets or environment."""
    try:
        key = st.secrets.get("XAI_API_KEY", "")
    except Exception:
        key = ""

    return key or os.getenv("XAI_API_KEY", "")


def extract_email_text(raw_bytes):
    """Extract readable headers and body from an EML file."""
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    parts = [
        f"From: {message.get('From', '')}",
        f"To: {message.get('To', '')}",
        f"Subject: {message.get('Subject', '')}",
        f"Reply-To: {message.get('Reply-To', '')}",
        "",
    ]

    if message.is_multipart():
        bodies = []
        for part in message.walk():
            if part.get_content_type() != "text/plain":
                continue
            if part.get_content_disposition() == "attachment":
                continue
            try:
                content = part.get_content()
                if isinstance(content, str):
                    bodies.append(content)
            except (LookupError, UnicodeError, ValueError):
                continue
        parts.extend(bodies)
    else:
        try:
            body = message.get_content()
            if isinstance(body, str):
                parts.append(body)
        except (LookupError, UnicodeError, ValueError):
            pass

    return "\n".join(parts).strip()


def extract_uploaded_text(uploaded_file):
    """Read supported files without executing or opening their content."""
    if uploaded_file is None:
        return ""

    raw = uploaded_file.getvalue()

    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("The uploaded file must be 1 MB or smaller.")

    extension = os.path.splitext(uploaded_file.name)[1].lower()

    if extension == ".eml":
        text = extract_email_text(raw)
    elif extension == ".txt":
        text = raw.decode("utf-8-sig", errors="replace")
    else:
        raise ValueError("Unsupported file type. Upload a .txt or .eml file.")

    if len(text) > MAX_TEXT_CHARS:
        raise ValueError(
            f"Extracted text exceeds {MAX_TEXT_CHARS:,} characters."
        )

    return text


def parse_json_response(content):
    """Parse a JSON object, including one wrapped in a Markdown fence."""
    content = content.strip()
    content = re.sub(r"^```(?:json)?\s*", "", content, flags=re.I)
    content = re.sub(r"\s*```$", "", content)

    result = json.loads(content)

    if not isinstance(result, dict):
        raise ValueError("The model returned an unexpected response.")

    return result


def validate_report(data):
    """Validate model output before displaying it to the user."""
    score = data.get("risk_score")

    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise ValueError("The model returned an invalid risk score.")

    score = int(score)
    if not 0 <= score <= 100:
        raise ValueError("The risk score must be between 0 and 100.")

    def clean_string(value, default, max_length=1500):
        if not isinstance(value, str):
            return default
        return value.strip()[:max_length] or default

    def clean_list(value, limit=8):
        if not isinstance(value, list):
            return []
        return [
            item.strip()[:500]
            for item in value
            if isinstance(item, str) and item.strip()
        ][:limit]

    if score >= 76:
        level = "High"
    elif score >= 51:
        level = "Elevated"
    elif score >= 26:
        level = "Moderate"
    else:
        level = "Low"

    return {
        "risk_score": score,
        "risk_level": level,
        "verdict": clean_string(
            data.get("verdict"), "Unable to determine"
        ),
        "summary": clean_string(
            data.get("summary"), "No summary provided."
        ),
        "indicators": clean_list(data.get("indicators")),
        "evidence": clean_list(data.get("evidence")),
        "recommended_actions": clean_list(
            data.get("recommended_actions")
        ),
        "limitations": clean_string(
            data.get("limitations"),
            "This is an AI estimate, not a definitive security finding.",
        ),
    }


def analyze_message(message_text, api_key, model):
    """Ask Grok to assess a message and return a validated report."""
    client = OpenAI(
        api_key=api_key,
        base_url=XAI_BASE_URL,
        timeout=45.0,
        max_retries=1,
    )

    system_prompt = """
