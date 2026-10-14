# 🛡️ Scam Risk Analyzer

A Streamlit app that analyzes a pasted email or SMS and returns a **risk score (0-100)**, a risk level, red flags, safe signals, a plain-language explanation and recommended actions. Powered by a Grok model via the xAI API.

## Features
- Risk score with level: Low, Moderate, High, Critical
- Scam category detection (phishing, bank impersonation, delivery scam, etc.)
- Red flags and legitimate signals listed separately
- Local link inspection (URL shorteners, raw IPs, http, look-alike domains)
- Prompt-injection hardening: the message is treated as data, never as instructions
- Per-session usage cap to protect your API key on public deployments

## Project structure
```
app.py             # Streamlit app
requirements.txt   # Python dependencies
README.md
```

## Run locally
1. Install Python 3.10+.
2. Create and activate a virtual environment, then install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate        # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Add your xAI API key (get one at https://console.x.ai). Create `.streamlit/secrets.toml`:
   ```toml
   XAI_API_KEY = "your-key-here"
   # Optional: XAI_MODEL = "model-name"
   ```
   Alternatively set the `XAI_API_KEY` environment variable.
4. Start the app:
   ```bash
   streamlit run app.py
   ```

## Configuration
| Setting | Where | Description |
|---|---|---|
| `XAI_API_KEY` | secrets / env | Required. Your xAI API key |
| `XAI_MODEL` | secrets / env | Optional. Defaults to `grok-4`. Check https://docs.x.ai for current model names |

## Deploy on Streamlit Community Cloud
1. Push this project to a GitHub repository (files at the repo root).
2. Go to https://share.streamlit.io and sign in with GitHub.
3. Click **Create app**, choose your repo, branch `main`, main file `app.py`.
4. Under **Advanced settings → Secrets**, paste `XAI_API_KEY = "your-key-here"`.
5. Click **Deploy**.

## Security and privacy
- Never commit API keys. Keep `.streamlit/secrets.toml` in `.gitignore`.
- Message text is sent to xAI for analysis. Do not paste passwords, OTPs or card numbers.
- Set a spending limit on your xAI account, especially for public deployments.

## Limitations
- This is a decision aid, not a guarantee. AI can produce false positives and false negatives.
- It analyzes text only. It does not check sender headers, live URL reputation or attachments.
- When in doubt, verify with the supposed sender via an official channel you look up yourself.

## License
MIT# AI-Phishing-Detector-
