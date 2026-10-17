# CyberGuard

CyberGuard is a local-first tool for assessing suspicious links and messages. It
provides a browser-based interface and uses Google Gemini to generate structured
risk assessments based on the content you submit.

## Built with

- **HTML, CSS, and vanilla JavaScript** for the responsive single-page interface
- **Python 3 standard library** for the local HTTP server and API proxy
- **Google Gemini API** for AI-assisted analysis
- **Browser local storage** for scan history

No frontend package manager or third-party Python packages are required.

## Requirements

- Python 3
- A Google AI API key with access to the Gemini API

## Run locally

1. Copy `.env.example` to `.env`.
2. Add your Google AI API key to `.env`:

   ```dotenv
   GEMINI_API_KEY=your-api-key
   ```

   Optionally change `GEMINI_MODEL` or `PORT`; the defaults are
   `gemma-4-31b-it` and `3000`.
3. Start the server:

   ```powershell
   python server.py
   ```

4. Open <http://127.0.0.1:3000> in your browser.

The server binds to localhost. Keep `.env` private; it is excluded from Git.

## Usage

Choose link analysis, message analysis, or security advice, enter content, and
request an assessment. Results include a risk level, score, indicators, and
recommended actions. Scan history is stored in the browser on your device.

Assessments are based only on the content you provide: CyberGuard does not visit
or verify links. A low risk score is not proof that content is safe.