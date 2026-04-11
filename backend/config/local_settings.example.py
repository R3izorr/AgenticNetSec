OPENROUTER_API_KEY = "paste_your_openrouter_key_here"
# Optional: add multiple OpenRouter keys for rotation. The app tries each key
# OPENROUTER_RETRY_ATTEMPTS times before moving to the next one.
OPENROUTER_API_KEYS = [
    OPENROUTER_API_KEY,
    # "paste_your_second_openrouter_key_here",
    # "paste_your_third_openrouter_key_here",
]
OPENROUTER_MODEL = "openai/gpt-5-mini"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_HTTP_REFERER = "http://localhost"
OPENROUTER_APP_NAME = "AgenticNetSec"
OPENROUTER_RETRY_ATTEMPTS = 3
OPENROUTER_RETRY_DELAY_SECONDS = 2.0

REPORT_PROVIDER = "openrouter"
REPORT_MODEL = "openai/gpt-5-mini"

# GEMINI_API_KEY = "paste_your_gemini_key_here"
# Optional: add multiple Gemini keys for rotation. The app tries each key
# GEMINI_RETRY_ATTEMPTS times for each configured Gemini model before moving to the next one.
# GEMINI_API_KEYS = [
#     GEMINI_API_KEY,
#     # "paste_your_second_gemini_key_here",
#     # "paste_your_third_gemini_key_here",
# ]
# GEMINI_MODEL = "gemini-2.5-flash"
# GEMINI_RETRY_ATTEMPTS = 3
# GEMINI_RETRY_DELAY_SECONDS = 2.0
# GOOGLE_API_KEY = "paste_your_google_api_key_here"
# GOOGLE_API_KEYS = [
#     GOOGLE_API_KEY,
#     # "paste_your_second_google_api_key_here",
# ]

# OPENAI_API_KEY = "paste_your_openai_key_here"
# OPENAI_MODEL = "gpt-5-mini"
# OPENAI_RETRY_ATTEMPTS = 3
# OPENAI_RETRY_DELAY_SECONDS = 2.0

# GROQ_API_KEY = "paste_your_groq_key_here"
# GROQ_MODEL = "openai/gpt-oss-20b"
# GROQ_BASE_URL = "https://api.groq.com/openai/v1"
# GROQ_RETRY_ATTEMPTS = 3
# GROQ_RETRY_DELAY_SECONDS = 2.0

# OLLAMA_MODEL = "qwen2.5:3b"
# OLLAMA_BASE_URL = "http://127.0.0.1:11434"
# OLLAMA_TIMEOUT_SECONDS = 300
