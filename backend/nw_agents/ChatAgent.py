import asyncio
import asyncio
from secretKeys import GEMINI_API_KEY
from pydantic_ai import Agent
from pydantic_ai.models.gemini import GeminiModel

import logging
logger = logging.getLogger(__name__)

ChatAgent = Agent(
    model=GeminiModel(model_name='gemini-2.0-flash', api_key=GEMINI_API_KEY),
    system_prompt="You are a network monitoring assistant. Based on the provided network metrics, answer the user's question about the current network performance.",
    model_settings={'temperature': 0.5},
    result_retries=3,
    retries=3,
    result_type=str
)
