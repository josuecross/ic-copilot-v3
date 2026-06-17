from __future__ import annotations

__all__ = [
    "AnthropicJSONClient",
    "GeminiJSONClient",
    "LocalHTTPJSONClient",
    "OpenAIJSONClient",
]


def __getattr__(name: str):
    if name == "OpenAIJSONClient":
        from ic_copilot.llm.providers.openai_json import OpenAIJSONClient

        return OpenAIJSONClient
    if name == "AnthropicJSONClient":
        from ic_copilot.llm.providers.anthropic_json import AnthropicJSONClient

        return AnthropicJSONClient
    if name == "GeminiJSONClient":
        from ic_copilot.llm.providers.gemini_json import GeminiJSONClient

        return GeminiJSONClient
    if name == "LocalHTTPJSONClient":
        from ic_copilot.llm.providers.local_http_json import LocalHTTPJSONClient

        return LocalHTTPJSONClient
    raise AttributeError(name)
