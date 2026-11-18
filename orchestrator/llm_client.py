"""Model-agnostic client for any OpenAI-compatible /v1/chat/completions endpoint.

Ollama, vLLM, LM Studio, and llama.cpp all speak this protocol, so switching models is a
URL + name change in the profile — no code change. The orchestrator runs on the host and
talks to Ollama at http://localhost:11434/v1 by default.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

from .config import LLMConfig


class LLMError(RuntimeError):
    pass


@dataclass
class LLMClient:
    cfg: LLMConfig
    timeout_s: int = 120

    @property
    def _url(self) -> str:
        return self.cfg.endpoint.rstrip("/") + "/chat/completions"

    def chat(self, messages: list[dict[str, str]], **overrides) -> str:
        """Send chat messages, return the assistant's text content."""
        payload = {
            "model": overrides.get("model", self.cfg.model),
            "messages": messages,
            "temperature": overrides.get("temperature", self.cfg.temperature),
            "max_tokens": overrides.get("max_tokens", self.cfg.max_tokens),
            "stream": False,
        }
        try:
            resp = requests.post(self._url, json=payload, timeout=self.timeout_s)
        except requests.exceptions.ConnectionError as e:
            raise LLMError(
                f"could not reach model server at {self.cfg.endpoint} — is Ollama running? "
                f"(try `ollama serve` / `ollama list`)\n{e}"
            ) from e
        except requests.exceptions.Timeout as e:
            raise LLMError(
                f"model server at {self.cfg.endpoint} timed out after {self.timeout_s}s "
                f"(a cold model load can be slow on first call)\n{e}"
            ) from e
        except requests.exceptions.RequestException as e:
            raise LLMError(f"request to model server failed: {e}") from e
        if resp.status_code != 200:
            raise LLMError(f"model server returned {resp.status_code}: {resp.text[:500]}")

        data = resp.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LLMError(f"unexpected response shape: {data}") from e

    def complete(self, system: str, user: str, **overrides) -> str:
        return self.chat(
            [{"role": "system", "content": system}, {"role": "user", "content": user}],
            **overrides,
        )

    def ping(self, timeout_s: int = 5) -> bool:
        """Fast reachability check: hit the OpenAI-compatible /models listing.

        Avoids a (possibly slow) generation, so `lab.py doctor` stays quick even when the
        model is cold. Returns True if the server answers 200.
        """
        url = self.cfg.endpoint.rstrip("/") + "/models"
        try:
            return requests.get(url, timeout=timeout_s).status_code == 200
        except requests.exceptions.RequestException:
            return False

    def model_available(self, timeout_s: int = 5) -> bool:
        """True if the configured model id appears in the server's /models listing."""
        url = self.cfg.endpoint.rstrip("/") + "/models"
        try:
            data = requests.get(url, timeout=timeout_s).json()
        except (requests.exceptions.RequestException, ValueError):
            return False
        ids = {m.get("id") for m in data.get("data", [])}
        return self.cfg.model in ids
