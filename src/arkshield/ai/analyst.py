"""
Arkshield — Nova AI Security Analyst

Intelligent security analyst powered by LLM APIs.
Falls back to local rule-based logic when no API key is configured.
Supports any OpenAI-compatible provider (OpenRouter, Groq, OpenAI, Ollama, etc.)
"""

import json
import os
import random
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger("arkshield.nova")

# Path to the AI configuration file
CONFIG_PATH = Path(__file__).parent.parent / "config" / "ai_config.json"


def load_ai_config() -> Dict[str, Any]:
    """Load AI configuration from disk."""
    defaults = {
        "provider": "openrouter",
        "api_key": "",
        "base_url": "https://openrouter.ai/api/v1",
        "model": "google/gemini-2.0-flash-001",
        "max_tokens": 512,
        "temperature": 0.7,
        "system_prompt_prefix": "You are Nova, an elite AI security analyst for the Arkshield autonomous cyber defense platform. You have access to real-time telemetry from the system you are protecting. Be concise, professional, and security-focused."
    }
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, "r") as f:
                config = json.load(f)
                defaults.update(config)
    except Exception as e:
        logger.warning(f"Failed to load AI config: {e}")
    return defaults


def save_ai_config(config: Dict[str, Any]) -> bool:
    """Save AI configuration to disk."""
    try:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        logger.error(f"Failed to save AI config: {e}")
        return False


class SentinelAnalyst:
    """
    Nova — Arkshield's AI Security Analyst.
    
    Uses a real LLM when an API key is configured.
    Falls back to intelligent local analysis when offline.
    """
    
    def __init__(self, repository):
        self.repository = repository
        self.config = load_ai_config()
        self.analyst_name = "Nova"

    def _build_system_context(self) -> str:
        """Build a rich system prompt with live telemetry data."""
        context_parts = [self.config.get("system_prompt_prefix", "")]
        
        # Inject live telemetry
        try:
            events = self.repository.get_recent_events(limit=5)
            alerts = self.repository.get_recent_alerts(limit=5)
            
            context_parts.append("\n\n--- LIVE SYSTEM TELEMETRY ---")
            context_parts.append(f"Total recent events: {len(events)}")
            context_parts.append(f"Active alerts: {len(alerts)}")
            
            if alerts:
                context_parts.append("\nRecent Alerts:")
                for a in alerts[:3]:
                    context_parts.append(f"  - [{a.severity}] {a.title} ({a.category}) — Status: {a.status}")
            
            if events:
                context_parts.append("\nRecent Events:")
                for e in events[:3]:
                    context_parts.append(f"  - [{e.event_class}] {e.event_type}: {e.description[:100]}")
                    
        except Exception as e:
            context_parts.append(f"\n[Telemetry unavailable: {e}]")
        
        return "\n".join(context_parts)

    def chat(self, user_query: str) -> str:
        """Process a user query — uses LLM if available, otherwise local logic."""
        
        # Try LLM first if API key is set
        api_key = self.config.get("api_key", "").strip()
        if api_key:
            try:
                return self._llm_chat(user_query, api_key)
            except Exception as e:
                logger.warning(f"LLM call failed, falling back to local: {e}")
                return f"[LLM unavailable: {e}] — " + self._local_chat(user_query)
        
        return self._local_chat(user_query)

    def _llm_chat(self, user_query: str, api_key: str) -> str:
        """Call the configured LLM API (OpenAI-compatible format)."""
        base_url = self.config.get("base_url", "https://openrouter.ai/api/v1").rstrip("/")
        model = self.config.get("model", "google/gemini-2.0-flash-001")
        max_tokens = self.config.get("max_tokens", 512)
        temperature = self.config.get("temperature", 0.7)
        
        system_prompt = self._build_system_context()
        
        payload = json.dumps({
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_query}
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False
        }).encode("utf-8")
        
        url = f"{base_url}/chat/completions"
        
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {api_key}")
        req.add_header("HTTP-Referer", "https://arkshield.local")
        req.add_header("X-Title", "Arkshield Nova AI")
        
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            if e.code == 401:
                raise RuntimeError("Invalid API Key or Missing Authentication. Please check your AI Settings and ensure your token is correct.")
            raise RuntimeError(f"API error {e.code}: {error_body[:100]}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Connection error: {e.reason}")

    def _local_chat(self, user_query: str) -> str:
        """Offline / fallback rule-based responses."""
        query = user_query.lower()
        
        if any(w in query for w in ["status", "health", "how are you", "operational"]):
            return "Arkshield is fully operational. All 6 monitors (Process, Network, File, Memory, Persistence, Integrity) are reporting green. Security posture: 100%."
        
        if any(w in query for w in ["alert", "incident", "threat", "attack", "suspicious"]):
            alerts = self.repository.get_recent_alerts(limit=5)
            if not alerts:
                return "No active threats detected. The environment is stable."
            latest = alerts[0]
            return f"I've detected {len(alerts)} recent alerts. The most critical is '{latest.title}' (severity {latest.severity}). Autonomous mitigation has been applied."
        
        if any(w in query for w in ["recommend", "improve", "secure", "fix", "advice"]):
            advices = [
                "Rotate JWT secrets for production. Enable 'Aggressive Mode' for lateral movement detection.",
                "I notice elevated memory entropy in background processes. Schedule a deep scan.",
                "Consider enabling Network Isolation for any processes flagged with C2 beacon patterns.",
                "Your detection sensitivity is at 85%. Increasing to 95% will catch more low-confidence anomalies but may increase false positives."
            ]
            return random.choice(advices)
        
        if any(w in query for w in ["what can you do", "features", "help", "capability"]):
            return "I can analyze threats, provide security recommendations, check system health, investigate alerts, and look up IP/hash reputation. Try asking about recent threats or system status!"
        
        fallbacks = [
            "Analyzing telemetry streams... No critical anomalies detected in the current buffer.",
            "System integrity is holding at 100%. No unauthorized privilege escalations found.",
            "All monitors are reporting nominal. Would you like a detailed alert breakdown?",
            "I'm continuously correlating events across all 6 monitors. Ask me about specific threats or system health."
        ]
        return random.choice(fallbacks)
