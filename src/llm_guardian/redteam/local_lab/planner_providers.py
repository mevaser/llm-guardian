import os
import json
import logging
import urllib.request
import urllib.error
from typing import Tuple, Optional, Any, Protocol

from pydantic import ValidationError

from llm_guardian.redteam.local_lab.models import PlannerDecision

logger = logging.getLogger("llm_guardian.redteam.local_lab")

class PlannerProvider(Protocol):
    def propose_decision(self, system_prompt: str) -> Tuple[Optional[PlannerDecision], Optional[str]]:
        ...

class GroqProvider:
    def __init__(self, model: str, temperature: float):
        self.model = model
        self.temperature = temperature
        self.api_key = os.environ.get("GROQ_API_KEY")

    def propose_decision(self, system_prompt: str) -> Tuple[Optional[PlannerDecision], Optional[str]]:
        if not self.api_key:
            return None, "missing_groq_api_key"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Generate your next attempt as valid JSON."}
        ]

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "response_format": {"type": "json_object"}
        }

        url = "https://api.groq.com/openai/v1/chat/completions"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "llm-guardian-wizard-lab/0.1"
            },
            method="POST"
        )

        def make_request(request: urllib.request.Request) -> Tuple[Optional[str], Optional[str]]:
            try:
                with urllib.request.urlopen(request, timeout=10.0) as response:
                    res_json = json.loads(response.read().decode("utf-8"))
                    return res_json["choices"][0]["message"]["content"].strip(), None
            except urllib.error.HTTPError as e:
                return None, f"HTTPError {e.getcode()}"
            except Exception as e:
                return None, str(e)

        content, error = make_request(req)
        if error:
            return None, error

        try:
            decision = PlannerDecision.model_validate_json(content)
            return decision, None
        except ValidationError:
            # Repair attempt
            repair_messages = messages + [
                {"role": "assistant", "content": content},
                {"role": "user", "content": "That was not valid JSON matching the schema. Please output only valid JSON without markdown."}
            ]
            repair_payload = dict(payload)
            repair_payload["messages"] = repair_messages
            
            repair_req = urllib.request.Request(
                url,
                data=json.dumps(repair_payload).encode("utf-8"),
                headers=req.headers,
                method="POST"
            )
            
            content_repair, error_repair = make_request(repair_req)
            if error_repair:
                return None, f"Repair failed: {error_repair}"
                
            try:
                decision = PlannerDecision.model_validate_json(content_repair)
                return decision, None
            except ValidationError as e:
                return None, f"JSON parse error after repair: {str(e)}"

class GeminiProvider:
    def __init__(self, model: str, temperature: float, max_tokens: int, use_structured_output: bool):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.use_structured_output = use_structured_output
        self.api_key = os.environ.get("GEMINI_API_KEY")
        
        if self.api_key:
            try:
                from google import genai
                self.client = genai.Client(api_key=self.api_key)
            except ImportError:
                self.client = None
        else:
            self.client = None

    def propose_decision(self, system_prompt: str) -> Tuple[Optional[PlannerDecision], Optional[str]]:
        if not self.api_key:
            return None, "missing_gemini_api_key"
            
        if not self.client:
            return None, "google-genai package not installed"

        from google.genai import types
        from google.genai.errors import APIError

        # Configure JSON response type
        config_kwargs = {
            "temperature": self.temperature,
            "max_output_tokens": self.max_tokens,
            "response_mime_type": "application/json"
        }
        
        if self.use_structured_output:
            config_kwargs["response_schema"] = PlannerDecision.model_json_schema()

        config = types.GenerateContentConfig(**config_kwargs)

        prompt = system_prompt + "\n\nGenerate your next attempt as valid JSON."

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=config,
            )
            content = response.text
        except APIError as e:
            return None, f"Gemini API Error: {str(e)}"
        except Exception as e:
            return None, f"Gemini connection error: {str(e)}"

        try:
            decision = PlannerDecision.model_validate_json(content)
            return decision, None
        except ValidationError as e:
            # We don't implement the repair loop here because Gemini supports structured output
            return None, f"JSON parse error: {str(e)}"
