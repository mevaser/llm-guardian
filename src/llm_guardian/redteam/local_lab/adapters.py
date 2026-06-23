from typing import Protocol, Dict, Any
from fastapi.testclient import TestClient
from llm_guardian.redteam.local_lab.app import app

class TargetAdapter(Protocol):
    def start_session(self, level_id: int) -> Dict[str, Any]:
        ...
        
    def submit_prompt(self, session_id: str, prompt: str, response_mode: str) -> Dict[str, Any]:
        ...

class LocalLabAdapter:
    def __init__(self):
        self.client = TestClient(app)

    def start_session(self, level_id: int) -> Dict[str, Any]:
        response = self.client.post(f"/api/session/start?level_id={level_id}")
        response.raise_for_status()
        return response.json()

    def submit_prompt(self, session_id: str, prompt: str, response_mode: str = "deterministic") -> Dict[str, Any]:
        response = self.client.post(
            "/api/session/submit",
            json={
                "session_id": session_id,
                "prompt": prompt,
                "response_mode": response_mode
            }
        )
        response.raise_for_status()
        return response.json()
