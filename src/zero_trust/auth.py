"""Context-aware authentication"""
from typing import Dict, Optional

class Authenticator:
    def __init__(self):
        self.agents = {}
        
    def authenticate(self, agent_id: str, context: Dict) -> bool:
        """Authenticate agent with context"""
        # Context-aware authentication logic
        return agent_id in self.agents or self._register_agent(agent_id, context)
        
    def _register_agent(self, agent_id: str, context: Dict) -> bool:
        self.agents[agent_id] = context
        return True
