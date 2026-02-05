"""Prompt injection detection for AI requests."""

import re
from dataclasses import dataclass
from typing import Optional

import structlog

from app.config import get_settings

logger = structlog.get_logger()


@dataclass
class InjectionResult:
    """Result of prompt injection detection."""
    
    is_injection: bool
    confidence: float
    detected_patterns: list[str]
    severity: str  # low, medium, high, critical
    explanation: str


class PromptInjectionDetector:
    """Detects potential prompt injection attacks."""
    
    # Known injection patterns (updated regularly based on research)
    INJECTION_PATTERNS = {
        # Direct instruction overrides
        "ignore_previous": {
            "patterns": [
                r"ignore\s+(all\s+)?(previous|above|foregoing)\s+(instructions?|prompts?|commands?)",
                r"disregard\s+(all\s+)?(previous|above|foregoing)",
                r"forget\s+(all\s+)?(previous|above|foregoing)",
            ],
            "severity": "critical",
            "weight": 1.0,
        },
        # System prompt extraction
        "system_prompt_extraction": {
            "patterns": [
                r"what\s+(are|were)\s+your\s+instructions",
                r"show\s+(me\s+)?your\s+(system\s+)?prompt",
                r"repeat\s+(the\s+)?(words\s+above|above\s+text|previous\s+message)",
                r"output\s+(the\s+)?(initial\s+)?(instructions|prompt)",
                r"print\s+(the\s+)?(system\s+)?prompt",
            ],
            "severity": "high",
            "weight": 0.9,
        },
        # Role switching
        "role_switch": {
            "patterns": [
                r"you\s+are\s+now\s+(an?\s+)?",
                r"act\s+as\s+(if\s+)?(you\s+)?(are\s+)?",
                r"pretend\s+(to\s+be\s+|you\s+are\s+)",
                r"from\s+now\s+on,?\s+you\s+are",
                r"switch\s+(to\s+)?(the\s+)?role\s+of",
            ],
            "severity": "medium",
            "weight": 0.7,
        },
        # Delimiter manipulation
        "delimiter_manipulation": {
            "patterns": [
                r"```\s*(system|instructions?|prompt)",
                r"<\s*(system|instructions?|prompt)\s*>",
                r"\[\s*(system|instructions?|prompt)\s*\]",
                r"---\s*(system|instructions?|prompt)\s*---",
            ],
            "severity": "high",
            "weight": 0.85,
        },
        # Context manipulation
        "context_manipulation": {
            "patterns": [
                r"new\s+(context|conversation|session)",
                r"let's\s+start\s+(a\s+)?new\s+(context|conversation)",
                r"clear\s+(the\s+)?(context|history|conversation)",
            ],
            "severity": "medium",
            "weight": 0.6,
        },
        # Jailbreak attempts
        "jailbreak": {
            "patterns": [
                r"jailbreak",
                r"do\s+anything\s+now",
                r"DAN\s+(mode|protocol)",
                r"developer\s+mode",
                r"anti\s*-\s*filter",
            ],
            "severity": "critical",
            "weight": 1.0,
        },
        # Encoding tricks
        "encoding_tricks": {
            "patterns": [
                r"base64\s*:",
                r"in\s+base64",
                r"rot13",
                r"hex\s+encoded",
                r"\$\{.*\}",  # Template injection patterns
            ],
            "severity": "medium",
            "weight": 0.5,
        },
        # Multi-language injection
        "translation_trick": {
            "patterns": [
                r"translate\s+(the\s+following|this)\s+to\s+\w+",
                r"in\s+\w+\s+(language\s+)?say",
                r"respond\s+only\s+in\s+\w+",
            ],
            "severity": "low",
            "weight": 0.4,
        },
    }
    
    # Suspicious character sequences
    SUSPICIOUS_SEQUENCES = [
        r"\x00",  # Null bytes
        r"\ufffd",  # Replacement character
        r"[\u202e\u202d]",  # Right-to-left override
    ]
    
    def __init__(self) -> None:
        self._settings = get_settings()
        self._pattern_cache: dict[str, re.Pattern] = {}
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for efficiency."""
        for category, config in self.INJECTION_PATTERNS.items():
            for i, pattern in enumerate(config["patterns"]):
                key = f"{category}_{i}"
                try:
                    self._pattern_cache[key] = re.compile(
                        pattern,
                        re.IGNORECASE | re.MULTILINE
                    )
                except re.error as e:
                    logger.warning("invalid_pattern", pattern=pattern, error=str(e))
    
    async def detect(self, text: str, context: Optional[dict] = None) -> InjectionResult:
        """
        Detect potential prompt injection in text.
        
        Args:
            text: Text to analyze
            context: Additional context (user history, etc.)
        
        Returns:
            InjectionResult with detection details
        """
        if not self._settings.prompt_injection_detection_enabled:
            return InjectionResult(
                is_injection=False,
                confidence=0.0,
                detected_patterns=[],
                severity="low",
                explanation="Detection disabled",
            )
        
        text_lower = text.lower()
        detected_patterns = []
        max_severity_score = 0.0
        total_weight = 0.0
        matched_categories = []
        
        # Check each pattern category
        for category, config in self.INJECTION_PATTERNS.items():
            category_matched = False
            
            for i, pattern in enumerate(config["patterns"]):
                key = f"{category}_{i}"
                compiled = self._pattern_cache.get(key)
                
                if compiled and compiled.search(text):
                    detected_patterns.append(pattern)
                    category_matched = True
            
            if category_matched:
                matched_categories.append(category)
                weight = config["weight"]
                total_weight += weight
                
                # Severity scoring
                severity_scores = {
                    "critical": 1.0,
                    "high": 0.75,
                    "medium": 0.5,
                    "low": 0.25,
                }
                max_severity_score = max(
                    max_severity_score,
                    severity_scores.get(config["severity"], 0.25)
                )
        
        # Check for suspicious sequences
        for seq in self.SUSPICIOUS_SEQUENCES:
            if re.search(seq, text):
                total_weight += 0.3
                detected_patterns.append(f"suspicious_sequence: {seq}")
        
        # Check message length anomalies
        if len(text) > self._settings.max_prompt_length * 0.9:
            total_weight += 0.2
            detected_patterns.append("near_max_length")
        
        # Calculate confidence
        confidence = min(1.0, total_weight * 0.5 + max_severity_score * 0.5)
        
        # Determine severity
        if confidence >= 0.8:
            severity = "critical"
        elif confidence >= 0.6:
            severity = "high"
        elif confidence >= 0.4:
            severity = "medium"
        else:
            severity = "low"
        
        is_injection = confidence >= 0.5
        
        # Build explanation
        if is_injection:
            explanation = (
                f"Detected potential prompt injection. "
                f"Categories: {', '.join(matched_categories)}. "
                f"Confidence: {confidence:.2f}"
            )
        else:
            explanation = "No prompt injection detected"
        
        return InjectionResult(
            is_injection=is_injection,
            confidence=confidence,
            detected_patterns=detected_patterns,
            severity=severity,
            explanation=explanation,
        )
    
    async def detect_in_messages(
        self,
        messages: list[dict],
        context: Optional[dict] = None,
    ) -> InjectionResult:
        """
        Detect injection across multiple messages.
        
        Analyzes both individual messages and the combined conversation.
        """
        all_results = []
        max_confidence = 0.0
        all_patterns = []
        max_severity = "low"
        
        # Check each message
        for msg in messages:
            content = msg.get("content", "")
            if not isinstance(content, str):
                continue
            
            result = await self.detect(content, context)
            all_results.append(result)
            
            if result.confidence > max_confidence:
                max_confidence = result.confidence
                max_severity = result.severity
                all_patterns.extend(result.detected_patterns)
        
        # Check combined conversation for context manipulation
        combined_text = "\n".join(
            msg.get("content", "") for msg in messages
            if isinstance(msg.get("content"), str)
        )
        
        combined_result = await self.detect(combined_text, context)
        
        # Use the higher confidence result
        if combined_result.confidence > max_confidence:
            max_confidence = combined_result.confidence
            max_severity = combined_result.severity
            all_patterns.extend(combined_result.detected_patterns)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_patterns = []
        for p in all_patterns:
            if p not in seen:
                seen.add(p)
                unique_patterns.append(p)
        
        is_injection = max_confidence >= 0.5
        
        return InjectionResult(
            is_injection=is_injection,
            confidence=max_confidence,
            detected_patterns=unique_patterns[:10],  # Limit patterns
            severity=max_severity,
            explanation=f"Multi-message analysis: {len(all_results)} messages checked"
            if is_injection else "No injection detected across messages",
        )
    
    async def analyze_conversation_flow(
        self,
        messages: list[dict],
    ) -> InjectionResult:
        """
        Analyze conversation flow for gradual injection attempts.
        
        Some attacks happen over multiple turns to establish context.
        """
        if len(messages) < 3:
            return await self.detect_in_messages(messages)
        
        # Check for gradual context building
        recent_messages = messages[-5:]  # Last 5 messages
        user_messages = [
            m for m in recent_messages
            if m.get("role") == "user"
        ]
        
        # Look for pattern of increasing manipulation
        manipulation_scores = []
        for msg in user_messages:
            result = await self.detect(msg.get("content", ""))
            manipulation_scores.append(result.confidence)
        
        # If scores are increasing, flag it
        if len(manipulation_scores) >= 3:
            is_increasing = all(
                manipulation_scores[i] <= manipulation_scores[i+1]
                for i in range(len(manipulation_scores)-1)
            )
            
            if is_increasing and manipulation_scores[-1] > 0.3:
                return InjectionResult(
                    is_injection=True,
                    confidence=manipulation_scores[-1] + 0.2,
                    detected_patterns=["gradual_manipulation_pattern"],
                    severity="high",
                    explanation="Detected gradual manipulation pattern across conversation",
                )
        
        return await self.detect_in_messages(messages)


# Global detector instance
injection_detector = PromptInjectionDetector()


async def get_injection_detector() -> PromptInjectionDetector:
    """Get prompt injection detector instance."""
    return injection_detector
