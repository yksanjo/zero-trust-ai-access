"""PII Detection using Microsoft Presidio."""

import re
from dataclasses import dataclass
from typing import Optional

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from app.config import get_settings
import structlog

logger = structlog.get_logger()


@dataclass
class PIIDetectionResult:
    """Result of PII detection."""
    
    has_pii: bool
    pii_types: list[str]
    confidence_scores: dict[str, float]
    anonymized_text: Optional[str] = None
    original_text: Optional[str] = None
    detection_count: int = 0


class PIIDetector:
    """PII detector using Microsoft Presidio."""
    
    # Entity types we want to detect
    DEFAULT_ENTITIES = [
        "PERSON",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "CREDIT_CARD",
        "US_SSN",
        "US_BANK_NUMBER",
        "US_PASSPORT",
        "IBAN_CODE",
        "IP_ADDRESS",
        "LOCATION",
        "DATE_TIME",
        "NRP",  # Nationality, religious or political group
        "MEDICAL_LICENSE",
        "URL",
        "US_ITIN",
        "US_DRIVER_LICENSE",
    ]
    
    # High-risk entities that should always be blocked
    HIGH_RISK_ENTITIES = [
        "CREDIT_CARD",
        "US_SSN",
        "US_BANK_NUMBER",
        "US_PASSPORT",
        "PASSWORD",
        "CRYPTO",
    ]
    
    def __init__(self) -> None:
        self.analyzer: Optional[AnalyzerEngine] = None
        self.anonymizer: Optional[AnonymizerEngine] = None
        self._settings = get_settings()
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize Presidio engines."""
        if self._initialized:
            return
        
        try:
            # Initialize NLP engine with default configuration
            provider = NlpEngineProvider()
            nlp_engine = provider.create_engine()
            
            self.analyzer = AnalyzerEngine(
                nlp_engine=nlp_engine,
                supported_languages=["en"],
            )
            self.anonymizer = AnonymizerEngine()
            
            self._initialized = True
            logger.info("pii_detector_initialized")
        except Exception as e:
            logger.error("pii_detector_initialization_failed", error=str(e))
            # Don't raise - the detector will fall back to pattern matching
    
    async def detect(
        self,
        text: str,
        language: str = "en",
        score_threshold: float = 0.5,
        anonymize: bool = True,
    ) -> PIIDetectionResult:
        """
        Detect PII in text.
        
        Args:
            text: Text to analyze
            language: Language code (default: en)
            score_threshold: Minimum confidence score for detection
            anonymize: Whether to return anonymized text
        
        Returns:
            PIIDetectionResult with detection details
        """
        if not self._settings.pii_detection_enabled:
            return PIIDetectionResult(
                has_pii=False,
                pii_types=[],
                confidence_scores={},
                original_text=text if not anonymize else None,
            )
        
        if not self._initialized:
            await self.initialize()
        
        # If Presidio is not available, use pattern-based detection
        if not self.analyzer:
            return await self._detect_with_patterns(text, anonymize)
        
        try:
            results = self.analyzer.analyze(
                text=text,
                entities=self.DEFAULT_ENTITIES,
                language=language,
                score_threshold=score_threshold,
            )
            
            has_pii = len(results) > 0
            pii_types = list(set(r.entity_type for r in results))
            confidence_scores = {
                r.entity_type: max(
                    confidence_scores.get(r.entity_type, 0),
                    r.score
                )
                for r in results
                for confidence_scores in [{r.entity_type: r.score for r in results}]
            }
            
            anonymized_text = None
            if anonymize and has_pii:
                anonymized_text = self._anonymize_text(text, results)
            
            # Check for high-risk entities
            high_risk_detected = any(
                entity in self.HIGH_RISK_ENTITIES for entity in pii_types
            )
            
            return PIIDetectionResult(
                has_pii=has_pii,
                pii_types=pii_types,
                confidence_scores=confidence_scores,
                anonymized_text=anonymized_text,
                original_text=text if not anonymize else None,
                detection_count=len(results),
            )
            
        except Exception as e:
            logger.error("pii_detection_error", error=str(e))
            return await self._detect_with_patterns(text, anonymize)
    
    async def _detect_with_patterns(
        self,
        text: str,
        anonymize: bool,
    ) -> PIIDetectionResult:
        """Fallback pattern-based PII detection."""
        
        patterns = {
            "EMAIL_ADDRESS": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "PHONE_NUMBER": re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
            "CREDIT_CARD": re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b'),
            "US_SSN": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            "IP_ADDRESS": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        }
        
        found_types = []
        confidence_scores = {}
        anonymized = text if anonymize else None
        
        for entity_type, pattern in patterns.items():
            matches = pattern.findall(text)
            if matches:
                found_types.append(entity_type)
                confidence_scores[entity_type] = 0.8  # Pattern match confidence
                
                if anonymize:
                    for match in matches:
                        replacement = f"<{entity_type}>"
                        anonymized = anonymized.replace(match, replacement)
        
        return PIIDetectionResult(
            has_pii=len(found_types) > 0,
            pii_types=found_types,
            confidence_scores=confidence_scores,
            anonymized_text=anonymized if anonymize else None,
            original_text=text if not anonymize else None,
            detection_count=len(found_types),
        )
    
    def _anonymize_text(self, text: str, analyzer_results) -> str:
        """Anonymize detected PII."""
        if not self.anonymizer:
            return text
        
        operators = {
            "DEFAULT": OperatorConfig(
                "replace",
                {"new_value": "<PII>"}
            )
        }
        
        result = self.anonymizer.anonymize(
            text=text,
            analyzer_results=analyzer_results,
            operators=operators,
        )
        
        return result.text
    
    async def detect_in_messages(
        self,
        messages: list[dict],
        score_threshold: float = 0.5,
        anonymize: bool = True,
    ) -> tuple[bool, list[dict], list[str]]:
        """
        Detect PII in chat messages.
        
        Returns:
            Tuple of (has_pii, processed_messages, pii_types_found)
        """
        all_pii_types = set()
        has_any_pii = False
        processed_messages = []
        
        for msg in messages:
            content = msg.get("content", "")
            if not isinstance(content, str):
                processed_messages.append(msg)
                continue
            
            result = await self.detect(
                text=content,
                score_threshold=score_threshold,
                anonymize=anonymize,
            )
            
            if result.has_pii:
                has_any_pii = True
                all_pii_types.update(result.pii_types)
                
                if anonymize and result.anonymized_text:
                    msg = msg.copy()
                    msg["content"] = result.anonymized_text
            
            processed_messages.append(msg)
        
        return has_any_pii, processed_messages, list(all_pii_types)
    
    def is_high_risk(self, result: PIIDetectionResult) -> bool:
        """Check if detected PII includes high-risk entities."""
        return any(
            entity in self.HIGH_RISK_ENTITIES
            for entity in result.pii_types
        )


# Global detector instance
pii_detector = PIIDetector()


async def get_pii_detector() -> PIIDetector:
    """Get PII detector instance."""
    return pii_detector
