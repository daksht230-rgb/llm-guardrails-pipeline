import re
from typing import Dict, Any, List

class LLMSafetyGuardrails:
    def __init__(self):
        # Patterns for prompt injection detection
        self.injection_patterns = [
            r"ignore previous instructions",
            r"disregard all prior rules",
            r"you are now unfiltered",
            r"system override",
            r"reveal your prompt"
        ]
        
        # Patterns for PII detection (Email, Phone Numbers, Credit Cards)
        self.pii_patterns = {
            "EMAIL": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "PHONE": r"\b\d{10}\b|\b\d{3}[-.\s]??\d{3}[-.\s]??\d{4}\b",
            "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b"
        }

    def detect_prompt_injection(self, text: str) -> bool:
        text_lower = text.lower()
        for pattern in self.injection_patterns:
            if re.search(pattern, text_lower):
                return True
        return False

    def redact_pii(self, text: str) -> Dict[str, Any]:
        redacted_text = text
        pii_found = []
        
        for pii_type, pattern in self.pii_patterns.items():
            matches = re.findall(pattern, redacted_text)
            if matches:
                pii_found.append(pii_type)
                redacted_text = re.sub(pattern, f"[REDACTED_{pii_type}]", redacted_text)
                
        return {
            "redacted_text": redacted_text,
            "has_pii": len(pii_found) > 0,
            "detected_pii_types": pii_found
        }

    def evaluate_input_safety(self, user_prompt: str) -> Dict[str, Any]:
        is_injection = self.detect_prompt_injection(user_prompt)
        pii_check = self.redact_pii(user_prompt)
        
        status = "PASSED"
        reason = "Input is clean and safe."
        
        if is_injection:
            status = "BLOCKED_INJECTION_RISK"
            reason = "Detected potential prompt injection attack pattern."
        elif pii_check["has_pii"]:
            status = "SANITIZED_PII_FOUND"
            reason = f"Contains sensitive PII data: {', '.join(pii_check['detected_pii_types'])}."
            
        return {
            "original_prompt": user_prompt,
            "sanitized_prompt": pii_check["redacted_text"],
            "guardrail_status": status,
            "action_reason": reason,
            "is_safe_to_proceed": status != "BLOCKED_INJECTION_RISK"
        }
