import math


class DomainRiskAnalyzer:
    DEFAULT_SUSPICIOUS_TLDS = [
        "zip",
        "mov",
        "top",
        "xyz",
        "click",
        "icu",
        "cyou",
        "gq",
        "tk",
        "ml",
        "cf",
    ]
    DEFAULT_SUSPICIOUS_KEYWORDS = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "wallet",
        "reset",
    ]

    def __init__(self, config=None):
        browser_config = (config or {}).get("browser_threat_protection", {})
        self.enabled = browser_config.get("enabled", True)
        self.risk_threshold = int(browser_config.get("risk_threshold", 60))
        self.suspicious_tlds = {
            self._normalize_token(tld)
            for tld in browser_config.get("suspicious_tlds", self.DEFAULT_SUSPICIOUS_TLDS)
        }
        self.suspicious_keywords = {
            self._normalize_token(keyword)
            for keyword in browser_config.get(
                "suspicious_keywords",
                self.DEFAULT_SUSPICIOUS_KEYWORDS,
            )
        }

    def analyze(self, domain):
        normalized_domain = self.normalize_domain(domain)
        labels = [label for label in normalized_domain.split(".") if label]
        registered_label = labels[-2] if len(labels) >= 2 else labels[0] if labels else ""
        tld = labels[-1] if labels else ""
        score = 0
        reasons = []

        keyword_matches = sorted(
            keyword for keyword in self.suspicious_keywords if keyword in normalized_domain
        )
        if keyword_matches:
            score += min(35, 15 + len(keyword_matches) * 5)
            reasons.append(f"suspicious keywords: {', '.join(keyword_matches)}")

        if tld in self.suspicious_tlds:
            score += 25
            reasons.append(f"suspicious tld: .{tld}")

        if len(registered_label) >= 24:
            score += 20
            reasons.append("excessive domain label length")
        elif len(registered_label) >= 18:
            score += 10
            reasons.append("long domain label")

        digit_ratio = self._digit_ratio(registered_label)
        if digit_ratio >= 0.35 and len(registered_label) >= 8:
            score += 20
            reasons.append("high digit ratio")
        elif digit_ratio >= 0.20 and len(registered_label) >= 8:
            score += 10
            reasons.append("elevated digit ratio")

        hyphen_count = registered_label.count("-")
        if hyphen_count >= 3:
            score += 15
            reasons.append("many hyphens")
        elif hyphen_count >= 2:
            score += 8
            reasons.append("multiple hyphens")

        entropy = self._entropy(registered_label)
        vowel_ratio = self._vowel_ratio(registered_label)
        if len(registered_label) >= 12 and entropy >= 3.4 and vowel_ratio < 0.30:
            score += 30
            reasons.append("DGA-like randomness")
        elif len(registered_label) >= 10 and entropy >= 3.2:
            score += 15
            reasons.append("entropy-like randomness")

        score = min(score, 100)
        return {
            "domain": normalized_domain,
            "risk_score": score,
            "risk_level": self.risk_level(score),
            "reasons": reasons,
        }

    def should_alert(self, risk_result):
        return self.enabled and risk_result["risk_score"] >= self.risk_threshold

    @classmethod
    def risk_level(cls, score):
        if score >= 80:
            return "High"
        if score >= 60:
            return "Medium"
        if score >= 30:
            return "Low"
        return "None"

    @staticmethod
    def normalize_domain(domain):
        return str(domain or "").strip().rstrip(".").lower()

    @staticmethod
    def _normalize_token(value):
        return str(value or "").strip().lstrip(".").lower()

    @staticmethod
    def _digit_ratio(value):
        if not value:
            return 0
        return sum(1 for character in value if character.isdigit()) / len(value)

    @staticmethod
    def _vowel_ratio(value):
        letters = [character for character in value.lower() if character.isalpha()]
        if not letters:
            return 0
        return sum(1 for character in letters if character in "aeiou") / len(letters)

    @staticmethod
    def _entropy(value):
        if not value:
            return 0
        counts = {}
        for character in value:
            counts[character] = counts.get(character, 0) + 1
        entropy = 0
        for count in counts.values():
            probability = count / len(value)
            entropy -= probability * math.log2(probability)
        return entropy
