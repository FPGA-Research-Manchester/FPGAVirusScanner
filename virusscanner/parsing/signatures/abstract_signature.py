from abc import ABC


class VirusSignature(ABC):
    """Abstract class for virus detectors."""
    def detect_virus(self) -> float:
        pass
