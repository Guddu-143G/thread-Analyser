import re
import json
from typing import Dict, Any, Optional

class RealTimeTechStackExtractor:
    """
    Dynamically analyzes normalized process telemetry and socket binds 
    to extract and maintain an accurate running Tech Stack profile of the host.
    """
    def __init__(self, signature_config_path: str):
        with open(signature_config_path, "r") as f:
            self.signatures = json.load(f).get("signatures", [])

    def extract_fingerprint(self, process_name: str, arguments: str, local_port: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Parses process parameters to dynamically identify target application technologies.
        """
        for sig in self.signatures:
            # Check process name match
            if process_name and re.search(sig["process_regex"], process_name, re.IGNORECASE):
                # Check arguments match
                if not sig["arguments_regex"] or (arguments and re.search(sig["arguments_regex"], arguments, re.IGNORECASE)):
                    # Check port match if telemetry is available
                    port_matched = False
                    if local_port is not None and local_port == sig["default_port"]:
                        port_matched = True
                    
                    confidence = "very_high" if port_matched else sig["confidence"]
                    
                    return {
                        "technology": sig["tech_name"],
                        "category": sig["category"],
                        "confidence": confidence,
                        "detected_port": local_port or sig["default_port"],
                        "provenance": {
                            "process": process_name,
                            "command_line": arguments
                        }
                    }
        return None
