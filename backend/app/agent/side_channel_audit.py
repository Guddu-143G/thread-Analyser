"""
Version 23: Hardware-Assisted Secure Enclave (SEP) Bypassing
Differential Power Analysis (DPA) and Correlation Power Analysis (CPA) Side-Channel Auditing.
"""

import numpy as np
from typing import Dict, Any, List, Tuple, Optional

class SideChannelAuditor:
    """
    Simulates non-destructive Differential Power Analysis (DPA) and Correlation Power Analysis (CPA)
    audits over cryptographic hardware boundaries to test passcode verification leakage.
    """
    def __init__(self, key_length: int = 8):
        self.key_length = key_length
        # Mock physical power trace consumption template per byte
        self.leakage_model = np.array([8, 12, 15, 6, 14, 2, 9, 11][:key_length], dtype=np.float32)

    def generate_power_traces(
        self,
        inputs: np.ndarray,
        target_key: Optional[np.ndarray] = None,
        noise_level: float = 0.3
    ) -> np.ndarray:
        """
        Generates simulated physical power consumption traces of the hardware chip.
        Power consumption is proportional to the Hamming Weight of Input XOR Key plus Gaussian thermal noise.
        """
        num_traces = inputs.shape[0]
        traces = np.zeros((num_traces, self.key_length), dtype=np.float32)
        actual_key = target_key if target_key is not None else np.array([0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x32, 0x33][:self.key_length], dtype=np.uint8)

        for i in range(num_traces):
            # Calculate Hamming weight of (input byte XOR key byte)
            xor_result = inputs[i] ^ actual_key
            hamming_weight = np.array([bin(int(b)).count('1') for b in xor_result], dtype=np.float32)
            noise = np.random.normal(0, noise_level, self.key_length)
            traces[i] = (hamming_weight * self.leakage_model) + noise

        return traces

    @staticmethod
    def pearson_correlation(x: np.ndarray, y: np.ndarray) -> float:
        """Computes sample Pearson correlation coefficient between two 1D numpy arrays."""
        if len(x) < 2:
            return 0.0
        x_diff = x - np.mean(x)
        y_diff = y - np.mean(y)
        numerator = np.sum(x_diff * y_diff)
        denominator = np.sqrt(np.sum(x_diff ** 2) * np.sum(y_diff ** 2))
        if denominator == 0:
            return 0.0
        return float(numerator / denominator)

    def correlate_key_candidates(
        self,
        inputs: np.ndarray,
        traces: np.ndarray,
        num_candidates: int = 256
    ) -> Dict[str, Any]:
        """
        Executes Correlation Power Analysis (CPA) to reconstruct Key candidates.
        Calculates Pearson correlation between experimental traces and leakage hypotheses.
        """
        best_keys = np.zeros(self.key_length, dtype=np.uint8)
        correlation_matrix = []
        max_corr_value = 0.0

        for byte_idx in range(self.key_length):
            byte_correlations = []
            for candidate in range(num_candidates):
                expected_hw = np.array([bin(int(inp) ^ candidate).count('1') for inp in inputs[:, byte_idx]], dtype=np.float32)
                corr = self.pearson_correlation(expected_hw, traces[:, byte_idx])
                byte_correlations.append((candidate, abs(corr)))

            # Sort by highest correlation spike
            byte_correlations.sort(key=lambda x: x[1], reverse=True)
            best_candidate, best_corr = byte_correlations[0]
            best_keys[byte_idx] = best_candidate
            max_corr_value = max(max_corr_value, best_corr)

            correlation_matrix.append({
                "byte_index": byte_idx,
                "recovered_byte_hex": f"0x{best_candidate:02X}",
                "recovered_char": chr(best_candidate) if 32 <= best_candidate <= 126 else ".",
                "correlation_peak": round(best_corr, 4),
                "top_candidates": [
                    {"candidate_hex": f"0x{cand:02X}", "correlation": round(c_val, 4)}
                    for cand, c_val in byte_correlations[:5]
                ]
            })

        recovered_hex = "".join(f"{b:02X}" for b in best_keys)
        recovered_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in best_keys)

        return {
            "key_length_bytes": self.key_length,
            "traces_analyzed_count": int(inputs.shape[0]),
            "max_correlation_peak": round(max_corr_value, 4),
            "recovered_key_hex": recovered_hex,
            "recovered_key_text": recovered_text,
            "correlation_matrix": correlation_matrix,
            "status": "KEY_RECONSTRUCTED_HIGH_CONFIDENCE" if max_corr_value > 0.7 else "MODERATE_CORRELATION"
        }
