from typing import List, Dict

class AnomalyScorer:
    def __init__(self):
        self.baseline_sizes = {}

    def set_baseline(self, endpoint: str, size: int):
        self.baseline_sizes[endpoint] = size

    def evaluate_mutant(self, result: Dict) -> Dict:
        """
        Analyzes the result of an executed mutant workflow.
        Returns a score indicating the likelihood of a vulnerability (BOLA/BFLA).
        """
        score = 0.0
        findings = []

        status = result.get("status_code", 0)
        body_len = result.get("body_len", 0)

        if status in [200, 201, 204]:
            score += 0.8
            findings.append("Privileged action succeeded under lower role.")
        elif status in [401, 403]:
            score += 0.0
            findings.append("Blocked by auth/RBAC as expected.")
        elif status == 500:
            score += 0.4
            findings.append("Unhandled exception triggered (potential logic flaw/race condition).")

        return {
            "workflow_id": result.get("workflow_id"),
            "vuln_score": score,
            "findings": findings
        }

    def score_batch(self, results: List[Dict]) -> List[Dict]:
        scored = []
        for r in results:
            scored.append(self.evaluate_mutant(r))
            
        # Sort by highest vulnerability score
        scored.sort(key=lambda x: x["vuln_score"], reverse=True)
        return scored
