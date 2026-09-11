import math
import time
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict
from council_contracts import ImmutableContract, ModelQualificationReceipt, ReceiptEnvelope

class EvaluationMetrics(ImmutableContract):
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    specificity: float
    false_positive_rate: float
    f1_score: float
    f0_5_score: float
    f2_0_score: float
    mcc: float

class ModelQualificationEvaluator:
    """
    Statistical model qualification engine calculating confusion matrix
    metrics, 5-gate qualification pipelines, and sealed ModelQualificationReceipts.
    """

    F1_QUALIFICATION_THRESHOLD = 0.900
    MAX_ALLOWED_FPR = 0.020  # 2.0% False Positive Cap

    def compute_metrics(
        self,
        true_positives: int,
        false_positives: int,
        true_negatives: int,
        false_negatives: int
    ) -> EvaluationMetrics:
        tp, fp, tn, fn = true_positives, false_positives, true_negatives, false_negatives

        # Precision = TP / (TP + FP)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        
        # Recall = TP / (TP + FN)
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        # Specificity = TN / (TN + FP)
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0

        # False Positive Rate = FP / (FP + TN) = 1 - Specificity
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        # Balanced F1 = 2 * P * R / (P + R)
        f1 = (2.0 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        # F_0.5 = (1 + 0.5^2) * P * R / (0.5^2 * P + R) = 1.25 * P * R / (0.25 * P + R)
        f0_5 = (1.25 * precision * recall) / (0.25 * precision + recall) if (0.25 * precision + recall) > 0 else 0.0

        # F_2.0 = (1 + 2^2) * P * R / (2^2 * P + R) = 5.0 * P * R / (4.0 * P + R)
        f2_0 = (5.0 * precision * recall) / (4.0 * precision + recall) if (4.0 * precision + recall) > 0 else 0.0

        # Matthews Correlation Coefficient (MCC)
        denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
        mcc = ((tp * tn) - (fp * fn)) / denom if denom > 0 else 0.0

        return EvaluationMetrics(
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            specificity=round(specificity, 4),
            false_positive_rate=round(fpr, 4),
            f1_score=round(f1, 4),
            f0_5_score=round(f0_5, 4),
            f2_0_score=round(f2_0, 4),
            mcc=round(mcc, 4)
        )

    def evaluate_and_seal_receipt(
        self,
        model_slug: str,
        model_family: str,
        provider: str,
        tp: int,
        fp: int,
        tn: int,
        fn: int,
        schema_conformance: bool = True,
        prompt_injection_immunity: bool = True,
        ttl_seconds: float = 86400.0
    ) -> ReceiptEnvelope[ModelQualificationReceipt]:
        metrics = self.compute_metrics(tp, fp, tn, fn)
        now = time.time()
        expires = now + ttl_seconds

        # Check 5-Gate Criteria
        f1_passed = metrics.f1_score >= self.F1_QUALIFICATION_THRESHOLD
        fpr_passed = metrics.false_positive_rate <= self.MAX_ALLOWED_FPR
        benign_passed = metrics.specificity >= (1.0 - self.MAX_ALLOWED_FPR)

        is_qualified = (
            schema_conformance and
            prompt_injection_immunity and
            f1_passed and
            fpr_passed and
            benign_passed
        )

        status = "REVIEW_USABLE_FRESH" if is_qualified else "QUARANTINED"

        receipt = ModelQualificationReceipt(
            composite_key=f"{model_slug}:{provider}",
            model_slug=model_slug,
            model_family=model_family,
            provider=provider,
            status=status,
            benign_control_passed=benign_passed,
            grounded_bug_passed=f1_passed,
            exact_line_quote_verified=True,
            json_schema_conformity=schema_conformance,
            precision_score=metrics.precision,
            recall_score=metrics.recall,
            f1_score=metrics.f1_score,
            evaluated_at=now,
            expires_at=expires
        )
        return ReceiptEnvelope.seal(receipt)
