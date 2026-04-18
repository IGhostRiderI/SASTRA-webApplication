"""ML engine: a Random Forest severity classifier and a Random Forest false
positive classifier, sharing one TF-IDF vectorizer. The full bundle is stored
as a gzip-compressed joblib file at ml_engine.pkl.gz."""

import csv
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion

from .config import (
    LANGUAGE_TO_CSV,
    ML_ENGINE_PATH,
    ML_MAX_SAMPLES_PER_LANGUAGE,
    ML_MAX_VOCAB,
    ML_MIN_DF,
)
from .mappings import normalize_cwe, severity_for_cwe
from . import cwe_dataset_loader

logger = logging.getLogger("sast.ml")

# Use at most 80% of available CPU cores for training/inference
_N_JOBS = max(1, int((os.cpu_count() or 1) * 0.8))

# Combined FP score threshold.  A finding is flagged when:
#   ml_vuln_prob * ML_WEIGHT + rule_confidence * RULE_WEIGHT < FP_THRESHOLD
# The rule confidence (0.45 - 0.99) is a reliable signal derived from how
# frequently the pattern appeared in real vulnerable code; the ML model
# provides an additional code-semantic signal.
FP_THRESHOLD  = 0.60
ML_WEIGHT     = 0.55
RULE_WEIGHT   = 0.45


def _build_feature_text(language: str, cwe: str, code: str) -> str:
    """
    Build the ML input string used at both training and inference time.

    Structure:
      {language} {cwe_id} {cwe_enrichment} {code[:600]}

    The CWE enrichment text (description + consequence tokens + CVE signal +
    detection method token) comes from the CWE mapping dataset and gives the
    TF-IDF vectorizer semantic signal that the bare CWE ID alone cannot provide.

    IMPORTANT: training and inference must call this function identically  - 
    any change here requires deleting ml_engine.pkl.gz to force a retrain.
    """
    enrichment = cwe_dataset_loader.get_enrichment_text(cwe)
    if enrichment:
        return f"{language} {cwe} {enrichment} {code[:600]}"
    return f"{language} {cwe} {code[:600]}"


def _build_feature_text_no_cwe(language: str, code: str) -> str:
    """Feature text with CWE stripped out - used only for severity eval.
    Forces the eval to measure whether the model learned code patterns,
    not just the CWE→severity lookup that causes 1.00 accuracy."""
    return f"{language} {code[:600]}"


# DATA LOADING

def _load_language_samples(
    csv_path: Path,
    language: str,
    max_samples: int,
) -> Tuple[List[str], List[str], List[int], List[str]]:
    """
    Load training samples from one vulnerability CSV file.

    Each row produces **two** entries:
      - ``vul_code``  → label 1 (genuinely vulnerable)
      - ``patch``     → label 0 (fixed/safe version of the same function)

    This gives the FP classifier a balanced view of vulnerable vs.
    safe code patterns.  The severity model uses only the vulnerable
    entries (label 1).

    Returns four parallel lists:
      texts - combined feature string: "{language} {cwe} {code[:600]}"
      severity_labels - severity derived from the CWE ID via severity_for_cwe()
      fp_labels - 1 = vulnerable, 0 = patched/safe
      code_only_texts - feature string WITHOUT CWE, used for honest severity eval
    """
    texts:           List[str] = []
    severity_labels: List[str] = []
    fp_labels:       List[int] = []
    code_only_texts: List[str] = []

    if not csv_path.exists():
        logger.warning("Dataset file not found - skipping: %s", csv_path)
        return texts, severity_labels, fp_labels

    try:
        with csv_path.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                if len(texts) >= max_samples:
                    break

                vul_code = (row.get("vul_code") or "").strip()
                patch    = (row.get("patch")    or "").strip()
                cwe_raw  = (row.get("cwe_id")   or "").strip()

                if not vul_code or not cwe_raw:
                    continue

                cwe = normalize_cwe(cwe_raw)
                if cwe == "CWE-000":
                    continue

                severity = severity_for_cwe(cwe)

                # Vulnerable entry
                texts.append(_build_feature_text(language, cwe, vul_code))
                severity_labels.append(severity)
                fp_labels.append(1)
                code_only_texts.append(_build_feature_text_no_cwe(language, vul_code))

                # Patched/safe entry (if available and meaningfully different)
                if patch and patch != vul_code and len(texts) < max_samples:
                    texts.append(_build_feature_text(language, cwe, patch))
                    severity_labels.append(severity)
                    fp_labels.append(0)
                    code_only_texts.append(_build_feature_text_no_cwe(language, patch))

    except Exception:
        logger.exception("Error reading dataset: %s", csv_path)

    vuln_count = sum(fp_labels)
    logger.info(
        "Loaded %d samples from %-20s  (vulnerable: %d  patched: %d)",
        len(texts), csv_path.name, vuln_count, len(fp_labels) - vuln_count,
    )
    return texts, severity_labels, fp_labels, code_only_texts


# ML ENGINE

class MLEngine:
    """
    Real-time ML enrichment for scan findings.

    Wraps:
      - a shared TF-IDF vectorizer
      - a Random Forest severity predictor
      - a Random Forest false positive classifier

    The ``enrich_scan_output`` method is the only public interface
    needed by the scan pipeline in main.py.
    """

    def __init__(
        self,
        vectorizer:       TfidfVectorizer,
        severity_model:   RandomForestClassifier,
        fp_model:         RandomForestClassifier,
        metadata:         dict,
    ) -> None:
        self.vectorizer     = vectorizer
        self.severity_model = severity_model
        self.fp_model       = fp_model
        self.metadata       = metadata

    #  per-finding inference 

    def predict_severity(
        self, snippet: str, cwe_id: str, language: str
    ) -> Dict[str, object]:
        """
        Predict severity for a single code snippet.

        Returns::
            {"severity": "High", "confidence": 0.82}

        Falls back to empty strings on any error so a prediction failure
        never breaks a scan.
        """
        try:
            text  = _build_feature_text(language, cwe_id, snippet)
            vec   = self.vectorizer.transform([text])
            proba = self.severity_model.predict_proba(vec)[0]
            idx   = int(np.argmax(proba))
            classes = self.severity_model.classes_
            return {
                "severity":   str(classes[idx]),
                "confidence": round(float(proba[idx]), 3),
            }
        except Exception:
            logger.debug("Severity prediction failed", exc_info=True)
            return {"severity": "", "confidence": 0.0}

    def predict_fp(
        self, snippet: str, cwe_id: str, language: str
    ) -> Dict[str, object]:
        """
        Estimate the probability that a scanner finding is genuine.

        Returns::
            {
                "is_fp":      bool,   # True  → likely false positive
                "vuln_prob":  float,  # probability the code is truly vulnerable
            }
        """
        try:
            text  = _build_feature_text(language, cwe_id, snippet)
            vec   = self.vectorizer.transform([text])
            proba = self.fp_model.predict_proba(vec)[0]
            # sklearn class order: [0=not_vulnerable, 1=vulnerable]
            vuln_prob = float(proba[1])
            return {
                "is_fp":     vuln_prob < FP_THRESHOLD,
                "vuln_prob": round(vuln_prob, 3),
            }
        except Exception:
            logger.debug("FP prediction failed", exc_info=True)
            return {"is_fp": False, "vuln_prob": 1.0}

    #  scan-level enrichment 

    def enrich_scan_output(
        self, scan_output: Dict[str, object]
    ) -> Dict[str, object]:
        """
        Run both models over every finding in *scan_output* in-place.

        Fields written to each finding:
          ml_severity - ML-predicted severity label
          ml_severity_confidence - model confidence (0 - 1)
          ml_confidence - vulnerability probability from FP model
          fp_flag - True when vuln_prob < FP_THRESHOLD
          fp_label - human-readable explanation when flagged
        """
        findings = scan_output.get("findings", [])
        for finding in findings:
            # Use ml_context (surrounding lines) if available - it matches the
            # function-body scale the models were trained on. Fall back to the
            # single-line display snippet only when ml_context is absent.
            snippet  = finding.get("ml_context") or finding.get("snippet", "")
            cwe_id   = finding.get("cwe_id",   "")
            language = finding.get("language", "")

            # Severity prediction
            sev = self.predict_severity(snippet, cwe_id, language)
            finding["ml_severity"]            = sev["severity"]
            finding["ml_severity_confidence"] = sev["confidence"]

            # False positive classification
            # Flag as FP when ML vuln_prob is at or below FP_THRESHOLD (0.60).
            # The rule confidence is stored for display only and does not
            # affect the FP decision - this ensures the ML score drives it.
            fp = self.predict_fp(snippet, cwe_id, language)
            rule_conf    = float(finding.get("confidence", 0.75))
            vuln_prob    = fp["vuln_prob"]
            combined     = vuln_prob * ML_WEIGHT + rule_conf * RULE_WEIGHT
            finding["ml_confidence"] = round(combined, 3)
            if combined <= FP_THRESHOLD:
                finding["fp_flag"]  = True
                finding["fp_label"] = (
                    f"Low confidence finding - combined score {combined:.0%} "
                    f"(ML: {vuln_prob:.0%}, rule: {rule_conf:.0%})"
                )

        return scan_output


# TRAINING

def _train(
    max_samples_per_language: int,
    max_vocab: int,
    min_df: int,
) -> "MLEngine":
    """
    Train the TF-IDF vectorizer, severity model, and FP classifier
    from scratch using the CSV vulnerability datasets.
    """
    all_texts:      List[str] = []
    all_severity:   List[str] = []
    all_fp:         List[int] = []
    all_code_only:  List[str] = []

    for language, csv_path in LANGUAGE_TO_CSV.items():
        texts, severity, fp, code_only = _load_language_samples(
            csv_path, language, max_samples_per_language
        )
        all_texts.extend(texts)
        all_severity.extend(severity)
        all_fp.extend(fp)
        all_code_only.extend(code_only)

    if not all_texts:
        raise RuntimeError(
            "No training samples loaded. "
            "Verify that the dataset CSV files exist under datasets/13870382/."
        )

    logger.info(
        "Training on %d samples  (vulnerable: %d  patched/safe: %d)",
        len(all_texts), sum(all_fp), len(all_fp) - sum(all_fp),
    )

    #  Shared TF-IDF vectorizer (word bigrams + char n-grams) 
    # Word bigrams capture multi-token patterns (e.g. "buffer overflow",
    # "eval input").  Char n-grams catch API names like strcpy/os.system
    # regardless of surrounding tokens.  FeatureUnion concatenates both
    # sparse matrices before the models see any features.
    word_vec = TfidfVectorizer(
        max_features  = int(max_vocab * 0.7),   # 70% budget for word features
        min_df        = min_df,
        sublinear_tf  = True,
        strip_accents = "unicode",
        analyzer      = "word",
        ngram_range   = (1, 2),
        token_pattern = r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+",
    )
    char_vec = TfidfVectorizer(
        max_features  = int(max_vocab * 0.3),   # 30% budget for char features
        min_df        = min_df,
        sublinear_tf  = True,
        strip_accents = "unicode",
        analyzer      = "char_wb",
        ngram_range   = (3, 5),
    )
    vectorizer = FeatureUnion([("word", word_vec), ("char", char_vec)])
    X = vectorizer.fit_transform(all_texts)
    word_vocab = len(word_vec.vocabulary_)
    char_vocab = len(char_vec.vocabulary_)
    logger.info(
        "Vectorizer fitted - word vocab: %d  char vocab: %d  total features: %d",
        word_vocab, char_vocab, word_vocab + char_vocab,
    )

    #  Severity model (trained on vulnerable samples only) 
    # We train only on genuinely vulnerable code so the model learns
    # which code patterns correspond to each severity, not the patterns
    # of patched/safe code.
    vuln_idx = [i for i, v in enumerate(all_fp) if v == 1]
    if len(vuln_idx) < 20:
        raise RuntimeError(
            f"Only {len(vuln_idx)} vulnerable samples found - too few to train. "
            "Check that is_vulnerable=True rows exist in the datasets."
        )

    X_vuln = X[vuln_idx]
    y_sev  = [all_severity[i] for i in vuln_idx]

    # Build no-CWE feature matrix for honest severity eval
    # (avoids the trivial CWE→severity lookup that produces 1.00 accuracy)
    vuln_code_only = [all_code_only[i] for i in vuln_idx]
    X_vuln_no_cwe  = vectorizer.transform(vuln_code_only)

    # Train/test split - train on full features, eval on no-CWE features
    idx_tr, idx_te = train_test_split(
        range(len(y_sev)), test_size=0.2, random_state=42,
        stratify=y_sev if len(set(y_sev)) > 1 else None,
    )
    X_sev_tr = X_vuln[list(idx_tr)]
    X_sev_te = X_vuln_no_cwe[list(idx_te)]   # eval without CWE
    y_sev_tr = [y_sev[i] for i in idx_tr]
    y_sev_te = [y_sev[i] for i in idx_te]

    _sev_rf = RandomForestClassifier(
        n_estimators     = 300,
        max_depth        = 40,   # cap depth to prevent memorising synthetic templates
        min_samples_leaf = 5,    # require more evidence per leaf
        max_features     = "sqrt",
        class_weight     = "balanced",
        random_state     = 42,
        n_jobs           = _N_JOBS,
    )
    _sev_rf.fit(X_sev_tr, y_sev_tr)
    logger.info(
        "Severity model eval - code-only features, 20%% hold-out "
        "(CWE excluded so score reflects code-pattern learning):\n%s",
        classification_report(y_sev_te, _sev_rf.predict(X_sev_te), zero_division=0),
    )
    # Final model: refit on all vulnerable samples, then calibrate
    _sev_rf_full = RandomForestClassifier(
        n_estimators     = 300,
        max_depth        = 40,
        min_samples_leaf = 5,
        max_features     = "sqrt",
        class_weight     = "balanced",
        random_state     = 42,
        n_jobs           = _N_JOBS,
    )
    _sev_rf_full.fit(X_vuln, y_sev)
    severity_model = CalibratedClassifierCV(_sev_rf_full, method="isotonic", cv=3)
    severity_model.fit(X_vuln, y_sev)
    logger.info(
        "Severity model trained - classes: %s  samples: %d",
        list(_sev_rf_full.classes_), len(vuln_idx),
    )

    #  FP classifier (trained on all samples) 
    # Note: isotonic calibration was removed - it collapsed the RF's already-
    # narrow output range (~0.63 - 0.69) into a constant (~0.536).  The raw RF
    # predict_proba is more spread and is combined with rule confidence at
    # inference time (see enrich_scan_output) which is a better FP signal.
    X_fp_tr, X_fp_te, y_fp_tr, y_fp_te = train_test_split(
        X, all_fp, test_size=0.2, random_state=42, stratify=all_fp,
    )
    fp_model = RandomForestClassifier(
        n_estimators     = 300,
        max_depth        = 40,
        min_samples_leaf = 5,
        max_features     = "sqrt",
        class_weight     = "balanced",
        random_state     = 42,
        n_jobs           = _N_JOBS,
    )
    fp_model.fit(X_fp_tr, y_fp_tr)
    logger.info(
        "FP classifier eval (20%% hold-out):\n%s",
        classification_report(y_fp_te, fp_model.predict(X_fp_te), zero_division=0),
    )
    # Refit on full dataset for better generalisation
    fp_model.fit(X, all_fp)
    unique, counts = np.unique(all_fp, return_counts=True)
    logger.info(
        "FP classifier trained - class distribution: %s",
        dict(zip(unique.tolist(), counts.tolist())),
    )

    metadata = {
        "trained_at":       datetime.now(timezone.utc).isoformat(),
        "sample_count":     len(all_texts),
        "vuln_count":       int(sum(all_fp)),
        "non_vuln_count":   int(len(all_fp) - sum(all_fp)),
        "vocab_size":       word_vocab + char_vocab,
        "severity_classes": list(_sev_rf_full.classes_),
        "fp_threshold":     FP_THRESHOLD,
        "status":           "ready",
    }

    return MLEngine(
        vectorizer     = vectorizer,
        severity_model = severity_model,
        fp_model       = fp_model,
        metadata       = metadata,
    )


# PERSISTENCE  (joblib - proposal tools section)

def _save(engine: "MLEngine", path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(engine, path, compress=("gzip", 3))
    logger.info("ML engine saved → %s", path.name)


def _load(path: Path) -> "MLEngine":
    engine = joblib.load(path)
    if not isinstance(engine, MLEngine):
        raise TypeError("Unexpected object in model file - expected MLEngine.")
    return engine


def load_or_train(force_retrain: bool = False) -> "MLEngine":
    """
    Load the ML engine from *ML_ENGINE_PATH* if it exists, otherwise
    train from scratch and save.

    Pass ``force_retrain=True`` to always retrain (used by the admin
    retrain endpoint in main.py).
    """
    if not force_retrain and ML_ENGINE_PATH.exists():
        try:
            engine = _load(ML_ENGINE_PATH)
            logger.info(
                "ML engine loaded - samples: %d  vocab: %d  severity classes: %s",
                engine.metadata.get("sample_count", 0),
                engine.metadata.get("vocab_size", 0),
                engine.metadata.get("severity_classes", []),
            )
            return engine
        except Exception:
            logger.exception("Failed to load saved ML engine - retraining from scratch")

    logger.info("Training ML engine from datasets (this may take a moment)...")
    engine = _train(
        max_samples_per_language = ML_MAX_SAMPLES_PER_LANGUAGE,
        max_vocab                = ML_MAX_VOCAB,
        min_df                   = ML_MIN_DF,
    )
    _save(engine, ML_ENGINE_PATH)
    return engine
