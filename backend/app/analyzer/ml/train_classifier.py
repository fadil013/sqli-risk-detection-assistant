"""Trains the XGBoost field-category classifier and saves it to
model.pkl. Run manually to (re)generate the model:

    python -m app.analyzer.ml.train_classifier

Why synthetic training data: no real-world dataset of manually-labeled
"is this field a database identifier / auth field / ..." exists for
us to train on, and hand-labeling thousands of examples isn't a good
use of time for a Phase-2 baseline. Instead we bootstrap labels
straight from knowledge_base.py's own keyword lists — the model's
"ground truth" IS the rule engine. That sounds circular, but the
payoff is real: the model is trained on *structural* features
(field_length, contains_id, contains_password, ...), not the literal
keyword strings, so it generalizes to names that are NOT in any
keyword list (e.g. "user_id_2", "newPasswordConfirm") the same way a
human skimming field names would, where a pure dictionary lookup
would just say "unknown".
"""
from __future__ import annotations

import pickle
import random
from pathlib import Path

from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder

from app.analyzer.knowledge_base import keyword_sets_by_category
from app.analyzer.ml_features import METHODS, PAGE_TYPES, build_feature_vector

MODEL_PATH = Path(__file__).parent / "model.pkl"

# Genuinely unrelated field names — the "none of the above" class.
UNKNOWN_NAMES = [
    "theme", "color", "language", "timezone", "fontsize", "volume",
    "brightness", "layout", "units", "currencydisplay", "darkmode",
    "notifications", "autosave", "zoomlevel", "colorscheme", "wallpaper",
]

# Structural variants of each real keyword, so the model sees more than
# the exact dictionary string — this is what teaches it to generalize.
def _variants(keyword: str) -> list[str]:
    return [keyword, f"{keyword}2", f"{keyword}Field", f"new{keyword.capitalize()}", f"{keyword}_value"]


def _generate_dataset(rows_per_name: int = 4, seed: int = 42) -> tuple[list[list[float]], list[str]]:
    rng = random.Random(seed)
    X: list[list[float]] = []
    y: list[str] = []

    def add_examples(name: str, label: str) -> None:
        for _ in range(rows_per_name):
            page_type = rng.choice(PAGE_TYPES)
            method = rng.choice(METHODS)
            is_api = rng.choice([True, False])
            X.append(build_feature_vector(name, page_type, method, is_api))
            y.append(label)

    for category, keywords in keyword_sets_by_category().items():
        for keyword in keywords:
            for variant in _variants(keyword):
                add_examples(variant, category)

    for name in UNKNOWN_NAMES:
        for variant in _variants(name):
            add_examples(variant, "unknown")

    return X, y


def train() -> None:
    X, y = _generate_dataset()

    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)

    model = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.2,
        objective="multi:softprob",
        num_class=len(encoder.classes_),
        eval_metric="mlogloss",
    )
    model.fit(X, y_encoded)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"model": model, "encoder": encoder}, f)

    train_accuracy = model.score(X, y_encoded)
    print(f"Trained on {len(X)} synthetic examples across {len(encoder.classes_)} categories.")
    print(f"Training accuracy: {train_accuracy:.3f} (expected near-1.0 — this is a sanity check on")
    print("synthetic data the model was built from, NOT a real-world generalization metric.")
    print(f"Saved to {MODEL_PATH}")


if __name__ == "__main__":
    train()
