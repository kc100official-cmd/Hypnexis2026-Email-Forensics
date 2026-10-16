import re
from typing import Dict, Any, List, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import numpy as np

from data.synthetic_dataset import TRAINING_DATA

class EmailThreatClassifier:
    """
    Lightweight, fast, explainable TF-IDF + Logistic Regression Classifier
    as specified in SIH26106 slides.
    """
    def __init__(self):
        self.pipeline: Pipeline = None
        self.is_trained: bool = False
        self._train_model()

    def _train_model(self):
        texts = [item["text"] for item in TRAINING_DATA]
        labels = [item["label"] for item in TRAINING_DATA]

        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                ngram_range=(1, 2),
                stop_words='english',
                max_features=2500,
                sublinear_tf=True
            )),
            ('clf', LogisticRegression(
                C=2.0,
                max_iter=500,
                class_weight='balanced'
            ))
        ])

        self.pipeline.fit(texts, labels)
        self.is_trained = True

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Classifies email text, returns probability, score, and influential keywords.
        """
        if not text or len(text.strip()) < 10:
            return {
                "prediction": "Inconclusive",
                "label": 0,
                "phishing_probability": 0.10,
                "ml_score": 10,
                "top_keywords": []
            }

        probs = self.pipeline.predict_proba([text])[0]
        phishing_prob = float(probs[1]) # probability of class 1 (phishing)
        label = int(np.argmax(probs))

        # Extract top influential tokens for explainability
        top_keywords = self._explain_prediction(text)

        prediction_text = "Phishing / Malicious Threat" if phishing_prob >= 0.50 else "Legitimate / Benign"
        ml_score = int(round(phishing_prob * 100))

        return {
            "prediction": prediction_text,
            "label": label,
            "phishing_probability": round(phishing_prob, 3),
            "ml_score": ml_score,
            "top_keywords": top_keywords
        }

    def _explain_prediction(self, text: str, top_n: int = 5) -> List[Tuple[str, float]]:
        """
        Calculates feature importance of tokens present in the input text
        based on TF-IDF weights and Logistic Regression coefficients.
        """
        try:
            vectorizer: TfidfVectorizer = self.pipeline.named_steps['tfidf']
            classifier: LogisticRegression = self.pipeline.named_steps['clf']

            feature_names = np.array(vectorizer.get_feature_names_out())
            coefficients = classifier.coef_[0]

            # Vectorize input text
            tfidf_vec = vectorizer.transform([text]).toarray()[0]
            non_zero_indices = np.where(tfidf_vec > 0)[0]

            token_contributions = []
            for idx in non_zero_indices:
                feature = feature_names[idx]
                coef = coefficients[idx]
                score = tfidf_vec[idx] * coef
                if coef > 0: # Tokens pushing towards phishing
                    token_contributions.append((feature, round(float(score), 3)))

            # Sort by highest positive contribution
            token_contributions.sort(key=lambda x: x[1], reverse=True)
            return token_contributions[:top_n]
        except Exception:
            return []

# Singleton instance for quick reuse
_classifier_instance = None

def get_classifier() -> EmailThreatClassifier:
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = EmailThreatClassifier()
    return _classifier_instance
