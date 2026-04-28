import pandas as pd
import os, re
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import accuracy_score
import joblib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "dataset", "spam_assassin.csv")

print("Dataset path:", DATA_PATH)

def clean_email_text(text):
    if not isinstance(text, str):
        return ""

    # Remove headers
    if "\n\n" in text:
        text = text.split("\n\n", 1)[1]

    text = text.lower()
    text = re.sub(r'https?://\S+', ' url ', text)
    text = re.sub(r'[^a-z\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()

    return text

if not os.path.exists(DATA_PATH):
    print("❌ Dataset not found.")
    exit(1)

df = pd.read_csv(DATA_PATH)
df = df.rename(columns={"text": "email_text", "target": "label"})
df.dropna(inplace=True)

print("Cleaning dataset...")
df["email_text"] = df["email_text"].apply(clean_email_text)
df = df[df["email_text"].str.len() > 10]

X = df["email_text"]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

vectorizer = TfidfVectorizer(stop_words="english", max_features=5000)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

print("Training Logistic Regression...")
lr = LogisticRegression(C=0.1, class_weight="balanced", max_iter=1000)
model = CalibratedClassifierCV(lr, cv=5)
model.fit(X_train_vec, y_train)

y_pred = model.predict(X_test_vec)

print("\nAccuracy:", accuracy_score(y_test, y_pred))

MODEL_DIR = os.path.join(BASE_DIR, "model")
os.makedirs(MODEL_DIR, exist_ok=True)

joblib.dump(model, os.path.join(MODEL_DIR, "phishing_model.pkl"))
joblib.dump(vectorizer, os.path.join(MODEL_DIR, "vectorizer.pkl"))

print("✅ Training complete")
