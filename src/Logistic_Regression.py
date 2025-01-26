import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib

# Load dataset
df = pd.read_csv(r"Data\Phishing_email_dataset.csv")

# Combine Email Content and Subject into a single feature
df["Combined"] = df["Email_Content"] + " " + df["Subject"]

# Split data into training and test sets
X_train, X_test, y_train, y_test = train_test_split(df['Combined'], df["Label"], train_size=0.8)

# Load the pre-trained vectorizer
vectorizer = joblib.load(r'models\vectorizer.joblib')  

# Transform training and test data using the vectorizer
tfidf_matrix = vectorizer.transform(X_train)
X_test_count = vectorizer.transform(X_test)

# Train a Logistic Regression model
model = LogisticRegression()
model.fit(tfidf_matrix, y_train)

# Evaluate the model on test data
y_pred = model.predict(X_test_count)
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average='binary')
recall = recall_score(y_test, y_pred, average='binary')
f1 = f1_score(y_test, y_pred, average='binary')

# Print evaluation metrics
print(f"Accuracy: {accuracy}")
print(f"Precision: {precision}")
print(f"Recall: {recall}")
print(f"F1-Score: {f1}")

# Save the trained Logistic Regression model (if needed)
joblib.dump(model, r'models\model_Logistic_Regression')

# Test the model on a new email sample
emails = [
    """Invitation to Webinar join us exclusive webinar future technology . click link register : register"""
]

# Transform the email sample
emails_count = vectorizer.transform(emails)

# Make predictions with the Logistic Regression model
p = model.predict(emails_count)
if p == 1:
    print("Prediction : Phishing!")
else:
    print(f"Prediction : Legitimate")
