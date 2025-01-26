import pandas as pd 
from sklearn.model_selection import train_test_split 
from sklearn.ensemble import RandomForestClassifier  
from sklearn.feature_extraction.text import TfidfVectorizer 
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score  
import joblib 

# Load dataset
df = pd.read_csv(r"Data\Phishing_email_dataset.csv")  # Load dataset
df["Combined"] = df["Email_Content"] + " " + df["Subject"] 

# Split data into train/test sets
X_train, X_test, y_train, y_test = train_test_split(df['Combined'], df["Label"], train_size=0.9)

# Vectorize text data
vectorizer = TfidfVectorizer()
tfidf_matrix = vectorizer.fit_transform(X_train)
X_test_count = vectorizer.transform(X_test)

# Save vectorizer
joblib.dump(vectorizer, r'models\vectorizer.joblib')

# Train model
model = RandomForestClassifier()
model.fit(tfidf_matrix, y_train)

# Evaluate model
y_pred = model.predict(X_test_count)
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average='binary')
recall = recall_score(y_test, y_pred, average='binary')
f1 = f1_score(y_test, y_pred, average='binary')

# Print metrics
print(f"Accuracy: {accuracy}")
print(f"Precision: {precision}")
print(f"Recall: {recall}")
print(f"F1-Score: {f1}")

joblib.dump(model, r'models\model_Random_Forest')

# Test with new email
emails = ["Invitation to Webinar join us exclusive webinar future technology . click link register : register"]
emails_count = vectorizer.transform(emails)
p = model.predict(emails_count)

# Output prediction
if p == 1:
    print("Prediction : Phishing!")
else:
    print(f"Prediction : Legitimate")