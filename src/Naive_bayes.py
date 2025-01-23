import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
import matplotlib.pyplot as plt

# Load dataset and combine email content with subject for text processing
df = pd.read_csv(r"Data\Phishing_email_dataset.csv")
df["Combined"] = df["Email_Content"] + " " + df["Subject"]

# Split the dataset into training (80%) and testing (20%) sets
X_train, X_test, y_train, y_test = train_test_split(df['Combined'], df["Label"], train_size=0.8)

# Load pre-saved TF-IDF vectorizer and transform training/test data
vectorizer = joblib.load(r'models\vectorizer.joblib')  
tfidf_matrix = vectorizer.transform(X_train)   
X_test_count = vectorizer.transform(X_test)

# Initialize and train the Naive Bayes model
model = MultinomialNB()
model.fit(tfidf_matrix, y_train)

# Predict on test data and evaluate the model
y_pred = model.predict(X_test_count)
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average='binary')
recall = recall_score(y_test, y_pred, average='binary')
f1 = f1_score(y_test, y_pred, average='binary')

# Display model performance metrics
print(f"Accuracy: {accuracy}")
print(f"Precision: {precision}")
print(f"Recall: {recall}")
print(f"F1-Score: {f1}")

# Plot Actual vs Predicted labels
plt.scatter(range(len(y_test)), y_test, color='blue', label='Actual', alpha=0.6)
plt.scatter(range(len(y_pred)), y_pred, color='red', label='Predicted', alpha=0.6)

plt.title('Actual vs Predicted')
plt.xlabel('Sample Index')
plt.ylabel('Label (0 = Legitimate, 1 = Phishing)')
plt.legend()
plt.show()

# Uncomment to save the trained model
joblib.dump(model, r'models\model_Naive_Bayes')

# Predict phishing status for a new email example
emails = [
    """Invitation to Webinar. Join us for an exclusive webinar on *"The Future of Technology"""
]
emails_count = vectorizer.transform(emails)
p = model.predict(emails_count)

# Output the prediction result
if p == 1:
    print("Prediction: Phishing!")
else:
    print("Prediction: Legitimate")
