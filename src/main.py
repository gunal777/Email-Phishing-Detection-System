import imaplib
import email
import re
from plyer import notification   # For desktop notifications
from bs4 import BeautifulSoup   
import nltk
from nltk.tokenize import word_tokenize
import getpass
import joblib
from collections import Counter
import time
from imapclient import IMAPClient

nltk.download("punkt")
nltk.download("stopwords")
nltk.download("wordnet")

# Clean and extract a valid email address
def clean_email_address(email_address):
    email = re.search(r"[\w\.-]+@[\w\.-]+", email_address)
    if email:
        return email.group(0)
    return email_address


# Connect to the email server using IMAP
def connect_to_email(username, password, server="imap.gmail.com"):
    try:
        mail = imaplib.IMAP4_SSL(server)
        mail.login(username, password)
        return mail
    except Exception as e:
        print(f"Error connecting to email: {str(e)}")
        return None


# Check if a URL is suspicious based on patterns
def check_suspicious_url(url):
    suspicious_patterns = [
        r"http:(www\.)?//.+",  # Capture URLs without optional spaces around colons
        r"(https?)?://(www\.)?bit\.ly(/.*)?",  # URL shorteners are common in phishing.
        r"@.*\.ru",  # Foreign domains sometimes raise red flags.
        r"(https?)?://tinyurl.com(/.*)?",  # URL shorteners.
        r"(https?)?://ow\.ly",
        r"^https?://[a-z0-9.-]+\.yourbank\.com\.example\.com$",  # Subdomain checks
        r"^https?://[a-z0-9.-]+\.paypal\.com\.scam\.com$",  # Subdomain checks
        r"^https?://[a-z0-9.-]+\.facebook\.com\.login\.secure\.com$",
        r"@[a-z0-9]+\.(ru|cn|tk|xyz|info)",  # URLs containing suspicious country domains
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            return True
    return False


# Send desktop notifications for phishing threats
def send_desktop_notification(subject, sender_email, score, classification):
    if score >= 10:
        try:
            # Create the notification message
            title = "Phishing Threat Detected!"
            msg_body = (
                f"Phishing Email Detected!\n\n"
                f"Classification - {classification}\n"
                f"Subject: {subject}\n"
                f"From: {sender_email}\n"
                f"Phishing Score: {score}/20"
            )

            # Send the notification using plyer
            notification.notify(
                title=title,
                message=msg_body,
                timeout=10  # Notification duration in seconds
            )

            print("Desktop notification sent about phishing threat.")
        except Exception as e:
            print(f"Error sending desktop notification: {str(e)}")


# Custom tokenization function to extract URLs and tokenize text
def custom_tokenize(text):
    tokens = []
    url_pattern = r"(https?://\S+)"
    for match in re.finditer(url_pattern, text):
        tokens.append(match.group())
    text = re.sub(url_pattern, "", text)
    tokens.extend(word_tokenize(text))
    return tokens


# Preprocess email content by cleaning and tokenizing
def email_preprocessing(email_content):
    # Remove HTML tags and special characters
    email_content = re.sub(r"<.*?>", "", email_content)
    email_content = re.sub(r"[^\w\s\.\-\/\:]", "", email_content.lower())

    # Tokenize the email_content
    tokens = custom_tokenize(email_content)
    return tokens


# Remove stopwords from tokens, keeping important words
def stopword_removal(tokens):
    custom_stopwords = [ "a", "an", "the", "is", "it", "of", "to", "and", "as"]

    filtered_tokens = []
    for word in tokens:
        if word not in custom_stopwords:
            filtered_tokens.append(word)
    return " ".join(filtered_tokens)


# Rate phishing potential based on email content
def rate_phishing(subject, email_content, urgent_keywords):
    score = 0

    # Check for common phishing indicators
    # 1. Suspicious URLs
    urls = re.findall(r'(https?://\S+)', email_content)
    j=1
    for url in urls:
        if check_suspicious_url(url):
            if(j>0):
                score += 3
                j=j-1
            
        elif re.search(r'[^\x00-\x7F]', url):  # Check for non-ASCII characters in URLs
            score += 1

    # 2. Urgent language (common in phishing attempts)
    i=1
    for keyword in urgent_keywords:
        if re.search(rf"\b{re.escape(keyword)}\b", email_content, re.IGNORECASE):
            if(i>0):
                score += 2
                i=i-1
        
    prediction = ml_model_prediction(subject, email_content)
    if(prediction == 1):
        score += 10          
            
    return score


# Fetch the latest email from the inbox
def fetch_last_email(mail):
    mail.select("inbox")
    _, data = mail.search(None, "ALL")

    # Get the list of email IDs
    email_ids = data[0].split()
    latest_email_id = email_ids[-1]

    # Fetch the latest email
    _, email_data = mail.fetch(latest_email_id, "(RFC822)")
    message = email.message_from_bytes(email_data[0][1])

    From = message.get("From")
    sender_email = clean_email_address(From)
    subject = message.get("Subject")
    
    email_content = ""

    for part in message.walk():
        content_type = part.get_content_type()
        
        # Check for plain text content
        if content_type == "text/plain":
            try:
                email_content = part.get_payload(decode=True).decode("utf-8")
                break 
            except Exception as e:
                print(f"Error decoding plain text content: {str(e)}")
        
        # If HTML content
        elif content_type == "text/html":
            try:
                html_content = part.get_payload(decode=True).decode("utf-8")
                email_content = BeautifulSoup(html_content, "html.parser").get_text()
            except Exception as e:
                print(f"Error decoding HTML content: {str(e)}")

    if not email_content:
        email_content = "(No readable content available)"

    print(f"Subject: {subject}")
    print(f"From: {sender_email}")
    print(f"Content: {email_content[:200]}")  # Print first 200 characters of the content
    print("=" * 50)

    return email_content, subject, sender_email


# Score the phishing potential based on email content and sender
def score(email_content, subject, sender_email, important_words):
    score = rate_phishing(subject, email_content, important_words)
    if score >= 10:
        classification = "Highly Dangerous"
    elif score >=5:
        classification = "Suspicious"
    else:
        classification = "Safe"

    print(f"Phishing Score: {score}/20 - Classification: {classification}")
    
    if (score>=10):
        send_desktop_notification(subject, sender_email, score, classification)
            

def ml_model_prediction(subject, email_content):
    text = [subject + " " + email_content]
    
    vectorizer = joblib.load(r"models\vectorizer.joblib") 
    emails_count = vectorizer.transform(text)
    
    #Load models
    model_LR = joblib.load(r"models\model_Logistic_Regression")
    model_NB = joblib.load(r"models\model_Naive_Bayes")
    model_RF = joblib.load(r"models\model_Random_Forest")

    # Collect predictions
    predictions = [
        model_NB.predict(emails_count)[0],
        model_RF.predict(emails_count)[0],
        model_LR.predict(emails_count)[0],
    ]
    
    # Use majority voting
    prediction_counter = Counter(predictions)
    majority_prediction = prediction_counter.most_common(1)[0][0]
    
    print(f"Predictions: {predictions}")
    print(f"Final Prediction (Majority Vote): {majority_prediction}")
    
    return majority_prediction


def email_idle_listener(username, password, server="imap.gmail.com", port=993):
    while True:
        try:
            with IMAPClient(server, port, use_uid=True, ssl=True) as client:
                client.login(username, password)
                client.select_folder("INBOX")  # Fallback to INBOX
                
                print("Starting IMAP IDLE mode. Waiting for new emails...")
                
                previous_email_count = len(client.search("ALL"))
                client.idle()

                try:
                    while True:
                        responses = client.idle_check(timeout=30)
                        if responses:
                            print("New event detected, checking for new emails...")
                            client.idle_done()

                            # Check for new email count
                            current_email_count = len(client.search("ALL"))
                            if current_email_count > previous_email_count:
                                print("New email detected!")

                                mail = connect_to_email(username, password)
                                email_content, subject, sender_email = fetch_last_email(mail)

                                important_words = {
                                    "click", "verify", "verify account", "password", "urgent", "hurry up",
                                    "sign up", "action required", "important", "click here","refund",
                                    "alert", "last chance", "debit", "suspended","payment", "your account"
                                }
                                tokens = email_preprocessing(email_content)
                                text = stopword_removal(tokens)
                                score(text, subject, sender_email, important_words)

                                previous_email_count = current_email_count

                            client.idle()  # Restart IDLE after handling the event

                except Exception as idle_error:
                    print(f"IDLE mode error: {idle_error}")
                    client.idle_done()  # Clean up IDLE before reconnecting

        except Exception as e:
            print(f"Connection error: {e}. Reconnecting in 30 seconds...")
            time.sleep(30)  

def main():
    username = getpass.getpass("Enter your email ID: ")
    password = getpass.getpass("Enter your password: ") 
    
    # Start the email listener
    email_idle_listener(username, password)

if __name__ == "__main__":
    main()