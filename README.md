# 📧 Email Phishing Detection System  

An advanced system that detects phishing emails using natural language processing (NLP) and machine learning techniques. The program monitors email accounts in real-time, analyzes email content, and classifies emails based on their phishing potential.  

## 🚀 Features  
- **Real-Time Email Monitoring**: Connects to your email account using IMAP and monitors new emails.  
- **Phishing Detection**: Identifies suspicious emails using NLP and machine learning models.  
- **Desktop Notifications**: Alerts the user when a dangerous phishing email is detected.  
- **Content Analysis**: Extracts and analyzes URLs, urgent keywords, and other phishing indicators.  
- **ML Integration**: Employs Logistic Regression, Naive Bayes, and Random Forest models with majority voting for accurate predictions.  

## ⚙️ Technologies Used  
- **Programming Language**: Python  
- **Libraries**:  
  - `imaplib`, `email`, `BeautifulSoup`: Email handling and content parsing  
  - `nltk`: Natural language processing  
  - `joblib`: Model loading and persistence  
  - `plyer`: Desktop notifications  

## 🛠️ Installation and Usage  
1. **Clone the Repository**:  
   ```bash
   git clone https://github.com/yourusername/email-phishing-detection.git
   cd email-phishing-detection
   ```

2. **Install Dependencies**:  
   ```bash
   pip install -r requirements.txt
   ```

3. **Prepare Models**:
   * Add your pre-trained machine learning models in the `models` directory.
   * Ensure the models are named:
     * `vectorizer.joblib`
     * `model_Logistic_Regression`
     * `model_Naive_Bayes`
     * `model_Random_Forest`

4. **Run the Program**: Start the system and provide your email credentials:
   ```bash
   python phishing_detection.py
   ```

5. **Monitor Notifications**: The program will notify you if a phishing email is detected.

## 📂 Project Structure

```
Email_Phishing_Detection_System/
│
├── data/                    # Raw and processed stock data
├── src/                     # Source code for data fetching and model training
├── models/                  # Saved trained models
├── requirements.txt         # Project dependencies
├── main.py                  # Entry point for running the prediction model
└── LICENSE                  # License file

```


## 🔍 How It Works
1. **Connects to Email**: Logs into your email account using IMAP.
2. **Fetches Emails**: Retrieves and processes the latest email.
3. **Analyzes Content**:
   * Tokenizes and cleans email content.
   * Extracts suspicious URLs and keywords.
4. **Classifies Email**: Uses machine learning models to determine if the email is safe or a phishing attempt.
5. **Sends Notifications**: Alerts you for highly dangerous emails.

## 📝 License
This project is licensed under the MIT License. See the LICENSE file for details.

## 📬 Contact
Feel free to reach out with questions or contributions!

Email📧: gunalb81@gmail.com