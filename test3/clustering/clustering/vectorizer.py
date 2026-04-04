from sklearn.feature_extraction.text import TfidfVectorizer

vectorizer = TfidfVectorizer()

email_texts = []

def fit_vectorizer(new_email):
    email_texts.append(new_email)
    return vectorizer.fit_transform(email_texts)

def transform_email(email):
    return vectorizer.transform([email])