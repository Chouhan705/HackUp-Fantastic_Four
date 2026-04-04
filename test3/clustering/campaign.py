from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

vectorizer = TfidfVectorizer()
stored_emails = []

THRESHOLD = 0.8

def detect_campaign(new_email):
    global stored_emails

    # First email case
    if len(stored_emails) == 0:
        stored_emails.append(new_email)
        return False, 1.0

    # Add email and vectorize
    stored_emails.append(new_email)
    X = vectorizer.fit_transform(stored_emails)

    new_vec = X[-1]
    old_vecs = X[:-1]

    similarities = cosine_similarity(new_vec, old_vecs)[0]
    max_sim = max(similarities)

    if max_sim > THRESHOLD:
        return True, float(max_sim)
    else:
        return False, float(max_sim)