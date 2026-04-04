from sklearn.metrics.pairwise import cosine_similarity
from test3.analyzers.clustering.clustering.vectorizer import fit_vectorizer, transform_email
from storage.email_store import stored_emails

THRESHOLD = 0.8

def detect_campaign(new_email):
    if len(stored_emails) == 0:
        fit_vectorizer(new_email)
        stored_emails.append(new_email)
        return 0, 1.0  # first campaign

    X = fit_vectorizer(new_email)
    new_vec = X[-1]

    similarities = cosine_similarity(new_vec, X[:-1])[0]

    max_sim = max(similarities)

    if max_sim > THRESHOLD:
        return 1, float(max_sim)  # same campaign
    else:
        return 0, float(max_sim)  # new campaign