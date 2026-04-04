import numpy as np

def extract_url_features(url):
    return [
        len(url),
        url.count('.'),
        url.count('-'),
        1 if 'https' in url else 0,
        1 if '@' in url else 0,
        1 if len(url) > 25 else 0
    ]

def extract_text_features(text):
    text = text.lower()
    return [
        1 if 'urgent' in text else 0,
        1 if 'verify' in text else 0,
        1 if 'click' in text else 0,
        1 if 'password' in text else 0,
        1 if 'bank' in text else 0,
        len(text)
    ]

def extract_behavior_features(work_hours, workdays):
    return [
        1 if work_hours == 0 else 0,   # outside work hours
        1 if workdays == 0 else 0      # weekend
    ]

def extract_features(text, url, work_hours, workdays):
    return np.array(
        extract_text_features(text) +
        extract_url_features(url) +
        extract_behavior_features(work_hours, workdays)
    )