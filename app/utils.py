from nltk.tokenize import word_tokenize

def clean_text(text, stop_words):
    tokens = word_tokenize(text)
    return ' '.join([w for w in tokens if w.lower() not in stop_words and w.isalpha()])
