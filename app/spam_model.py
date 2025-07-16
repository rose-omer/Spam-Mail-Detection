import pickle
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

def load_models():
    with open("model/model_tr.pkl", "rb") as f:
        model_tr = pickle.load(f)
    with open("model/vectorizer_tr.pkl", "rb") as f:
        vect_tr = pickle.load(f)
    with open("model/model_en.pkl", "rb") as f:
        model_en = pickle.load(f)
    with open("model/vectorizer_en.pkl", "rb") as f:
        vect_en = pickle.load(f)
    return model_tr, vect_tr, model_en, vect_en, set(stopwords.words('turkish')), set(stopwords.words('english'))

def get_spam_keywords(text, vectorizer, model):
    feature_names = vectorizer.get_feature_names_out()
    coefs = model.coef_[0]
    tokens = word_tokenize(text.lower())
    tokens = [t for t in tokens if t.isalpha()]
    spam_keywords = []
    threshold = 0.5
    for token in tokens:
        if token in feature_names:
            idx = list(feature_names).index(token)
            weight = coefs[idx]
            if weight > threshold:
                spam_keywords.append((token, weight))
    spam_keywords = sorted(spam_keywords, key=lambda x: x[1], reverse=True)
    return [kw[0] for kw in spam_keywords]
