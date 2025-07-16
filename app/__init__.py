from flask import Flask
import nltk
from dotenv import load_dotenv

nltk.download('punkt')
nltk.download('stopwords')
load_dotenv()

app = Flask(__name__)

