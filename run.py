from app import app
import os
import nltk

# nltk_data konumunu manuel belirle
os.environ['NLTK_DATA'] = '/usr/local/nltk_data'

# Gerekli modelleri (önlem olarak) tekrar indir
nltk.download('punkt', download_dir=os.environ['NLTK_DATA'])
nltk.download('stopwords', download_dir=os.environ['NLTK_DATA'])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
