from flask import Flask, render_template, request
import pickle
import test_data_preprocessing 
import warnings
from urllib.parse import urlparse
warnings.filterwarnings("ignore")
app = Flask(__name__)

model = pickle.load(open("C:\\Users\\AGASTYA SHANKER\\Python Files\\Detection of Phishing websites\\model_dt.pkl", 'rb'))
def is_complete_url(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme and parsed_url.netloc:
        return True
    else:
        return False
    

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        user_input = request.form['url']
        output_string = "" 
        if is_complete_url(user_input) :

            website_url = test_data_preprocessing.main(user_input)
            prediction = model.predict([website_url])
            # Return the prediction result to display on the page
            if prediction == 0 : 
                output_string = "Legitimate website"
            elif prediction == 1: 
                output_string = "Phishing website"
            else : 
                output_string = "Didn't worked"
        
        else : 
            output_string = "website url is incorrect" 

        return render_template('index.html', output_string = output_string)
    
    return render_template('index.html')
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    app.run(debug=True)

