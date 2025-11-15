# ——— ROUTES ———
@app.route('/')
def home():
    return render_template('index.html')
    
# Routes for all HTML files in templates folder - USE render_template FOR ALL
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

@app.route('/hash-generator')
def hash_generator():
    return render_template('hash-generator.html')

@app.route('/password-tools')
def password_tools():
    return render_template('password-tools.html')

@app.route('/file-scanner')
def file_scanner():
    return render_template('file-scanner.html')

@app.route('/network-tools')
def network_tools():
    return render_template('network-tools.html')

@app.route('/checker')
def checker():
    return render_template('checker.html')

@app.route('/checker-thankyou')
def checker_thankyou():
    return render_template('checker-thankyou.html')

@app.route('/demo_thank_you')
def demo_thank_you():
    return render_template('demo_thank_you.html')

@app.route('/home')
def home_page():
    return render_template('home.html')

@app.route('/incident-playbook')
def incident_playbook():
    return render_template('incident-playbook.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/newsletter')
def newsletter():
    return render_template('newsletter.html')

@app.route('/next_steps')
def next_steps():
    return render_template('next_steps.html')

@app.route('/playbook')
def playbook():
    return render_template('playbook.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/subscribe-thankyou')
def subscribe_thankyou():
    return render_template('subscribe-thankyou.html')

@app.route('/thank-you')
def thank_you():
    return render_template('thank-you.html')

@app.route('/verify_link')
def verify_link():
    return render_template('verify_link.html')

@app.route('/whoisxmlapi')
def whoisxmlapi():
    return render_template('whoisxmlapi.html')

@app.route('/404')
def not_found_page():
    return render_template('404.html')