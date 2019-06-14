from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.secret_key = "How are mirrors real if our eyes aren't"

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

USER_KEY = "user_id"

@app.route('/')
def index():
    print("GET - Landing page - Render index.html")
    return render_template("index.html")

@app.route('/register', methods=['POST'])
def register():
    print("POST - Register page - Redirect to /success")

    is_valid = True
    if not EMAIL_REGEX.match(request.form['email']):
        is_valid = False
        flash('Please insert a valid email address', 'registration_email')
    if len(request.form['password']) < 8:
        is_valid = False
        flash('Please insert a valid password of at least 8 characters.', 'registration_password')    

    hashed_password = bcrypt.generate_password_hash(request.form['password'])
    string_password = request.form['confirmation_password']
    passwords_match = bcrypt.check_password_hash(hashed_password, string_password)

    if not passwords_match:
        flash('Confirmation password did not match, please try again.', 'registration_confirmation_password')
        is_valid = False
    if passwords_match:
        query = 'INSERT INTO users (first_name, last_name, email, password) VALUES (%(fname)s, %(lname)s, %(email)s, %(password)s);'
        data = {
            'fname' : request.form['first_name'],
            'lname' : request.form['last_name'],
            'email' : request.form['email'],
            'password' : hashed_password
        }
        mysql = connectToMySQL('private_wall')
        session[USER_KEY] = mysql.query_db(query, data)
        # print("SESSION KEY: " + str(session[USER_KEY]))
        return redirect('/success')        
    if not is_valid:
        return redirect('/')  

@app.route('/login', methods=["POST"])
def login():

    # Validating login fields
    is_valid = True
    if not EMAIL_REGEX.match(request.form['email']):
        is_valid = False
        flash('Please insert a valid email address', 'login_email')
    if len(request.form['password']) < 8:
        flash('Incorrect password, please try again', 'login_password')
        is_valid = False
    if not is_valid:
        return redirect('/')

    query = 'SELECT id, password FROM users WHERE email = %(email)s;'
    data = {
        'email' : request.form['email']
    }
    mysql = connectToMySQL('private_wall')
    user_id = mysql.query_db(query, data)

    string_password = request.form['password']
    if bcrypt.check_password_hash(user_id[0]['password'], string_password):
        session[USER_KEY] = user_id[0]['id']
        return redirect('/success')

    print('GET - Login Attempt - Redirect /success')
    print(session[USER_KEY])
    return redirect('/success')

@app.route('/success')
def successful_login():
    if USER_KEY in session:
        flash("Successful login!", "login_successful")
    print('GET - Successful Login Page - Render success.html')
    query = 'SELECT * FROM users WHERE id = %(id)s'    
    data = {
        'id' : session[USER_KEY]
    }
    mysql = connectToMySQL('private_wall')
    user_id = mysql.query_db(query, data)
    # print('User_ID: ' + str(user_id))

    #Query posts database and pull out all the recipients_id where id
    query = 'SELECT * FROM posts JOIN users ON posts.sender_id = users.id WHERE recipient_id = %(id)s AND posts.recipient_id != posts.sender_id;'
    data = {
        'id' : session[USER_KEY]
    }
    mysql = connectToMySQL('private_wall')
    posts = mysql.query_db(query, data)

    query = 'SELECT * FROM users WHERE id != %(id)s;'
    data = {
        'id' : session[USER_KEY]
    }
    mysql = connectToMySQL('private_wall')
    users = mysql.query_db(query, data)

    return render_template('success.html', user=user_id, posts=posts, all_users=users)

@app.route('/send_message/<id>', methods=["POST"])
def send_message(id):

    query = 'INSERT INTO posts (topic, content, sender_id, recipient_id) VALUES (%(topic)s, %(content)s, %(sid)s, %(rid)s);'
    data = {
        "topic" : request.form['topic'],
        "content" : request.form['content'],
        "sid"      : session[USER_KEY],
        "rid"      : id
    }
    mysql = connectToMySQL('private_wall')
    user_id = mysql.query_db(query, data)

    print(request.form['topic'])
    print(request.form['content'])
    print(session[USER_KEY])
    return redirect('/success')

@app.route('/destroy/<id>', methods=["POST"])
def delete_message(id):

    query = 'DELETE FROM posts WHERE id = %(id)s'
    data = {
        'id' : id
    }
    mysql = connectToMySQL('private_wall')
    deleted_message = mysql.query_db(query, data)
    return redirect('/success')

@app.route('/logout')
def logout():
    print('GET - User logging out')
    if session[USER_KEY]:
        flash("user successfully logged out", "logout")
        session.clear()
    return redirect('/')

@app.route('/create_message', methods=["POST"])
def create_message():
    # Validation
    # if not USER_KEY in session:
    #     return redirect('/')
    
    query = 'INSERT INTO posts (topic, content, sender_id) VALUES (%(topic)s, %(content)s, %(id)s);'
    data = {
        "topic" : request.form['topic'],
        "content" : request.form['content'],
        "id"      : session[USER_KEY]
    }
    mysql = connectToMySQL('private_wall')
    user_id = mysql.query_db(query, data)
    print("*"*20)
    print(data)
    return redirect('/success')

if __name__=="__main__":
    app.run(debug=True)