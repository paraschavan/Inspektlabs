import os
import pathlib
from uuid import uuid4
import re

import psycopg2
from psycopg2 import Error
from flask import Flask, render_template, send_from_directory, url_for, redirect, request, session, abort
from flask_uploads import UploadSet, IMAGES, configure_uploads, TEXT
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import SubmitField

import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Assignment 1

app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
)
delay = '5/minute'

app.config['SECRET_KEY'] = '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14'
app.config['UPLOADED_PHOTOS_DEST'] = 'uploads'
app.config['UPLOADED_TEXT_DEST'] = 'uploads'

app.static_folder = 'static'

# os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

GOOGLE_CLIENT_ID = "321951942693-i43902ba8tgupahdp6o3gmvbjoo9edmt.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, 'auth.json')
flow = Flow.from_client_secrets_file(client_secrets_file=client_secrets_file,
                                     scopes=["https://www.googleapis.com/auth/userinfo.profile",
                                             "https://www.googleapis.com/auth/userinfo.email", "openid"],
                                     redirect_uri="https://inspektlabs.onrender.com/callback")

photos = UploadSet('photos', IMAGES)
configure_uploads(app, photos)


class UploadForm(FlaskForm):
    photo = FileField(
        validators=[
            FileAllowed(photos, 'Only Image File Is Allowed!'),
            FileRequired('File Field Should Not Be Empty!')
        ]
    )
    submit = SubmitField('Upload')


def login_is_required(function):
    def wrapper(*args, **kwargs):
        session['next_url'] = request.url
        if "google_id" not in session:
            # return abort(401)  # Authorization required
            return redirect('/login')
        else:
            return function(*args, **kwargs)

    wrapper.__name__ = function.__name__
    return wrapper


@app.route('/uploads/<filename>')
@limiter.limit(delay)
@login_is_required
def get_file(filename):
    return send_from_directory(app.config['UPLOADED_PHOTOS_DEST'], filename)


@app.route('/upload', methods=['GET', 'POST'])
@limiter.limit(delay)
@login_is_required
def upload_image():
    if request.method == 'POST':
        form = UploadForm()
        if form.validate_on_submit():
            filename = photos.save(form.photo.data)
            return redirect(f'/image/{filename}')

        elif request.files.get('photo'):
            photo = request.files.get('photo')
            # Save the image to a directory on your server
            filename = str(uuid4())[:8] + '.jpeg'
            photo.save(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], filename))
            return redirect(f'/image/{filename}')

    else:
        form = UploadForm()
        return render_template('upload.html', form=form)


@app.route('/image/<filename>')
@limiter.limit(delay)
@login_is_required
def image(filename):
    file_url = url_for('get_file', filename=filename)
    return render_template('image.html', file_url=file_url)


@app.route('/web')
@limiter.limit(delay)
@login_is_required
def web():
    return render_template('web.html')


@app.route('/mobile')
@limiter.limit(delay)
@login_is_required
def mobile():
    return render_template('mobile.html')


@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        return abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")

    if session.get('next_url'):
        return redirect(session.get('next_url'))
    else:
        return redirect('/upload')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/')
def index():
    return 'Index <a href="/login"><button>Login</button></a>'


# Assignment 2
host, database, user, password = os.environ['db'].split('|')
kwargs = {'host': host,
          'database': database,
          'user': user,
          'password': password}

text_uploads = UploadSet('text', TEXT)
configure_uploads(app, text_uploads)


def get_db_connection():
    conn = psycopg2.connect(**kwargs)
    return conn


def insertDB(data_to_insert):
    try:
        # Connect to the PostgreSQL database
        connection = get_db_connection()

        # Create a cursor object to interact with the database
        cursor = connection.cursor()

        # Define the SQL query to insert data into the "log" table
        insert_query = """INSERT INTO log (
            ip, user_identity, user_auth, timestamp, method, url, protocol, status, size, referrer, user_agent, other_info
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        );"""

        # Loop through the list of data tuples and insert each set of data
        for data in data_to_insert:
            cursor.execute(insert_query, data)

        # Commit the transaction
        connection.commit()

        print("Data inserted successfully!")

    except Error as e:
        print("Error:", e)

    finally:
        # Close the cursor and connection
        if cursor:
            cursor.close()
        if connection:
            connection.close()


class TextUploadForm(FlaskForm):
    text = FileField(
        validators=[
            FileAllowed(text_uploads, 'Only Text File Is Allowed!'),
            FileRequired('File Field Should Not Be Empty!')
        ]
    )
    submit = SubmitField('Upload')


@app.route('/log', methods=['GET', 'POST'])
def upload_log():
    form = TextUploadForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            file = form.text.data
            if file:
                # Optional Parameters -> Identity, User, Size of Response, Referrer, User-Agent, Other Info
                pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+)(?: (?P<identity>\S+))?(?: (?P<user>\S+))? \[(?P<timestamp>.*?)\] "(?P<method>\w+) (?P<url>.*?) (?P<protocol>HTTP/\d+\.\d+)" (?P<status>\d+)(?: (?P<size>\d+))?(?: "(?P<referrer>.*?)")?(?: "(?P<user_agent>.*?)")?(?: "(?P<other_info>.*?)")?'
                data = []
                try:
                    def read_file_line_by_line(file):
                        for line in file:
                            # Process each line here
                            yield line.decode('utf-8')  # Decode if needed (adjust the encoding)

                    # Use the generator function to process the file
                    for line in read_file_line_by_line(file):
                        # Process each line here
                        match = re.search(pattern, line.strip())
                        if match:
                            data.append((match.group('ip'), match.group('identity'), match.group('user'),
                                         match.group('timestamp')
                                         , match.group('method'), match.group('url'), match.group('protocol'),
                                         int(match.group('status')), match.group('size'),
                                         match.group('referrer'), match.group('user_agent'), match.group('other_info')))
                            # print("IP Address:", match.group('ip'))
                            # print("Identity:", match.group('identity'))
                            # print("User:", match.group('user'))
                            # print("Timestamp:", match.group('timestamp'))
                            # print("HTTP Method:", match.group('method'))
                            # print("Request URL:", match.group('url'))
                            # print("HTTP Protocol:", match.group('protocol'))
                            # print("Response Status Code:", match.group('status'))
                            # print("Size of Response:", match.group('size'))
                            # print("Referrer:", match.group('referrer'))
                            # print("User-Agent:", match.group('user_agent'))
                            # print("Other Info:", match.group('other_info'))
                            # print('Valid Data')
                        else:
                            pass
                            # print("Invalid Data.")
                            # print(f'{line}')

                except Exception as e:
                    # Handle exceptions that may occur during file processing
                    return f"<h1>An error occurred: {str(e)}</h1>"
        insertDB(data)
        return render_template('logView.html', data=data)

    else:
        return render_template('logUpload.html', form=form)


if __name__ == '__main__':
    app.run()
