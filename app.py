import os
import pathlib
from uuid import uuid4

from flask import Flask, render_template, send_from_directory, url_for, redirect, request, session, abort
from flask_uploads import UploadSet, IMAGES, configure_uploads
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

app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
)
delay = '500/minute'

app.config['SECRET_KEY'] = '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'
app.config['UPLOADED_PHOTOS_DEST'] = 'uploads'
app.static_folder = 'static'

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

GOOGLE_CLIENT_ID = "321951942693-g4533h1425tukpu8k4t3bceqf2ebuqgb.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, 'auth.json')
flow = Flow.from_client_secrets_file(client_secrets_file=client_secrets_file,
                                     scopes=["https://www.googleapis.com/auth/userinfo.profile",
                                             "https://www.googleapis.com/auth/userinfo.email", "openid"],
                                     redirect_uri="http://localhost:5000/callback")

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


if __name__ == '__main__':
    app.run(debug=True)
    # app.run(debug=True,host='192.168.1.13',port=8000)
