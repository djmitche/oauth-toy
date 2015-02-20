# coding: utf-8

from datetime import datetime, timedelta
import logging
import base64
from flask import Flask
from flask import Response
from flask import session, request
from flask import render_template, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import gen_salt
from werkzeug.exceptions import Forbidden


app = Flask(__name__, template_folder='templates')
app.debug = True
app.secret_key = 'secret'
app.config.update({
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})
db = SQLAlchemy(app)

log = logging.getLogger("app")


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)


class Client(db.Model):
    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), nullable=False)

    user_id = db.Column(db.ForeignKey('user.id'))
    user = db.relationship('User')

    _redirect_uris = db.Column(db.Text)
    _default_scopes = db.Column(db.Text)

    @property
    def grant_type(self):
        return 'authorization_code'

    @property
    def response_type(self):
        return 'code'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []


class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')

    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    code = db.Column(db.String(255), index=True, nullable=False)

    redirect_uri = db.Column(db.String(255))
    expires_at = db.Column(db.DateTime)

    _scopes = db.Column(db.Text)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id')
    )
    user = db.relationship('User')

    # currently only bearer is supported
    token_type = db.Column(db.String(40))

    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires_at = db.Column(db.DateTime)
    _scopes = db.Column(db.Text)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


# Skeleton for an OAuth 2 Web Application Server which is an OAuth
# provider configured for Authorization Code, Refresh Token grants and
# for dispensing Bearer Tokens.

# This example is meant to act as a supplement to the documentation,
# see http://oauthlib.readthedocs.org/en/latest/.

from oauthlib.oauth2 import RequestValidator, WebApplicationServer


class SkeletonValidator(RequestValidator):

    # Ordered roughly in order of appearance in the authorization grant flow

    # Pre- and post-authorization.

    def validate_client_id(self, client_id, request, *args, **kwargs):
        # Simple validity check, does client exist? Not banned?
        client = load_client(client_id)
        return bool(client)

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        # Is the client allowed to use the supplied redirect_uri? i.e. has
        # the client previously registered this EXACT redirect uri.
        client = load_client(client_id)
        return redirect_uri in client.redirect_uris

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        # The redirect used if none has been supplied.
        # Prefer your clients to pre register a redirect uri rather than
        # supplying one on each authorization request.
        pass

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        # Is the client allowed to access the requested scopes?
        return True

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        # Scopes a client will authorize for if none are supplied in the
        # authorization request.
        return []

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        return response_type == 'code'

    # Post-authorization

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.redirect_uri
        # request.client, request.state and request.user (the last is passed in
        # post_authorization credentials, i.e. { 'user': request.user}.
        save_grant(client_id, code, request)

    # Token request

    def authenticate_client(self, request, *args, **kwargs):
        # Whichever authentication method suits you, HTTP Basic might work
        _, s = request.headers.get('Authorization', 'None None').split(' ')
        client_id, client_secret = base64.b64decode(s).split(':')
        client = load_client(client_id)
        if client_secret != client.client_secret:
            return False

        request.client = client
        return True

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        # Don't allow public (non-authenticated) clients
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        # Validate the code belongs to the client. Add associated scopes,
        # state and user to request.scopes, request.state and request.user.
        grant = load_grant(client_id, code)
        if not grant:
            return False
        request.scopes = grant.scopes
        #request.state = grant.state -- not needed?
        request.user = grant.user
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        # You did save the redirect uri with the authorization code right?
        grant = load_grant(client_id, code)
        if not grant:
            return False
        return redirect_uri == grant.redirect_uri

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of grant.
        # In this case, it must be "authorization_code" or "refresh_token"
        return grant_type in ('authorization_code', 'refresh_token')

    def save_bearer_token(self, token, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.user and
        # request.client. The two former will be set when you validate
        # the authorization code. Don't forget to save both the
        # access_token and the refresh_token and set expiration for the
        # access_token to now + expires_in seconds.
        save_token(token, request)

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Authorization codes are use once, invalidate it when a Bearer token
        # has been acquired.
        delete_grant(client_id, code)

    # Protected resource request

    def validate_bearer_token(self, token, scopes, request):
        # Remember to check expiration and scope membership
        tok = load_token(token)
        if set(scopes) <= set(tok.scopes):
            # XXX also expiration
            return True

    # Token refresh request

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # Obtain the token associated with the given refresh_token and
        # return its scopes, these will be passed on to the refreshed
        # access token if the client did not specify a scope during the
        # request.
        tok = load_token(refresh_token=refresh_token)
        return tok.scopes

    def validate_refresh_token(self, refresh_token, client, request,
                               *args, **kwargs):
        """Ensure the token is valid and belongs to the client

        This method is used by the authorization code grant indirectly by
        issuing refresh tokens, resource owner password credentials grant
        (also indirectly) and the refresh token grant.
        """

        tok = load_token(refresh_token=refresh_token)
        if tok and tok.client_id == client.client_id:
            request.client_id = tok.client_id
            request.user = tok.user
            return True


validator = SkeletonValidator()
server = WebApplicationServer(validator)

# from flask-oauthlib
def _get_uri_from_request(request):
    """
    The uri returned from request.uri is not properly urlencoded
    (sometimes it's partially urldecoded) This is a weird hack to get
    werkzeug to return the proper urlencoded string uri
    """
    uri = request.base_url
    if request.query_string:
        uri += '?' + request.query_string.decode('utf-8')
    return uri


def extract_params():
    """Extract request params."""

    uri = _get_uri_from_request(request)
    http_method = request.method
    headers = dict(request.headers)

    body = request.form.to_dict()
    return uri, http_method, body, headers

def create_response(headers, body, status):
    """Create response class for Flask."""
    response = Response(body or '')
    for k, v in headers.items():
        response.headers[str(k)] = v

    response.status_code = status
    return response

def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


@app.route('/', methods=('GET', 'POST'))
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        return redirect('/')
    user = current_user()
    return render_template('home.html', user=user)


@app.route('/client')
def client():
    user = current_user()
    if not user:
        return redirect('/')
    item = Client(
        client_id=gen_salt(40),
        client_secret=gen_salt(50),
        _redirect_uris=' '.join([
            'http://172.16.1.22:8011/authorized',
            ]),
        _default_scopes='email',
        user_id=user.id,
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(
        client_id=item.client_id,
        client_secret=item.client_secret,
    )


def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()


def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()


def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires_at = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=current_user(),
        expires_at=expires_at
    )
    db.session.add(grant)
    db.session.commit()
    return grant


def delete_grant(client_id, code):
    Grant.query.filter_by(client_id=client_id, code=code).delete()
    db.session.commit()


def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


def save_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id
    )
    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

    expires_in = token.pop('expires_in')
    expires_at = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires_at=expires_at,
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    db.session.add(tok)
    db.session.commit()
    return tok


@app.route('/oauth/token', methods=['POST'])
def access_token():
    uri, http_method, body, headers = extract_params()
    ret = server.create_token_response(
        uri, http_method, body, headers)
    return create_response(*ret)


@app.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize(*args, **kwargs):
    user = current_user()
    if not user:
        log.warning("no user; redirecting to /")
        return redirect('/') # TODO: with params or session set up to link back here
    uri, http_method, body, headers = extract_params()
    if request.method == 'GET':
        scopes, credentials = server.validate_authorization_request(
                        uri, http_method, body, headers)
        credentials.pop('request') # not json-able, not needed?
        credentials['scopes'] = scopes
        env = {
            'scopes': scopes,
            'user': user,
        }
        # XXX what the heck are these?
        session['credentials'] = credentials
        return render_template('authorize.html', **env)

    confirm = request.form.get('confirm', 'no')
    if confirm != 'yes':
        return redirect('/')
    else:
        credentials = session['credentials']
        del session['credentials']
        ret = server.create_authorization_response(
            uri, http_method, body, headers, 
            request.form.get('scopes'),
            credentials)
        return create_response(*ret)


@app.route('/api/me')
def me():
    uri, http_method, body, headers = extract_params()

    valid, r = server.verify_request(
            uri, http_method, body, headers, ['email'])
    if not valid:
        raise Forbidden

    return jsonify(username='me')


if __name__ == '__main__':
    db.create_all()
    app.run(host='0.0.0.0', port=8010)
