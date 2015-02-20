# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import Flask, url_for, session, request, jsonify, redirect
from flask_oauthlib.client import OAuth
import requests


CLIENT_ID = "dSMy1vk5yULBcbIWPDaarSAgSdgkALTQsDU3mCza"
CLIENT_SECRET = "gwa9qEajR2d1Rysy6iSvFM4uz8BqH9wi5kEoAvCveVkuAibQQN"

app = Flask(__name__)
app.debug = True
app.secret_key = 'secret4'
oauth = OAuth(app)

remote = oauth.remote_app(
    'remote',
    consumer_key=CLIENT_ID,
    consumer_secret=CLIENT_SECRET,
    request_token_params={'scope': 'email'},
    base_url='http://euclid.r.igoro.us:8010/api/',
    request_token_url=None,
    access_token_url='http://euclid.r.igoro.us:8010/oauth/token',
    authorize_url='http://euclid.r.igoro.us:8010/oauth/authorize'
)


@app.route('/')
def index():
    if 'remote_oauth' in session:
        resp = remote.get('me')
        return jsonify(data=resp.data)
    next_url = request.args.get('next') or request.referrer or None
    return remote.authorize(
        callback=url_for('authorized', next=next_url, _external=True)
    )


@app.route('/authorized')
@remote.authorized_handler
def authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    if isinstance(resp, Exception):
        return 'Access denied: ' + resp.message
    session['remote_oauth'] = (resp['access_token'], '')
    return redirect('/')


@remote.tokengetter
def get_oauth_token():
    return session.get('remote_oauth')


if __name__ == '__main__':
    import os
    os.environ['DEBUG'] = 'true'
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    app.run(host='0.0.0.0', port=8011)
