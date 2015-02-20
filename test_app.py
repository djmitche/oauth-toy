from flask import redirect
from flask import request
import uuid
import json
import base64
import urllib

import contextlib
from app import app
import logging


# TODO: insert client_id on setup

class Client(object):
    """A simple test client.  Note that this stores all of its metadata
    as instance attributes, which works fine here (with only one user) but
    isn't a great idea in the real world."""

    def __init__(self, app):
        self.client_id = "JxDVCOOZyG1foRLEY1NlBATaa4JuKbd3414BHuIN"
        self.client_secret = "TpyxzOIPs6k9xr0Y5o9EbqjHioun3BAJmYlMxZIeYxCSNnB7v0"
        self.redirect_uri = 'http://localhost/cl/authorized'
        app.route('/cl')(self.client_connect)
        app.route('/cl/authorized')(self.authorized)
        self.state = None
        self.refresh_token = self.access_token = None

    def client_connect(self):
        if not self.refresh_token:
            self.state = str(uuid.uuid4())

            url = '/oauth/authorize'
            url += '?response_type=code'
            url += '&client_id=' + urllib.quote_plus(self.client_id)
            url += '&redirect_uri=' + urllib.quote_plus(self.redirect_uri)
            url += '&scope=email'
            url += '&state=' + urllib.quote_plus(self.state)
            return redirect(url)

        # TODO: access a protected resource here
        return 'SUCCESS'

    def authorized(self):
        assert request.args['state'] == self.state
        code = request.args['code']

        # use a fresh test client to trade that code in for an auth token
        with app.test_client() as tc:
            auth_header = 'Bearer {}'.format(
                    base64.b64encode('{}:{}'.format(self
                        .client_id, self.client_secret)))
            r = tc.post('/oauth/token', data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': self.redirect_uri,
                'client_id': self.client_id
            }, headers={'Authorization': auth_header})
            result = json.loads(r.data)
            assert result['token_type'].lower() == 'bearer'
        self.access_token = result['access_token']
        self.refresh_token = result['refresh_token']
        return redirect('/cl')


class Browser(object):

    """A *very* simple model of a browser, able to be redirected and handle
    cookies.  It has "loaded" a single page at any given time, represented
    by a Response in the `page` attribute."""

    def __init__(self, client):
        self.client = client
        self.url = None
        self.page = None
        self.log = logging.getLogger('browser')

    def _meth(self, meth, url, *args, **kwargs):
        self.log.info("{} {}".format(meth, url))
        follow_redirects = kwargs.pop('follow_redirects', False)
        self.url = url
        self.page = r = getattr(self.client, meth)(url, *args, **kwargs)
        self.log.info(">> {}".format(r))
        if follow_redirects and r.status_code == 302:
            new_loc = r.location.replace('http://localhost', '')
            return self.get(new_loc, follow_redirects=True)
        return self.page

    def get(self, *args, **kwargs):
        return self._meth('get', *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._meth('post', *args, **kwargs)

    # purpose-specific methods

    def assert_login_form(self):
        assert self.url == '/' and 'any username' in self.page.data

    def login(self, username):
        self.log.info("logging in as {}".format(username))
        self.post('/', {'username': username}, follow_redirects=True)

    def access_client(self):
        self.log.info("accessing OAuth2 client")
        self.get('/cl', follow_redirects=True)

    def assert_authorize_form(self):
        assert self.url.startswith('/oauth/authorize') and \
               'Allow access?' in self.page.data

    def submit_authorize_form(self, authorized):
        self.log.info("submitting authorization form (authorized={})".format(authorized))
        return self.post('/oauth/authorize',
                         data={'confirm': 'yes' if authorized else 'no'},
                         follow_redirects=True)


@contextlib.contextmanager
def test_browser():
    with app.test_client() as client:
        yield Browser(client)


def test_sequence():
    cl = Client(app)
    with test_browser() as browser:
        browser.access_client()
        browser.assert_login_form()
        browser.login('dustin')
        browser.assert_login_form()
        # XXX redirect doesn't re-try the authorization, so try it again
        browser.access_client()
        browser.assert_authorize_form()
        r = browser.submit_authorize_form(True)
        print r.data
