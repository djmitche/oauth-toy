# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import requests
import urlparse
import json
import urllib

CLIENT_ID = "dSMy1vk5yULBcbIWPDaarSAgSdgkALTQsDU3mCza"
CLIENT_SECRET = "gwa9qEajR2d1Rysy6iSvFM4uz8BqH9wi5kEoAvCveVkuAibQQN"
REDIRECT_URI = 'http://172.16.1.22:8011/authorized'
BASE_URL = 'http://euclid.r.igoro.us:8010/'


class Browser(object):

    """A *very* simple model of a browser, able to be redirected and handle
    cookies.  It is "displaying" a single page at any given time."""

    def __init__(self):
        self.session = requests.Session()
        self.page = self.session.get(BASE_URL)

    def get(self, *args, **kwargs):
        self.page = self.session.get(*args, **kwargs)
        return self.page

    def post(self, *args, **kwargs):
        self.page = self.session.post(*args, **kwargs)
        return self.page

    def login(self, username):
        self.post(BASE_URL, {'username': username})


def get_query_as_dict(url):
    query = urlparse.parse_qs(urlparse.urlparse(url).query)
    for k in query:
        if len(query[k]) != 1:
            raise RuntimeError("multiple values for " + k)
        query[k] = query[k][0]
    return query

def test_success():
    b = Browser()
    state = 'abcd'

    # A: hit the authorization endpoint (4.1.1)
    url = BASE_URL + 'oauth/authorize'
    url += '?response_type=code'
    url += '&client_id=' + urllib.quote_plus(CLIENT_ID)
    url += '&redirect_uri=' + \
        urllib.quote_plus(REDIRECT_URI)
    url += '&scope=email'
    url += '&state=' + urllib.quote_plus(state)
    b.get(url)

    # B: auth server authenticates user (4.1.2)
    # in this case, the user is not logged in yet and we are
    # redirected to the login page
    assert b.page.url == BASE_URL
    b.login('dustin')

    # (that doesn't redirect back properly, so re-try the auth)
    assert b.page.url == BASE_URL
    b.get(url)
    assert 'Allow access?' in b.page.text

    # C: user is redirected back with an auth code and state
    post_base = urlparse.urlunparse(urlparse.urlparse(b.page.url)[:3] + ('', '', ''))
    post_args = get_query_as_dict(b.page.url)
    post_args['confirm'] = 'yes'
    r = b.post(post_base, post_args, allow_redirects=False)
    redir = r.headers['Location']
    assert redir.startswith(REDIRECT_URI)
    query = get_query_as_dict(redir)
    assert query['state'] == state
    authorization_code = query['code']

    # D: access token request (4.1.3)
    # XXX this should require client auth!!!
    resp = requests.post(BASE_URL + 'oauth/token', {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID
    })
    result = resp.json()
    assert result['token_type'].lower() == 'bearer'
    access_token = result['access_token']
    refresh_token = result['refresh_token']

    # access the resource
    resp = requests.get(BASE_URL + 'api/me',
            headers={'Authorization': 'Bearer %s' % access_token})
    print resp.json()

    # refresh the token
    # XXX this should require client auth too!
    resp = requests.post(BASE_URL + 'oauth/token', {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'scope': 'email',
        'client_id': CLIENT_ID, # XXX not required by spec
    })
    result = resp.json()
    print result
    assert result['token_type'].lower() == 'bearer'
    access_token = result['access_token']
    refresh_token = result['refresh_token']

    # access the resource again
    resp = requests.get(BASE_URL + 'api/me',
            headers={'Authorization': 'Bearer %s' % access_token})
    print resp.json()


if __name__ == "__main__":
    test_success()
