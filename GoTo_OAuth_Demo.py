import requests
import requests.utils
import base64

# functions
def get_auth_code():
    query_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri
    }
    full_auth_url = append_query_params(auth_url, query_params)
    print(f"Please go to this URL and authorize access: {full_auth_url}")
    auth_code = input("Enter the auth code provided in the URL of redirect page: ")
    return auth_code.strip()

def append_query_params(url, query_params):
    # query_params should be a dictionary
    # If url don't end in ? mark, then append ? mark.
    if (url[-1] != '?'):
        url = url + '?'

    for key, value in query_params.items():
        url = url + encode_uri(key) + '=' + encode_uri(value) + '&'

    # If url ends in & sign, remove ending & sign.
    if (url[-1] == '&'):
        url = url[:-1]

    return url 

def encode_uri(string):
    return requests.utils.quote(string, safe='')

def get_access_token(auth_code):
    url = token_url    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {auth_string}"
    }
    body = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": redirect_uri 
    }
    response = requests.post(url=url, headers=headers, data=body)
    # Returns dictionary with access_token, token_type, expires_in, scope, principal, refresh_token, and loa.
    return response.json()

def encode_base64(string):
    return base64.b64encode(string.encode()).decode() # UTF-8 encoding

def get_my_goto_profile(access_code):
    url = "https://api.getgo.com/admin/rest/v1/me"
    headers = {
        "Authorization": f"Bearer {access_code}"
    }
    response = requests.get(url=url, headers=headers)
    return response.json()

def refresh_access_token(refresh_token):
    url = token_url
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {auth_string}"
    }
    body = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }
    response = requests.post(url=url, headers=headers, data=body)
    # Returns dictionary with access_token, token_type, expires_in, scope, principal, and loa.
    # Will return a refresh_token if it's been 18 days since the last one was provided.
    return response.json()

# fields
client_id = "enter client id"
client_secret = "it's a secret!"
redirect_uri = "https://localhost"
auth_url = "https://authentication.logmeininc.com/oauth/authorize"
token_url = "https://authentication.logmeininc.com/oauth/token"
auth_string = encode_base64(f"{client_id}:{client_secret}")

# main
auth_code = get_auth_code()
access_token_response = get_access_token(auth_code)
my_goto_profile = get_my_goto_profile(access_token_response['access_token'])
print("\nMy GoTo profile:")
print(my_goto_profile)
refresh_token_response = refresh_access_token(access_token_response['refresh_token'])
print("\nRefresh token response:")
print(refresh_token_response)

# If refresh_token_response returns a new refresh taken, start using that new one going forward.
# Options to continually refresh the token:
#   - Define try-catch > catch TokenExpiredError > refresh token > try again.
#   - Auto-refresh the token every 50ish minutes.
# In either case don't forget to start using the new refresh_token after 18 days when its provided and before 30 days when it expires.
# When a new refresh token is provided, the old one is invalidated.



################
# Authorization Code Grant Flow Outline (a.k.a Web Application Flow)
# 
# 1. Set up an OAuth Client and with the following properties:
#     - Client ID
#     - Client Secret
#     - Redirect URI (typically https://localhost)
# 2. Get first access token.
#     1. Get authorization code.
#         1. User is directed to authorization URL in browser.
#         2. User logs in (if they aren’t already).
#         3. User approves permissions requested by the app/oauth client (if they haven’t already).
#         4. User or client are redirected to specified redirect URL. Auth code will be provided in the URL.
#     2. Make request to access token endpoint. 
#         - Provide the auth code obtained previously.
#         - You’ll be provided with access token and refresh token.
# 3. Refresh access token.
#     1. Before/after your access token expires, make a request to the refresh token endpoint.
#         - This is usually the same as access token endpoint, but not always.
#         - Provide refresh token obtained previously.
#         - GoTo access tokens expire in 60 minutes.
#     2. Eventually refresh token expires, but you’ll be provided a new one at some point when you refresh your access tokens.
#         - GoTo refresh tokens expire in 30 days, but you are provided a new one after 18 days (invalidating the old one).
#         - If you let the refresh token expire, the user will need to again perform the auth code grant flow.

################
# A note on the Implicit Grant flow:
# GoTo also accepts the Implicit Grant flow, but this flow is considered to be inferior, and doesn't support refresh tokens, so it requires continual user interaction. 
# Implicit grant may still be needed where the client/application lives on the user agent/browser with no server side component, so there is no safe place to store client secrets or access/refresh tokens. 
# The auth code would have no benefit, as the authorization is “implicit”, as there is no separate client/agent to authorize.

################
# A note on the Password Grant flow:
# GoTo (and the whole industry) has deprecated this for security reasons. 
# They no longer make this available to new OAuth clients. 
# Existing clients using password grant can still use it for now. 
# They are officially decommissioning this flow for all OAuth clients on Aug 28, 2024, and have given one years notice.
#   - https://developer.goto.com/guides/References/05_Direct-Login_migration/
#   - https://developer.goto.com/guides/Authentication/New_Token_Retrieval_Migration_Guide/


################
# Docs
################
# GoTo connect API auth guides
#   https://developer.goto.com/Authentication/
#   https://developer.goto.com/Authentication/#tag/Authorize
#   https://developer.goto.com/Authentication/#tag/Tokens
#   https://developer.goto.com/guides/Authentication/03_HOW_accessToken/
#   https://developer.goto.com/guides/Authentication/05_HOW_refreshToken/
# Each access token expires in 60 minutes. Refresh token expires in 30 days, but a new one is given after 18 days.

################
# Auth code request
# GET https://authentication.logmeininc.com/oauth/authorize

# query params
#   response_type=code
#   client_id={CLIENT_ID}
#   redirect_uri={REDIRECT_URI}

################
# Access token request using authorization code (expires in 60 minutes)
# POST https://authentication.logmeininc.com/oauth/token

# headers
#   Content-Type: "application/x-www-form-urlencoded"
#   Authorization: "Basic base64("{CLIENT_ID}:{CLIENT_SECRET}")"

# body
#   grant_type: "authorization_code"
#   code: {AUTH_CODE}
#   redirect_uri: "https://oauth.pstmn.io/v1/callback" or "https://localhost"

################
# Access token request using refresh token (expires in 60 minutes)
# POST https://authentication.logmeininc.com/oauth/token

# headers
#   Content-Type: "application/x-www-form-urlencoded"
#   Authorization: "Basic base64("{CLIENT_ID}:{CLIENT_SECRET}")"

# body
#   grant_type: "refresh_token"
#   refresh_token: {REFRESH_TOKEN}

################
# Potential libraries for OAuth2 Authorization Code Grant Flow (a.k.a Web Application Flow).
# requests-oauthlib: (Most popular and existed since Nov 2012. Actually uses oathlib and requests libraries under the hood and abstracts the usage of both.)
#   https://pypi.org/project/requests-oauthlib/
#   https://github.com/requests/requests-oauthlib
#   https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#web-application-flow

# oauthlib: (Almost as popular as requests-oauthlib and existed since Nov 2011)
#   https://pypi.org/project/oauthlib/
#   https://github.com/oauthlib/oauthlib
#   https://oauthlib.readthedocs.io/en/latest/oauth2/clients/webapplicationclient.html
#   https://oauthlib.readthedocs.io/en/latest/oauth2/clients/baseclient.html
#   https://testdriven.io/blog/oauth-python/

# authlib: (Least popular and more focused on server side than client side. Existed since Oct 2017)
#   https://pypi.org/project/Authlib/
#   https://github.com/lepture/authlib
#   https://docs.authlib.org/en/latest/client/oauth2.html#oauth-2-session

################
# Further reading on OAuth 2.0
# https://auth0.com/intro-to-iam/what-is-oauth-2