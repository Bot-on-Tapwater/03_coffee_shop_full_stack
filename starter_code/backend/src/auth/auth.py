import json
from flask import request, _request_ctx_stack, abort, Flask
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'dev-u8srfgkm.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'coffeeshop'

# AUTH0_DOMAIN = 'udacity-fsnd.auth0.com'
# ALGORITHMS = ['RS256']
# API_AUDIENCE = 'dev'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def _init_(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''
def get_token_auth_header():

    if 'Authorization' not in request.headers:
        raise AuthError({
            ''' If the "Authorization" is not in the header raise an AuthError'''
            'code': 'No Authorization',
            'description': 'Authorization not present in headers'
        }, 401)
        #abort(401) # If the key 'Authorization' is not in the header and raise a 401 status code

    auth_header = request.headers['Authorization'] # Grab the values assigned to the key 'Authorization' and assign them to the variable 'auth_header'

    header_parts = auth_header.split(' ') 

    if len(header_parts) != 2:
        raise AuthError({
            ''' If the "Authorization" is malformed raise an AuthError'''
            'code': 'No Authorization',
            'description': 'Authorization header is malformed'
        }, 401)
        #abort(401)

    elif header_parts[0].lower() != 'bearer':
        raise AuthError({
            ''' If 'bearer' token is not our specified authorization method raise an AuthError'''
            'code': 'No Authorization',
            'description': 'Bearer token not authorization method'
        }, 401)

        #abort(401) # We use an if statement to check whether  a bearer token is our selected authorization method, if not we abort and raise a 401 status code

    return header_parts[1]

    raise Exception('Not Implemented')

'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''
def check_permissions(permission, payload):
    if 'permissions' not in payload:
        raise AuthError({
            '''Check whether 'permissions' is present in our decoded JWT, if not raise an AuthError'''
            'code': 'permissions not found',
            'description': 'permissions not present in payload'
        }, 400)

    if permission not in payload['permissions']:
        raise AuthError({
            '''Check whether our specified permission(s) is present in the key 'permssions' in our decoded JWT if not raise an AuthError'''
        })

    return True

    raise Exception('Not Implemented')

    


'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def verify_decode_jwt(token):
    ''' In this method we get our JWT token and verify it'''
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    if 'kid' not in unverified_header:
        '''Check if kid is present in our decoded header, if not raise an AuthError'''
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            return payload

        except jwt.ExpiredSignatureError:
            '''If provided token has expired raise an AuthError'''
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError:
            '''If audience and issuer don't match the details provided in Auth0 raise an AuthError'''
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)

        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)
    raise AuthError({
        'code': 'invalid_header',
        'description': 'Unable to find the appropriate key.'
    }, 400)

    raise Exception('Not Implemented')

'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator

# app = Flask(__name__)

# @app.route('/test')
# @requires_auth('get:drinks')
# def test(token):

#     print('Nothing to worry about in the authenticaction & authorizaton segment')

#     return 'Nothing to worry about in the authenticaction & authorizaton segment'

# @app.route('/drinks', methods=['GET'])
# @requires_auth('get:drinks')
# def retrieve_drinks(token):
    # all_drinks = Drink.query.order_by(Drink.id).all()
    # drinks = [drink.short() for drink in all_drinks]

    # return jsonify({
    #     'success': True,
    #     'drinks': drinks
    # })
    # return 'the endpoint /drinks works as expected'