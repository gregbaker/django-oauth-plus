from __future__ import absolute_import

from functools import wraps

import oauth2 as oauth
from django.utils.translation import ugettext as _

from .consts import OAUTH_PARAMETERS_NAMES
from .responses import (COULD_NOT_VERIFY_OAUTH_REQUEST_RESPONSE,
                        INVALID_CONSUMER_RESPONSE, INVALID_PARAMS_RESPONSE,
                        INVALID_SCOPE_RESPONSE)
from .store import InvalidConsumerError, InvalidTokenError, store
from .utils import (get_oauth_request, initialize_server_request,
                    send_oauth_error, verify_oauth_request)

try:
    from functools import update_wrapper
except ImportError:
    from django.utils.functional import update_wrapper  # Python 2.3, 2.4 fallback.




class CheckOauth(object):
    """
    Decorator that checks that the OAuth parameters passes the given test, raising
    an OAuth error otherwise. If the test is passed, the view function
    is invoked.

    We use a class here so that we can define __get__. This way, when a
    CheckOAuth object is used as a method decorator, the view function
    is properly bound to its instance.
    """
    def __init__(self, scope_name=None):
        self.scope_name = scope_name

    def __new__(cls, arg=None):
        if not callable(arg):
            return super(CheckOauth, cls).__new__(cls)
        else:
            obj =  super(CheckOauth, cls).__new__(cls)
            obj.__init__()
            return obj(arg)

    def __call__(self, view_func):

        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            oauth_request = get_oauth_request(request)
            if oauth_request is None:
                return INVALID_PARAMS_RESPONSE

            try:
                consumer = store.get_consumer(request, oauth_request, oauth_request['oauth_consumer_key'])
            except InvalidConsumerError:
                return INVALID_CONSUMER_RESPONSE

            try:
                token = store.get_access_token(request, oauth_request, consumer, oauth_request.get_parameter('oauth_token'))
            except InvalidTokenError:
                return send_oauth_error(oauth.Error(_('Invalid access token: %s') % oauth_request.get_parameter('oauth_token')))

            if not verify_oauth_request(request, oauth_request, consumer, token):
                return COULD_NOT_VERIFY_OAUTH_REQUEST_RESPONSE

            if self.scope_name and (not token.scope
                                    or token.scope.name != self.scope_name):
                return INVALID_SCOPE_RESPONSE

            if token.user:
                request.user = token.user
            return view_func(request, *args, **kwargs)

        return wrapped_view


oauth_required = CheckOauth
