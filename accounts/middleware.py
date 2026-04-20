import logging
logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """
    Keeps security headers but removes browser-only CSP rules
    that would break JSON API clients.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user    = request.user
        display = user.username if user.is_authenticated else "anonymous"
        logger.info(f"[REQUEST]  {request.method} {request.path} — user: {display}")

        response = self.get_response(request)

        response['X-XSS-Protection']       = '1; mode=block'
        response['X-Content-Type-Options']  = 'nosniff'
        response['X-Frame-Options']         = 'DENY'
        # CSP removed — not applicable for a pure JSON API service

        logger.info(f"[RESPONSE] {request.path} — status: {response.status_code}")

        return response