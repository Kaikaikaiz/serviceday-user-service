import logging
logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """
    Topic 7.1a — Adds security headers to every response.
    Logs every request for audit purposes.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user    = request.user
        display = user.username if user.is_authenticated else "anonymous"
        logger.info(f"[REQUEST]  {request.method} {request.path} — user: {display}")

        response = self.get_response(request)

        response['X-XSS-Protection']         = '1; mode=block'
        response['X-Content-Type-Options']    = 'nosniff'
        response['X-Frame-Options']           = 'DENY'
        response['Content-Security-Policy']   = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.tailwindcss.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "img-src 'self' data:;"
        )

        logger.info(f"[RESPONSE] {request.path} — status: {response.status_code}")
        return response