from django.utils import translation
from django.utils.deprecation import MiddlewareMixin


class UserLanguageMiddleware(MiddlewareMixin):
    """
    Middleware to set the user's preferred language.
    
    For authenticated users, loads language from database.
    For anonymous users, uses session language set by Django's set_language view.
    """
    
    def process_request(self, request):
        if request.user.is_authenticated and hasattr(request.user, 'preferred_language'):
            # Use the user's preferred language from database
            language = request.user.preferred_language
            if language:
                translation.activate(language)
                request.LANGUAGE_CODE = language
