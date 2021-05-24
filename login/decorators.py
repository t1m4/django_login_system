import time

import requests
from django.conf import settings
from django.contrib import messages


def check_recaptcha(function):
    """
    This is non-async function because you need to wait some respones. Better use async function,
    because this request block the main thread
    :param function:
    :return:
    """
    def wrap(request, *args, **kwargs):
        request.recaptcha_is_valid = None
        if request.method == 'POST':
            recaptcha_response = request.POST.get('g-recaptcha-response')
            data = {
                'secret': settings.GOOGLE_RECAPTCHA_SECRET_KEY,
                'response': recaptcha_response
            }
            print(request.POST.get('username'), "seleeping")
            time.sleep(5)
            r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
            result = r.json()
            if result['success']:
                request.recaptcha_is_valid = True
            else:
                request.recaptcha_is_valid = False
                messages.error(request, 'Invalid reCAPTCHA. Please try again.')
        return function(request, *args, **kwargs)

    wrap.__doc__ = function.__doc__
    # wrap.__name__ = function.__name__
    return wrap
