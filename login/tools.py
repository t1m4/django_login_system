import asyncio
from threading import Thread

import httpx
from asgiref.sync import sync_to_async
from django.contrib import messages
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.utils.html import format_html

from login_system import settings
from login_system.settings import EMAIL_HOST_USER


async def get_object_or_none(klass, *args, **kwargs):
    try:
        return await sync_to_async(klass.objects.get)(*args, **kwargs)
    except klass.DoesNotExist:
        return None

async def async_check_recaptcha(request, *args, **kwargs):
    request.recaptcha_is_valid = None
    if request.method == 'POST':
        recaptcha_response = request.POST.get('g-recaptcha-response')
        data = {
            'secret': settings.GOOGLE_RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        # TODO don't send request
        async with httpx.AsyncClient() as client:
            # r = await client.post('https://www.google.com/recaptcha/api/siteverify', data=data)
            r = await client.get('https://evileg.com/ru/post/283/', timeout=5)
            print('hello',r)
        result = r.json()
        print(result)
        if result['success']:
            request.recaptcha_is_valid = True
        else:
            request.recaptcha_is_valid = False
            messages.error(request, 'Invalid reCAPTCHA. Please try again.')
    return request

    wrap.__doc__ = function.__doc__
    # wrap.__name__ = function.__name__
    return wrap
