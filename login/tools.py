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
    """
    This better way to use httpx with django. It help user non-block requests.
    :param request:
    :param args:
    :param kwargs:
    :return:
    """
    request.recaptcha_is_valid = None
    if request.method == 'POST':
        recaptcha_response = request.POST.get('g-recaptcha-response')
        data = {
            'secret': settings.GOOGLE_RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        async with httpx.AsyncClient() as client:
            r = httpx.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        result = r.json()
        if result['success']:
            request.recaptcha_is_valid = True
        else:
            request.recaptcha_is_valid = False
            messages.error(request, 'Invalid reCAPTCHA. Please try again.')
    return request
