import asyncio
from threading import Thread

from asgiref.sync import sync_to_async
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.utils.html import format_html

from login_system.settings import EMAIL_HOST_USER


async def get_object_or_none(klass, *args, **kwargs):
    try:
        return await sync_to_async(klass.objects.get)(*args, **kwargs)
    except klass.DoesNotExist:
        return None

