import asyncio

from asgiref.sync import sync_to_async
from django.contrib.auth.models import User


async def get_object_or_none(klass, *args, **kwargs):
    try:
        return await sync_to_async(klass.objects.get)(*args, **kwargs)
    except klass.DoesNotExist:
        return None
