import asyncio

from django.shortcuts import render

# Create your views here.
from django.utils.decorators import classonlymethod
from django.views import View


class AsyncView(View):
    @classonlymethod
    def as_view(cls, **initkwargs):
        view = super().as_view(**initkwargs)
        view._is_coroutine = asyncio.coroutines._is_coroutine
        return view
