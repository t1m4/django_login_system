import asyncio

from asgiref.sync import sync_to_async
from django.contrib.auth import REDIRECT_FIELD_NAME, login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordResetView, LoginView, SuccessURLAllowedHostsMixin
from django.core.mail import send_mail
from django.http import HttpResponse
from django.shortcuts import render, redirect

# Create your views here.
from django.urls import reverse
from django.utils.decorators import classonlymethod
from django.utils.http import is_safe_url
from django.views import View

from login.forms import LoginForm, PasswordResetForm
from login.tasks import send_reset_mail
from login.tools import get_object_or_none
from login_system.settings import EMAIL_HOST_USER


class AsyncView(View):
    @classonlymethod
    def as_view(cls, **initkwargs):
        view = super().as_view(**initkwargs)
        view._is_coroutine = asyncio.coroutines._is_coroutine
        return view

class IndexView(AsyncView):
    async def get(self, request, *args, **kwargs):
        return HttpResponse('ok', status=200)

class MyLoginView(AsyncView):
    form_class = LoginForm
    redirect_field_name = REDIRECT_FIELD_NAME
    success_url = 'login-index'
    template_name = 'registration/login.html'
    two_factor_authentication = False
    recaptcha_enabled = False
    extra_context = None
    context = {}
    async def get(self, request, *args, **kwargs):
        form = self.form_class()
        self.context['form'] = form
        return render(request, self.template_name, self.context)

    async def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if form.is_valid():
            return await self.form_valid(request, form)
        else:
            return await self.form_invalid(request, form)


    async def form_valid(self, request, form, *args, **kwargs):
        """
        When form is valid
        :param form:
        :param args:
        :param kwargs:
        :return:
        """
        user = await get_object_or_none(User, username=form.cleaned_data.get('username'))
        if user:
            if check_password(form.cleaned_data.get('password'), user.password):
                await sync_to_async(login)(request, user)
                return redirect(reverse(self.success_url))
            else:
                form.add_error(None, form.error_messages.get('invalid_login'))
        else:
            form.add_error(None, form.error_messages.get('invalid_login'))
        self.context['form'] = form
        return render(request, self.template_name, self.context)

    async def form_invalid(self, request, form, *args, **kwargs):
        return render(request, self.template_name, self.context)


class MyLogoutView(AsyncView):
    redirect_field_name = REDIRECT_FIELD_NAME
    # template_name = 'registration/logged_out.html'
    template_name = 'registration/logout.html'
    context = {}

    async def get(self, request, *args, **kwargs):
        await sync_to_async(logout)(request)
        return render(request, self.template_name, self.context)

    async def post(self, request, *args, **kwargs):
        return await self.get(request, *args, **kwargs)

class MyPasswordResetView(AsyncView):
    form_class = PasswordResetForm
    redirect_field_name = REDIRECT_FIELD_NAME
    success_url = 'login-async_reset_done'
    template_name = 'registration/password_reset.html'
    context = {}
    token_generator = default_token_generator

    async def get(self, request, *args, **kwargs):
        form = self.form_class()
        self.context['form'] = form
        return render(request, self.template_name, self.context)

    async def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if form.is_valid():
            return await self.form_valid(request, form)
        else:
            return await self.form_invalid(request, form)

    async def form_valid(self, request, form, *args, **kwargs):
        """
        When form is valid generate a new token and send it to link
        :param form:
        :param args:
        :param kwargs:
        :return:
        """
        email = form.cleaned_data.get('email')
        user = await get_object_or_none(User, email=email)
        if user:
            # Generate token and send it to user
            token = self.token_generator.make_token(user)
            await send_reset_mail(user, token, email)
        else:
            form.add_error(None, form.error_messages.get('invalid_email'))
        self.context['form'] = form
        return redirect(reverse(self.success_url))

    async def form_invalid(self, request, form, *args, **kwargs):
        return render(request, self.template_name, self.context)


class MyPasswordResetDoneView(AsyncView):
    template_name = 'registration/password_reset_done.html'
    context = {}
    async def get(self, request, *args, **kwargs):
        return render(request, self.template_name, self.context)


class MyPasswordResetConfirmView(AsyncView):
    async def get(self, request, uidhex, token,*args, **kwargs):
        return HttpResponse('ok', status=200)

class MyPasswordResetCompleteView(AsyncView):
    pass

