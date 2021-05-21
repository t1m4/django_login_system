import asyncio

from asgiref.sync import sync_to_async
from django.contrib.auth import REDIRECT_FIELD_NAME, login, logout
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core.cache import cache
from django.http import HttpResponse
from django.shortcuts import render, redirect
# Create your views here.
from django.urls import reverse
from django.utils.decorators import classonlymethod
from django.views import View

from login.forms import LoginForm, PasswordResetForm, PasswordForm
from login.tasks import send_reset_mail
from login.tools import get_object_or_none


class AsyncView(View):
    @classonlymethod
    def as_view(cls, **initkwargs):
        view = super().as_view(**initkwargs)
        view._is_coroutine = asyncio.coroutines._is_coroutine
        return view


class IndexView(AsyncView):
    """
    View for main info
    """
    async def get(self, request, *args, **kwargs):
        return HttpResponse('ok', status=200)


class MyLoginView(AsyncView):
    """
    Use email for login
    """
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
    """
        Use email for reset. Create token and send it to user.mail
        Also save token in cache.
    """
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
            cache.set(user.id, token)
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
    """
        Check token in cache.
    """
    form_class = PasswordForm
    template_name = 'registration/password_reset_confirm.html'
    context = {}
    success_url = "login-async_reset_complete"
    async def get(self, request, uidhex, token, *args, **kwargs):
        check_valid = await self.check_valid_token(uidhex, token)
        if check_valid:
            form = self.form_class()
            self.context['form'] = form
            return render(request, self.template_name, self.context)
        else:
            return HttpResponse('Not Found', status=404)

    async def post(self, request, uidhex, token, *args, **kwargs):
        check_valid = await self.check_valid_token(uidhex, token)
        form = self.form_class(request.POST)
        if form.is_valid() and check_valid:
            return await self.form_valid(request, form, uidhex)
        else:
            return await self.form_invalid(request, form)

    async def check_valid_token(self, uidhex, token, *args, **kwargs):
        try:
            id = int(uidhex, 0)
        except:
            return False
        cache_token = cache.get(id)
        if cache_token == token:
            return True
        else:
            return False
    async def form_valid(self, request, form, uidhex, *args, **kwargs):
        """
        When form is valid save new password and redirect to success_url
        :param form:
        :param uidhex: user id in hex
        :param args:
        :param kwargs:
        :return:
        """
        if form.cleaned_data.get('new_password1') != form.cleaned_data.get('new_password2'):
            form.add_error(None, form.error_messages.get('password_mismatch'))
        else:
            user = await get_object_or_none(User, id=int(uidhex, 0))
            await form.save(user)
            return redirect(reverse(self.success_url))
        self.context['form'] = form
        return render(request, self.template_name, self.context)

    async def form_invalid(self, request, form, *args, **kwargs):
        return render(request, self.template_name, self.context)


class MyPasswordResetCompleteView(AsyncView):
    template_name = 'registration/password_reset_complete.html'
    context = {}
    async def get(self, request, *args, **kwargs):
        return render(request, self.template_name, self.context)

