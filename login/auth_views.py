import asyncio
import random

from asgiref.sync import sync_to_async
from django.contrib.auth import REDIRECT_FIELD_NAME, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import redirect_to_login
from django.core.cache import cache
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import render, redirect
# Create your views here.
from django.urls import reverse
from django.utils.decorators import classonlymethod, method_decorator
from django.views import View

from login.forms import LoginForm, PasswordResetForm, PasswordForm, TwoFactorForm, RegisterForm
from login.tasks import send_reset_mail, send_code_mail, send_confirm_mail
from login.tools import get_object_or_none, async_check_recaptcha


class AsyncView(View):
    @classonlymethod
    def as_view(cls, **initkwargs):
        view = super().as_view(**initkwargs)
        view._is_coroutine = asyncio.coroutines._is_coroutine
        return view

class MyLoginRequiredMixin(AsyncView):
    """
    Check that user is logged in account. If not logged in then redirect to login page else pass to destination
    """
    redirect_field_name = REDIRECT_FIELD_NAME
    login_url = 'login-async_login'

    async def dispatch(self, request, *args, **kwargs):
        if not await self.get_user_is_authenticated(request):
            # redirect to login page with params next
            return redirect_to_login(self.request.get_full_path(), self.login_url, self.redirect_field_name)
        return await super().dispatch(request, *args, **kwargs)
    @sync_to_async()
    def get_user_is_authenticated(self, request):
        """
        Return user authenticated
        """
        return request.user.is_authenticated

class IndexView(MyLoginRequiredMixin):
    """
    View for main info
    """
    login_page = 'login-async_login'

    async def get(self, request, *args, **kwargs):
        if await self.get_user_is_authenticated(request):
            message = 'Ok. You have access on <a href={}>admin panel</a>'.format("/admin")
            return HttpResponse(message, status=200)
        else:
            message = "You don't have access. You have to login using this link <a href={}>login</a>".format(
                reverse(self.login_page))
            return HttpResponse(message, status=200)

    @sync_to_async
    def get_user_is_authenticated(self, request):
        return request.user.is_authenticated


class MyRegisterView(AsyncView):
    """
    Use email for login
    """
    form_class = RegisterForm
    redirect_field_name = REDIRECT_FIELD_NAME
    success_url = 'login-index'
    template_name = 'registration/register.html'

    # You can enable two factor email authentication
    two_factor_confirm = True
    token_generator = default_token_generator
    two_factor_success_url = 'login-index'
    cache_timeout = 60 * 60
    code_length = 6

    # You can enable recaptcha
    recaptcha_enabled = False
    extra_context = None
    context = {}

    async def get(self, request, *args, **kwargs):
        form = self.form_class()
        self.context['form'] = form
        if self.recaptcha_enabled:
            self.context['recaptcha_enabled'] = True

        return render(request, self.template_name, self.context)

    async def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if self.recaptcha_enabled:
            await async_check_recaptcha(request)
            # check valid recaptcha
            if not request.recaptcha_is_valid:
                return render(request, self.template_name, self.context)

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
        username = form.cleaned_data.get('username')
        email = form.cleaned_data.get('email')
        password = form.cleaned_data.get('password')
        double_password = form.cleaned_data.get('double_password')
        user = await get_object_or_none(User, Q(username=username) | Q(email=email))
        self.context['form'] = form
        if user:
            form.add_error(None, form.error_messages.get('user_exists'))
        else:
            if password != double_password:
                form.add_error(None, form.error_messages.get('passwords_equals'))
            else:
                # delete double_password in form
                del form.cleaned_data['double_password']
                # hash password using django
                form.cleaned_data['password'] = make_password(password)
                form.cleaned_data['is_active'] = False
                user = await sync_to_async(User.objects.create)(**form.cleaned_data)
                # Generate token and send it to user
                token = self.token_generator.make_token(user)
                # set token in cache for TIMEOUT minutes
                cache.set(user.id, token, self.cache_timeout)
                await send_confirm_mail(user, token, email)
                return redirect(reverse(self.success_url))
        return render(request, self.template_name, self.context)

    async def form_invalid(self, request, form, *args, **kwargs):
        return render(request, self.template_name, self.context)


class MyAccountConfirmView(AsyncView):
    template_name = 'registration/account_confirm.html'
    context = {}
    success_url = "login-index"

    async def get(self, request, uidhex, token, *args, **kwargs):
        check_valid = await self.check_valid_token(uidhex, token)
        if check_valid:
            id = int("0x" + uidhex, 0)
            user = await get_object_or_none(User, id=id)
            await sync_to_async(login)(request, user)
            await self.update_user(user)
            return redirect(reverse(self.success_url))
        else:
            return HttpResponse('Not Found', status=404)

    async def check_valid_token(self, uidhex, token, *args, **kwargs):
        try:
            id = int("0x" + uidhex, 0)
        except:
            return False
        cache_token = cache.get(id)
        if cache_token == token:
            return True
        else:
            return False

    @sync_to_async
    def update_user(self, user, *args, **kwargs):
        user.is_active = True
        user.save()


class MyLoginView(AsyncView):
    """
    Use email for login
    """
    form_class = LoginForm
    redirect_field_name = REDIRECT_FIELD_NAME
    success_url = 'login-index'
    template_name = 'registration/login.html'

    # You can enable two factor email authentication
    two_factor_authentication = False
    two_factor_success_url = 'login-async_two_factor'
    cache_timeout = 60 * 60
    code_length = 6

    # You can enable recaptcha
    recaptcha_enabled = False
    extra_context = None
    context = {}

    async def get(self, request, *args, **kwargs):
        form = self.form_class()
        self.context['form'] = form
        if self.recaptcha_enabled:
            self.context['recaptcha_enabled'] = True

        return render(request, self.template_name, self.context)

    async def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if self.recaptcha_enabled:
            await async_check_recaptcha(request)
            # check valid recaptcha
            if not request.recaptcha_is_valid:
                return render(request, self.template_name, self.context)

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
        user = await get_object_or_none(User, Q(username=form.cleaned_data.get('username')) & Q(is_active=True))
        if user:
            if check_password(form.cleaned_data.get('password'), user.password):
                if self.two_factor_authentication:
                    await self.send_code(user)
                    await self.set_session_key(request, "_auth_user_id", user.id)
                    # Save in cache how many times user try to send code
                    cache.set("_auth_user_{id}_count".format(id=user.id), 0)
                    return redirect(reverse(self.two_factor_success_url))
                else:
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

    async def send_code(self, user, *args, **kwargs):
        start = int("1" + (self.code_length - 1) * "0")
        end = int(self.code_length * "9")
        code = random.randint(start, end)
        cache.set(user.id, code, self.cache_timeout)
        await send_code_mail(user, code)

    @sync_to_async()
    def set_session_key(self, request, key, value):
        """
        set any session key in async way
        :param request:
        :param key:
        :param value:
        :return:
        """
        request.session[key] = value


class TwoFactorAuthentication(AsyncView):
    form_class = TwoFactorForm
    success_url = 'login-index'
    template_name = 'registration/two_factor.html'
    context = {}

    async def get(self, request, *args, **kwargs):
        # Check that user have access to this point
        if await self.check_session(request):
            form = self.form_class()
            self.context['form'] = form
            return render(request, self.template_name, self.context)
        else:
            return HttpResponse('Not Found', status=404)

    async def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        # Check that user have access to this point
        if await self.check_session(request):
            if form.is_valid():
                return await self.form_valid(request, form)
            else:
                return await self.form_invalid(request, form)
        else:
            return HttpResponse('Not Found', status=404)

    async def form_valid(self, request, form, *args, **kwargs):
        """
        When form is valid
        :param form:
        :param args:
        :param kwargs:
        :return:
        """
        id = await self.check_session(request)
        id_count = cache.incr('_auth_user_{id}_count'.format(id=id))
        user = await get_object_or_none(User, id=id)
        cache_code = cache.get(id)
        if id_count > 3:
            cache.delete(id)
            return HttpResponse('Not Found', status=404)
        if user and cache_code:
            if form.cleaned_data.get('code') == cache_code:
                await sync_to_async(login)(request, user)
                return redirect(reverse(self.success_url))
            else:
                form.add_error(None, form.error_messages.get('invalid_code'))
        else:
            form.add_error(None, form.error_messages.get('invalid_code'))
        self.context['form'] = form
        return render(request, self.template_name, self.context)

    async def form_invalid(self, request, form, *args, **kwargs):
        return render(request, self.template_name, self.context)

    async def check_session(self, request):
        try:
            id = await sync_to_async(request.session.get)('_auth_user_id')
            return id
        except:
            return None


class MyLogoutView(AsyncView):
    redirect_field_name = REDIRECT_FIELD_NAME
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
    cache_timeout = 60 * 30
    recaptcha_enabled = False

    async def get(self, request, *args, **kwargs):
        form = self.form_class()
        self.context['form'] = form
        if self.recaptcha_enabled:
            self.context['recaptcha_enabled'] = True
        return render(request, self.template_name, self.context)

    async def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if self.recaptcha_enabled:
            await async_check_recaptcha(request)
            # check valid recaptcha
            if not request.recaptcha_is_valid:
                return render(request, self.template_name, self.context)

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
            # set token in cache for TIMEOUT minutes
            cache.set(user.id, token, self.cache_timeout)
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
            id = int("0x" + uidhex, 0)
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
            id = int("0x" + uidhex, 0)
            user = await get_object_or_none(User, id=id)
            await form.save(user)
            cache.delete(id)
            return redirect(reverse(self.success_url))
        self.context['form'] = form
        return render(request, self.template_name, self.context)

    async def form_invalid(self, request, form, *args, **kwargs):
        # return render(request, self.template_name, self.context)
        return HttpResponse('Not Found', status=404)


class MyPasswordResetCompleteView(AsyncView):
    template_name = 'registration/password_reset_complete.html'
    context = {}

    async def get(self, request, *args, **kwargs):
        return render(request, self.template_name, self.context)
