from asgiref.sync import sync_to_async
from django import forms
from django.contrib.auth import password_validation
from django.contrib.auth.forms import UsernameField
from django.contrib.auth.hashers import make_password
from django.utils.translation import gettext_lazy as _


class RegisterForm(forms.Form):
    username = forms.CharField(max_length=255)
    email = forms.EmailField()
    first_name = forms.CharField(max_length=30)
    password = forms.CharField(
        label=_("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'}),
    )
    double_password = forms.CharField(
        label=_("Double Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'}),
    )
    error_messages = {
        'user_exists': _("User with that username or email already exists."),
        'passwords_equals': _("Your passwords are not equal."),
        'invalid_recaptcha': _("This recaptcha is not valid."),
    }


class LoginForm(forms.Form):
    username = UsernameField(widget=forms.TextInput(attrs={'autofocus': True}))
    password = forms.CharField(
        label=_("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'}),
    )
    error_messages = {
        'invalid_login': _(
            "Please enter a correct %(username)s and password. Note that both "
            "fields may be case-sensitive."
        ),
        'inactive': _("This account is inactive."),
        'invalid_recaptcha': _("This recaptcha is not valid."),
    }


class TwoFactorForm(forms.Form):
    code = forms.IntegerField()
    error_messages = {
        'invalid_code': _(
            "Please enter a correct code."
        ),
    }


class PasswordResetForm(forms.Form):
    email = forms.EmailField(
        label=_("Email"),
        max_length=254,
        widget=forms.EmailInput(attrs={'autocomplete': 'email'})
    )
    error_messages = {
        'invalid_email': _(
            "Please enter a correct email"
        ),
    }


class PasswordForm(forms.Form):
    new_password1 = forms.CharField(
        label=_("New password"),
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        strip=False,
        help_text=password_validation.password_validators_help_text_html(),
    )
    new_password2 = forms.CharField(
        label=_("New password confirmation"),
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
    )
    error_messages = {
        'password_mismatch': _('The two password fields didn’t match.'),
    }

    @sync_to_async
    def save(self, user):
        new = make_password(self.cleaned_data['new_password1'])
        user.password = new
        user.save()
