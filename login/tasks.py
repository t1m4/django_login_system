from django.core.mail import send_mail
from django.urls import reverse
from django.utils.html import format_html

from login_system.settings import EMAIL_HOST_USER


async def send_reset_mail(user, token, email, *args, **kwargs):
    uidhex = hex(user.id)[2:]
    html_message = format_html("""You're receiving this email because you requested a password reset for your user account at 127.0.0.1:8000.
        <br><br>
        Please go to the following page and choose a new password:
        <br><br>
        http://127.0.0.1:8000{url}
        <br><br>
        Your username, in case you’ve forgotten: {username}
        <br><br>
        Thanks for using our site!
        <br><br>
        The 127.0.0.1:8000 team""", username=user.username,
                               url=reverse('login-async_reset_confirm', kwargs={'uidhex': uidhex, 'token': token}))
    send_mail(
        'Password Reset',
        'Here is the message.',
        EMAIL_HOST_USER,
        [email],
        html_message=html_message,
        fail_silently=False,
    )
async def send_confirm_mail(user, token, email, *args, **kwargs):
    uidhex = hex(user.id)[2:]
    print(user.id, uidhex, token)
    html_message = format_html("""You're receiving this email because you register account at 127.0.0.1:8000.
        <br><br>
        Please go to the following page and confirm your account:
        <br><br>
        http://127.0.0.1:8000{url}
        <br><br>
        Your username, in case you’ve forgotten: {username}
        <br><br>
        Thanks for using our site!
        <br><br>
        The 127.0.0.1:8000 team""", username=user.username,
                               url=reverse('login-async_account_confirm', kwargs={'uidhex': uidhex, 'token': token}))
    send_mail(
        'Account Confirm',
        'Here is the message.',
        EMAIL_HOST_USER,
        [email],
        html_message=html_message,
        fail_silently=False,
    )


async def send_code_mail(user, code, *args, **kwargs):
    html_message = format_html("""You're receiving this email because you're login for your user account at 127.0.0.1:8000.
        <br><br>
        Your username, in case you’ve forgotten: {username}
        <br><br>
        Your code, <b>{code}</b>
        <br><br>
        Thanks for using our site!
        <br><br>
        The 127.0.0.1:8000 team""", username=user.username, code=code)
    send_mail(
        'Two factor code',
        'Here is the message.',
        EMAIL_HOST_USER,
        [user.email],
        html_message=html_message,
        fail_silently=False,
    )
