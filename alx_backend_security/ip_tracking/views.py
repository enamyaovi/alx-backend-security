from django.shortcuts import redirect
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django_ratelimit.decorators import ratelimit


@ratelimit(key="user_or_ip", rate="10/m", method="POST", block=False)
@ratelimit(key="ip", rate="5/m", method="POST", block=False)
def loginview(request):
    # If request is over the limit
    if getattr(request, "limited", False):
        return JsonResponse(
            {"error": "Too many login attempts. Please try again later."},
            status=429,  # HTTP 429 Too Many Requests
        )

    if request.method == 'POST':
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('secure')
        else:
            messages.error(request, 'Login failed. Please try again.')

    return HttpResponse("<h1>Login Page - Submit credentials via POST</h1>")


def secure(request):
    return HttpResponse("<h1>Secure page - You are logged in</h1>")
