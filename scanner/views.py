import json

from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

from .models import ScanRecord
from .utils import (
    scan_url as do_scan_url,
    scan_message as do_scan_message,
    check_password_strength,
)


# ============================================================
# URL SCANNER
# ============================================================

def scan_url(request):
    """GET: show the URL scan form. POST: run the scan."""
    if request.method == 'GET':
        return render(request, 'scanner/scan_url.html')

    # POST → run scan
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    target = (data.get('target') or '').strip()
    if not target:
        return JsonResponse({'error': 'URL is required'}, status=400)

    result = do_scan_url(target)

    ScanRecord.objects.create(
        scan_type='url',
        input_value=target,
        verdict=result['verdict'],
        risk_score=result['risk_score'],
        reasons=result['reasons'],
        recommendations=result['recommendations'],
    )

    return JsonResponse({'success': True, 'results': result})


# ============================================================
# MESSAGE SCANNER
# ============================================================

def scan_message(request):
    """GET: show the message scan form. POST: analyze the message."""
    if request.method == 'GET':
        return render(request, 'scanner/scan_message.html')

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    message = (data.get('message') or '').strip()
    if not message:
        return JsonResponse({'error': 'Message is required'}, status=400)

    result = do_scan_message(message)

    ScanRecord.objects.create(
        scan_type='message',
        input_value=message[:2000],       # keep DB tidy
        verdict=result['verdict'],
        risk_score=result['risk_score'],
        reasons=result['reasons'],
        recommendations=result['recommendations'],
    )

    return JsonResponse({'success': True, 'results': result})


# ============================================================
# PASSWORD CHECKER
# ============================================================

def check_password(request):
    """GET: show the password form. POST: score the password (never stored)."""
    if request.method == 'GET':
        return render(request, 'scanner/check_password.html')

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    password = data.get('password') or ''
    if not password:
        return JsonResponse({'error': 'Password is required'}, status=400)

    result = check_password_strength(password)

    # IMPORTANT: never store the actual password.
    # We only keep the score + suggestions.
    ScanRecord.objects.create(
        scan_type='password',
        input_value='[hidden]',
        verdict=result['verdict'],
        risk_score=result['risk_score'],
        reasons=result['reasons'],
        recommendations=result['recommendations'],
    )

    # merge score into results for the frontend
    result['score'] = result['risk_score']
    result['suggestions'] = result.get('details', {}).get('suggestions', [])

    return JsonResponse({'success': True, 'results': result})


# ============================================================
# RESULT & HISTORY
# ============================================================

def result(request, pk):
    """Show a saved scan result."""
    scan = get_object_or_404(ScanRecord, pk=pk)
    return render(request, 'scanner/result.html', {'scan': scan})


def history(request):
    """Show all past scans."""
    scans = ScanRecord.objects.all()[:100]
    return render(request, 'scanner/history.html', {'scans': scans})