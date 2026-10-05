from django.shortcuts import render
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta

# Import ScanRecord from scanner app (adjust if your model name differs)
try:
    from scanner.models import ScanRecord
except ImportError:
    ScanRecord = None


def home(request):
    """Home page with search bar and quick actions."""
    context = {
        'total_scans': 0,
        'threats_detected': 0,
        'safe_scans': 0,
        'recent_threats': [],
    }

    if ScanRecord:
        try:
            context['total_scans'] = ScanRecord.objects.count()
            context['threats_detected'] = ScanRecord.objects.filter(
                verdict__in=['suspicious', 'dangerous']
            ).count()
            context['safe_scans'] = ScanRecord.objects.filter(verdict='safe').count()
            context['recent_threats'] = ScanRecord.objects.filter(
                verdict__in=['suspicious', 'dangerous']
            )[:5]
        except Exception:
            pass

    return render(request, 'core/home.html', context)


def about(request):
    """About page describing the CyberShield AI project."""
    return render(request, 'core/about.html')


def help_page(request):
    """Help / FAQ page."""
    faqs = [
        {
            'question': 'What is CyberShield AI?',
            'answer': (
                'CyberShield AI is a smart digital safety system that helps you '
                'detect phishing links, suspicious messages, and weak passwords '
                'before they cause harm.'
            ),
        },
        {
            'question': 'How do I scan a URL?',
            'answer': (
                'Go to the Scanner page, paste the URL in the input box, and click '
                '"Scan". You will get a verdict (Safe / Suspicious / Dangerous) '
                'along with detailed reasons.'
            ),
        },
        {
            'question': 'How do I check a suspicious message?',
            'answer': (
                'Open the Scan Message page, paste the full text of the SMS or '
                'email you received, and click "Analyze". Our engine will highlight '
                'red flags such as urgency, fake links, or requests for personal info.'
            ),
        },
        {
            'question': 'How does the password strength checker work?',
            'answer': (
                'Enter any password on the Check Password page. We analyze its '
                'length, character variety, and patterns — and never store your '
                'password anywhere.'
            ),
        },
        {
            'question': 'Is my data stored?',
            'answer': (
                'Only the results of your scans are stored so you can view history. '
                'Passwords are never stored. You can delete any scan from your history.'
            ),
        },
        {
            'question': 'What should I do if a scan says "Dangerous"?',
            'answer': (
                'Do NOT click the link, reply to the message, or enter any personal '
                'information. Report it to your IT/security team if it came from work, '
                'or forward phishing emails to your email provider.'
            ),
        },
        {
            'question': 'Can I use CyberShield AI on mobile?',
            'answer': (
                'Yes — the web app is fully responsive and works on phones and tablets. '
                'A native mobile app and browser extension are on our roadmap.'
            ),
        },
    ]
    return render(request, 'core/help.html', {'faqs': faqs})


def search(request):
    """Universal search — redirects to URL or message scanner."""
    from django.http import HttpResponseRedirect
    from django.urls import reverse

    query = request.GET.get('q', '').strip()

    if not query:
        return HttpResponseRedirect(reverse('core:home'))

    # Simple heuristic: if it looks like a URL, send to URL scanner.
    looks_like_url = (
        query.startswith(('http://', 'https://', 'www.'))
        or ('.' in query and ' ' not in query and len(query) < 200)
    )

    if looks_like_url:
        return HttpResponseRedirect(f"{reverse('scanner:scan_url')}?q={query}")

    # Otherwise treat as a message
    return HttpResponseRedirect(f"{reverse('scanner:scan_message')}?q={query}")