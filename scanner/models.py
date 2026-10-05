from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class ScanRecord(models.Model):
    SCAN_TYPES = [
        ('url', 'URL'),
        ('message', 'Message'),
        ('password', 'Password'),
    ]
    VERDICTS = [
        ('safe', 'Safe'),
        ('suspicious', 'Suspicious'),
        ('dangerous', 'Dangerous'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES)
    input_value = models.TextField()
    verdict = models.CharField(max_length=20, choices=VERDICTS, default='safe')
    risk_score = models.IntegerField(default=0)
    reasons = models.JSONField(default=list, blank=True)
    recommendations = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Scan Record'
        verbose_name_plural = 'Scan Records'

    def __str__(self):
        return f"{self.scan_type} → {self.verdict} ({self.risk_score})"