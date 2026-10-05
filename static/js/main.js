/* ============================================
   CyberShield AI — Main JavaScript
   ============================================ */

document.addEventListener('DOMContentLoaded', () => {

    // ---------- FAQ accordion ----------
    document.querySelectorAll('.faq-question').forEach(q => {
        q.addEventListener('click', () => {
            q.parentElement.classList.toggle('open');
        });
    });

    // ---------- Password strength meter ----------
    const pwdInput = document.getElementById('password-input');
    const strengthBar = document.getElementById('strength-bar');
    const strengthLabel = document.getElementById('strength-label');

    if (pwdInput && strengthBar && strengthLabel) {
        pwdInput.addEventListener('input', () => {
            const pwd = pwdInput.value;
            const score = calculatePasswordScore(pwd);

            strengthBar.style.width = score.percent + '%';
            strengthBar.className = 'strength-bar ' + score.level;
            strengthLabel.textContent = score.label;
            strengthLabel.className = 'strength-bar ' + score.level;
            strengthLabel.style.background = 'none';
            strengthLabel.style.color = getLevelColor(score.level);
        });
    }

    function calculatePasswordScore(pwd) {
        if (!pwd) return { percent: 0, level: 'weak', label: '' };

        let score = 0;
        if (pwd.length >= 8) score += 25;
        if (pwd.length >= 12) score += 15;
        if (pwd.length >= 16) score += 10;
        if (/[a-z]/.test(pwd)) score += 10;
        if (/[A-Z]/.test(pwd)) score += 10;
        if (/[0-9]/.test(pwd)) score += 10;
        if (/[^a-zA-Z0-9]/.test(pwd)) score += 20;

        score = Math.min(score, 100);

        let level = 'weak';
        let label = 'Very Weak';
        if (score >= 80) { level = 'strong'; label = 'Strong'; }
        else if (score >= 60) { level = 'good'; label = 'Good'; }
        else if (score >= 40) { level = 'fair'; label = 'Fair'; }
        else if (score >= 20) { level = 'weak'; label = 'Weak'; }

        return { percent: score, level, label };
    }

    function getLevelColor(level) {
        return {
            weak: '#ff0044',
            fair: '#ff6600',
            good: '#ffcc00',
            strong: '#00cc66',
        }[level] || '#ff0044';
    }

    // ---------- Universal search (home page) ----------
    const searchForm = document.getElementById('universal-search');
    if (searchForm) {
        searchForm.addEventListener('submit', (e) => {
            const input = searchForm.querySelector('input[name="q"]');
            const query = input.value.trim();
            if (!query) {
                e.preventDefault();
                return;
            }

            // Heuristic: URL vs message — let the backend decide via /search/
            // /search/ will redirect to appropriate scanner page.
        });
    }

    // ---------- Auto-focus first input on scan pages ----------
    const firstInput = document.querySelector('input[autofocus], textarea[autofocus]');
    if (firstInput) {
        firstInput.focus();
    }

});