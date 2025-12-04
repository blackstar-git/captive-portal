// Custom JavaScript for the captive portal
document.addEventListener('DOMContentLoaded', function() {
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            // Use Bootstrap's Alert component if available, otherwise manual close
            if (typeof bootstrap !== 'undefined' && bootstrap.Alert) {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            } else {
                // Manual fallback
                alert.style.opacity = '0';
                alert.style.transition = 'opacity 0.5s ease';
                setTimeout(() => {
                    alert.remove();
                }, 500);
            }
        }, 5000);
    });

    // Copy to clipboard functionality
    const copyButtons = document.querySelectorAll('[data-copy]');
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const textToCopy = this.getAttribute('data-copy');

            // Modern clipboard API with fallback
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(textToCopy).then(() => {
                    showCopyFeedback(this);
                }).catch(() => {
                    fallbackCopyText(textToCopy, this);
                });
            } else {
                fallbackCopyText(textToCopy, this);
            }
        });
    });

    // Fallback copy method for older browsers
    function fallbackCopyText(text, button) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();

        try {
            const successful = document.execCommand('copy');
            if (successful) {
                showCopyFeedback(button);
            } else {
                showCopyError(button);
            }
        } catch (err) {
            showCopyError(button);
        }

        document.body.removeChild(textArea);
    }

    function showCopyFeedback(button) {
        const originalHTML = button.innerHTML;
        const originalClass = button.className;

        button.innerHTML = '✓ Copied!';
        button.className = originalClass + ' btn-success';
        button.disabled = true;

        setTimeout(() => {
            button.innerHTML = originalHTML;
            button.className = originalClass;
            button.disabled = false;
        }, 2000);
    }

    function showCopyError(button) {
        const originalHTML = button.innerHTML;

        button.innerHTML = '❌ Failed';
        button.classList.add('btn-danger');
        button.disabled = true;

        setTimeout(() => {
            button.innerHTML = originalHTML;
            button.classList.remove('btn-danger');
            button.disabled = false;
        }, 2000);
    }

    // Progress bar animation
    const progressBars = document.querySelectorAll('.progress-bar');
    progressBars.forEach(bar => {
        const width = bar.style.width;
        bar.style.width = '0';
        setTimeout(() => {
            bar.style.transition = 'width 1s ease-in-out';
            bar.style.width = width;
        }, 100);
    });

    // Card hover effects enhancement
    const cards = document.querySelectorAll('.card');
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-5px)';
        });

        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });

    // Form validation enhancement
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const requiredFields = this.querySelectorAll('[required]');
            let isValid = true;

            requiredFields.forEach(field => {
                if (!field.value.trim()) {
                    isValid = false;
                    field.classList.add('is-invalid');
                } else {
                    field.classList.remove('is-invalid');
                }
            });

            if (!isValid) {
                e.preventDefault();
                // Show error message
                const errorDiv = document.createElement('div');
                errorDiv.className = 'alert alert-danger mt-3';
                errorDiv.textContent = 'Please fill in all required fields.';
                this.appendChild(errorDiv);

                setTimeout(() => {
                    errorDiv.remove();
                }, 5000);
            }
        });
    });

    // Password strength indicator (if you have password fields)
    const passwordFields = document.querySelectorAll('input[type="password"]');
    passwordFields.forEach(field => {
        field.addEventListener('input', function() {
            const strengthIndicator = this.parentNode.querySelector('.password-strength');
            if (!strengthIndicator) return;

            const password = this.value;
            let strength = 0;

            if (password.length >= 8) strength++;
            if (/[A-Z]/.test(password)) strength++;
            if (/[0-9]/.test(password)) strength++;
            if (/[^A-Za-z0-9]/.test(password)) strength++;

            strengthIndicator.className = 'password-strength strength-' + strength;
            strengthIndicator.textContent = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'][strength];
        });
    });

    // QR code download enhancement
    const qrDownloadButtons = document.querySelectorAll('.download-qr');
    qrDownloadButtons.forEach(button => {
        button.addEventListener('click', function() {
            const qrImage = this.closest('.qr-container').querySelector('img');
            if (qrImage) {
                const link = document.createElement('a');
                link.download = 'wifi-config-qr.png';
                link.href = qrImage.src;
                link.click();
            }
        });
    });
});

// Utility function for debouncing
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Utility function for loading states
function setLoadingState(button, isLoading) {
    if (isLoading) {
        button.disabled = true;
        const originalText = button.innerHTML;
        button.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Loading...';
        button.setAttribute('data-original-text', originalText);
    } else {
        button.disabled = false;
        const originalText = button.getAttribute('data-original-text');
        if (originalText) {
            button.innerHTML = originalText;
        }
    }
}