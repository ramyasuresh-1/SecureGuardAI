document.addEventListener('DOMContentLoaded', () => {
  const passwordField = document.getElementById('password');
  const confirmPasswordField = document.getElementById('confirm_password');
  const strengthBar = document.getElementById('password-strength-bar');
  const strengthText = document.getElementById('password-strength-text');
  const avatarOptions = document.querySelectorAll('.avatar-option');

  const setPasswordStrength = (value) => {
    if (!strengthBar || !strengthText) {
      return;
    }

    let score = 0;
    if (value.length >= 8) score += 1;
    if (/[A-Z]/.test(value)) score += 1;
    if (/[0-9]/.test(value)) score += 1;
    if (/[^A-Za-z0-9]/.test(value)) score += 1;

    const widths = ['0%', '25%', '50%', '75%', '100%'];
    const labels = ['weak', 'fair', 'good', 'strong', 'excellent'];
    const width = widths[Math.min(score, 4)];
    const label = labels[Math.min(score, 4)];

    strengthBar.style.width = width;
    strengthText.textContent = `Password strength: ${label}`;
  };

  if (passwordField) {
    passwordField.addEventListener('input', (event) => {
      setPasswordStrength(event.target.value);
    });
  }

  document.querySelectorAll('.password-toggle').forEach((button) => {
    button.addEventListener('click', () => {
      const targetId = button.getAttribute('data-target');
      const input = document.getElementById(targetId);
      if (!input) {
        return;
      }

      const icon = button.querySelector('i');
      if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      }
    });
  });

  avatarOptions.forEach((option) => {
    option.addEventListener('click', () => {
      avatarOptions.forEach((item) => item.classList.remove('selected'));
      option.classList.add('selected');
      const input = option.querySelector('input');
      if (input) {
        input.checked = true;
      }
    });
  });

  const forms = document.querySelectorAll('form.needs-validation');
  forms.forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!form.checkValidity()) {
        event.preventDefault();
        event.stopPropagation();
      }
      form.classList.add('was-validated');
    });
  });

  if (confirmPasswordField && passwordField) {
    confirmPasswordField.addEventListener('input', () => {
      if (confirmPasswordField.value && confirmPasswordField.value !== passwordField.value) {
        confirmPasswordField.setCustomValidity('Passwords do not match');
      } else {
        confirmPasswordField.setCustomValidity('');
      }
    });
  }
});
