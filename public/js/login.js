// Password visibility toggle
document.getElementById('show-password').addEventListener('change', function() {
    const passwordInput = document.getElementById('password');
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
    this.nextElementSibling.textContent = type === 'password' ? 'Show password' : 'Hide password';
});

// Client-side validation and form submission
document.getElementById('loginForm').addEventListener('submit', function(event) {
    event.preventDefault();

    // Clear previous error messages
    const errorBox = document.getElementById('errorBox');
    errorBox.textContent = '';
    errorBox.style.display = 'none';

    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value.trim();
    let hasError = false;

    // Simple email validation
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
        errorBox.textContent = 'Please enter a valid email address.';
        hasError = true;
    }

    // Password validation (minimum 8 characters, at least 1 uppercase, 1 lowercase, 1 number)
    if (password.length < 8) {
        errorBox.textContent = 'Password must be at least 8 characters long.';
        hasError = true;
    } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
        errorBox.textContent = 'Password must contain at least one uppercase letter, one lowercase letter, and one number.';
        hasError = true;
    }

    // Show error message if there are validation errors
    if (hasError) {
        errorBox.style.display = 'block';
        return;
    }

    // Proceed with login request
    fetch('/index', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
        credentials: 'include' // Include credentials for session cookies
    })
    .then(response => {
        return response.json().then(data => {
            if (!response.ok) {
                throw new Error(data.message || 'Login failed.');
            }
            return data;
        });
    })
    .then(data => {
        if (data.success) {
            // Redirect accordingly
            window.location.href = '/dashboard.html';
        } else {
            // Display error message from server
            errorBox.textContent = data.message;
            errorBox.style.display = 'block';
        }
    })
    .catch(error => {
        if (error.message.includes('429')) {
            errorBox.textContent = 'Too many login attempts. Please try again later.';
        } else {
            errorBox.textContent = error.message || 'An error occurred during login.';
        }
        errorBox.style.display = 'block';
    });
});
