const minPasswordLength = 8;
const maxPasswordLength = 20;
const specialCharacters = "!@#$%^&*()_+-=[]{};':\"\\|,.<>/?";

function togglePassword() {
    const passwordInput = document.getElementById('newPassword');
    const passwordCheck = document.getElementById('confirmPassword');
    const showPasswordCheckbox = document.getElementById('show-password');

    if (showPasswordCheckbox.checked) {
        passwordInput.type = 'text';
        passwordCheck.type = 'text';
    } else {
        passwordInput.type = 'password';
        passwordCheck.type = 'password';
    }
}

document.getElementById('resetPasswordForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const resetKey = document.getElementById('resetKey').value.trim();
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (resetKey === '') {
        alert('Please enter a valid token key.');
        return;
    }

    if (newPassword.length < minPasswordLength || newPassword.length > maxPasswordLength) {
        alert(`Password must be between ${minPasswordLength} and ${maxPasswordLength} characters long.`);
        return;
    }

    if (newPassword.toLowerCase() === newPassword) {
        alert("Password must contain at least one uppercase letter.");
        return;
    }

    let hasSpecialChar = false;
    for (let char of newPassword) {
        if (specialCharacters.includes(char)) {
            hasSpecialChar = true;
            break;
        }
    }
    if (!hasSpecialChar) {
        alert("Password must contain at least one special character.");
        return;
    }

    if (newPassword !== confirmPassword) {
        alert("Passwords don't match!");
        return;
    }

    fetch(this.action, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ resetKey: resetKey, newPassword: newPassword })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Your password has been reset successfully.');
            window.location.href = 'index.html'; 
        } else {
            alert(data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred.');
    });
});
