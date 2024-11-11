const minPasswordLength = 5;
const maxPasswordLength = 15;
const birthdayInput = document.getElementById('birthday');
const specialCharacters = "!@#$%^&*()_+-=[]{};':\"\\|,.<>/?";

function isValidEmail(email) {
    return email.includes('@') && email.toLowerCase().endsWith('.com');
}

function togglePassword() {
    const passwordInput = document.getElementById('password');
    const confirmPassword = document.getElementById('confirmPassword');
    const showPasswordCheckbox = document.getElementById('show-password');
    
    passwordInput.type = showPasswordCheckbox.checked ? 'text' : 'password';
    confirmPassword.type = showPasswordCheckbox.checked ? 'text' : 'password';
}

document.getElementById('signupForm').addEventListener('submit', function(e) {
    e.preventDefault();

    const fullName = document.getElementById('fullName').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (!isValidEmail(email)) {
        alert('Please enter a valid email address with @ and ending with .com');
        return;
    }

    if (password.length < minPasswordLength || password.length > maxPasswordLength) {
        alert(`Password must be between ${minPasswordLength} and ${maxPasswordLength} characters long.`);
        return;
    }
    
    if (password !== confirmPassword) {
        alert("Passwords don't match!");
        return;
    }

    let hasSpecialChar = false;
    for (let char of password) { 
        if (specialCharacters.includes(char)) {
            hasSpecialChar = true;
            break;
        }
    }
    if (!hasSpecialChar) {
        alert("Password must contain at least one special character.");
        return;
    }
    
    fetch(this.action, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, password: password })
    })
    .then(response =>
        return response.json())
    .then(data => {
        if (data.success) {
            alert('Account created successfully! You can now log in.');
            window.location.href = 'index.html'; 
        } else {
            alert(data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred. Please try again later.');
    });
});

birthdayInput.addEventListener('change', function() {
    const selectedDate = new Date(birthdayInput.value);
    const selectedYear = selectedDate.getFullYear();

    if (selectedYear >= 2015) {
        alert('You should be at least 18 years old! (year 2007 and below)');
        birthdayInput.value = '';
    }
});