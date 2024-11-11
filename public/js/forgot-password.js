document.addEventListener('DOMContentLoaded', function() { // Ensure the DOM is loaded before attaching listeners
    const form = document.getElementById('forgotPasswordForm');
    const emailField = document.getElementById('email');

    // Check if form and email elements exist
    if (!form) {
        console.error("Form element with id 'forgotPasswordForm' not found.");
        return;
    }
    if (!emailField) {
        console.error("Email input element with id 'email' not found.");
        return;
    }

    form.addEventListener('submit', function(event) {
        event.preventDefault(); // Prevent the default form submission

        const email = emailField.value;

        if (!email) {
            alert("Please enter your email address.");
            return; // If the email is empty, do not proceed
        }

        // AJAX request
        fetch('/send-password-reset', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email }) // Send the email in the request body
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                window.location.href = data.redirectUrl; // Redirect if successful
            } else {
                alert(data.message || 'An error occurred, please try again.');
            }
        })
        .catch(error => {
            console.error('Error:', error); // Improved error handling
            alert('An unexpected error occurred. Please try again later.');
        });
    });
});
