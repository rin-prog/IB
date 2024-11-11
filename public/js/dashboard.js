// Fetch user details when the page loads
 document.addEventListener('DOMContentLoaded', function () {
    fetchUserDetails();
});

// Function to fetch user details from the server
async function fetchUserDetails() {
    try {
        const response = await fetch('/user-details', { credentials: 'include' });
        
        // If the response is not OK, throw an error
        if (!response.ok) {
            throw new Error('Failed to fetch user details.');
        }

        // Parse the response as JSON
        const data = await response.json();
        console.log("Fetched user data:", data); // Debug log to check the response

        // If the user data is successfully fetched, update the UI
        if (data.success) {
            document.getElementById('userEmail').textContent = data.user.email;
        } else {
            console.error('Failed to fetch user details:', data.message);
            document.getElementById('userEmail').textContent = 'Error fetching user details';
        }
    } catch (error) {
        console.error('Error fetching user details:', error);
        document.getElementById('userEmail').textContent = 'User not logged in. Please log in.';
        // Optionally redirect to login page if error occurs
        window.location.href = '/login.html';  // Redirect to the login page if no user is found
    }
}

// Add logout functionality
document.getElementById('logoutLink').addEventListener('click', function (event) {
    event.preventDefault();
    performLogout();
});

// Function to handle the logout process
async function performLogout() {
    try {
        const response = await fetch('/logout', {
            method: 'POST',
            credentials: 'include'  // Include credentials (cookies) with the request
        });

        if (response.ok) {
            
            window.location.href = '/index.html';  
        } else {
            console.error('Logout failed');
        }
    } catch (error) {
        console.error('Error during logout:', error);
    }
}