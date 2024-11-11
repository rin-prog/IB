require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const bodyParser = require('body-parser');
const sgMail = require('@sendgrid/mail');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Rate limiter for login route
const loginLimiter = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: 'Too many login attempts, please try again after 30 minutes.',
    handler: function (req, res, next, options) {
        res.status(options.statusCode).json({ success: false, message: options.message });
    }
});

// MongoDB Connection using Mongoose
const mongoUri = process.env.MONGO_URI;
mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch((err) => {
        console.error('Failed to connect to MongoDB', err);
        process.exit(1);
    });

// Session Management
app.use(session({
    secret: process.env.SESSION_SECRET || 'yourSecretKeyHere',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: mongoUri }),
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 30 * 60 * 1000 // 30 minutes session expiry
    }
}));

// MongoDB Schema for User (with resetKey and resetExpires fields)
const userSchema = new mongoose.Schema({
    emaildb: { type: String, required: true },
    password: { type: String, required: true },
    resetKey: { type: String, default: null },
    resetExpires: { type: Date, default: null },
    fullName: { type: String },
    birthday: { type: Date },
});

const User = mongoose.model('User', userSchema);

// Helper Functions
function hashPassword(password) {
    const saltRounds = 10;
    return bcrypt.hashSync(password, saltRounds);
}

function generateRandomString(length) {
    return [...Array(length)].map(() => (~~(Math.random() * 36)).toString(36)).join('');
}

// Login Route with Rate Limiting and Enhanced Security
app.post('/index', loginLimiter, async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }
        if (!validator.isEmail(email)) {
            return res.status(400).json({ success: false, message: 'Invalid email format.' });
        }

        const user = await User.findOne({ emaildb: email });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid email or password.' });
        }

        if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
            const remainingTime = Math.ceil((user.accountLockedUntil - new Date()) / 60000);
            return res.status(403).json({ success: false, message: `Account is locked. Try again in ${remainingTime} minutes.` });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            let invalidAttempts = (user.invalidLoginAttempts || 0) + 1;
            let updateFields = { invalidLoginAttempts: invalidAttempts };
            if (invalidAttempts >= 3) {
                updateFields.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000);
                updateFields.invalidLoginAttempts = 0;
                await User.updateOne({ _id: user._id }, { $set: updateFields });

                return res.status(403).json({ success: false, message: 'Account is locked due to multiple failed login attempts. Please try again after 30 minutes.' });
            } else {
                await User.updateOne({ _id: user._id }, { $set: updateFields });
                return res.status(400).json({ success: false, message: 'Invalid email or password.' });
            }
        }

        await User.updateOne(
            { _id: user._id },
            { $set: { invalidLoginAttempts: 0, accountLockedUntil: null, lastLoginTime: new Date() } }
        );
        req.session.userId = user._id;
        req.session.email = user.emaildb;
        req.session.role = user.role;

        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) return reject(err);
                resolve();
            });
        });
        res.json({ success: true, role: user.role, message: 'Login successful!' });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ success: false, message: 'Error during login.' });
    }
});

function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized access.' });
    }
}

// Protected Route for Dashboard
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/dashboard.html');
});

app.get('/user-details', isAuthenticated, async (req, res) => {
    try {
        const email = req.session.email;
        if (!email) {
            return res.status(401).json({ success: false, message: 'Unauthorized access.' });
        }
        // Fetch user details, only retrieving the email field
        const user = await User.findOne({ emaildb: email }, 'emaildb');
        
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        
        res.json({
            success: true,
            user: { email: user.emaildb }
        });
        } catch (error) {
            console.error('Error fetching user details:', error);
            res.status(500).json({ success: false, message: 'Error fetching user details.' });
        }
    });

// Logout Route
app.post('/logout', async (req, res) => {
    if (!req.session.userId) {
        return res.status(400).json({ success: false, message: 'No user is logged in.' });
    }
    try {
        req.session.destroy(err => {
            if (err) {
                console.error('Error destroying session:', err);
                return res.status(500).json({ success: false, message: 'Logout failed.' });
            }
            res.clearCookie('connect.sid');
            // Prevent caching
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
            res.setHeader('Surrogate-Control', 'no-store');
            return res.json({ success: true, message: 'Logged out successfully.' });
        });
    } catch (error) {
        console.error('Error during logout:', error);
        return res.status(500).json({ success: false, message: 'Failed to log out.' });
    }
});

// Sign-Up Route
app.post('/signup', async (req, res) => {
    const { email, password, fullName, birthday } = req.body; //here also

    try {
        // Check if the email already exists using the User model
        const existingUser = await User.findOne({ emaildb: email });
        if (existingUser) {
            res.status(400).json({ success: false, message: 'Email already registered.' });
            return;
        }

        const hashedPassword = hashPassword(password);
        await

        usersCollection.insertOne({emaildb:email,password:hashedPassword});

        res.json({ success: true, message: 'Account created successfully.', redirectUrl: '/index.html' });
    } catch (error) {
        console.error('Error creating account:', error);
        res.status(500).json({ success: false, message: 'Error creating account.' });
    }
});


// Password Reset Request Route
app.post('/send-password-reset', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required' });
    }

    try {
        const user = await User.findOne({ emaildb: email });
        if (!user) {
            return res.status(404).json({ success: false, message: 'No account with that email address exists.' });
        }

        // Generate reset key and expiration
        const resetKey = generateRandomString(32);
        const resetExpires = new Date(Date.now() + 3600000); // 1 hour expiration

        // Update user's resetKey and resetExpires
        await User.updateOne(
            { emaildb: email },
            { $set: { resetKey: resetKey, resetExpires: resetExpires } }
        );

        // Send reset email using SendGrid
        const msg = {
            to: email,
            from: 'rinprog24@gmail.com',
            subject: 'Password Reset Request',
            text: `Your password reset token is: ${resetKey}`,
            html: `<p>Your password reset token is:</p><h3>${resetKey}</h3>`,
        };

        await sgMail.send(msg);
        res.json({ success: true, redirectUrl: '/reset-password.html' });

    } catch (error) {
        console.error('Error processing your request', error);
        res.status(500).json({ success: false, message: 'Error processing your request.' });
    }
});

// Reset Password Route
app.post('/reset-password', async (req, res) => {
    const { resetKey, newPassword } = req.body;

    if (!resetKey || !newPassword) {
        return res.status(400).json({ success: false, message: 'Reset key and new password are required' });
    }

    try {
        // Find user by resetKey and ensure it hasn't expired
        const user = await User.findOne({
            resetKey: resetKey,
            resetExpires: { $gt: new Date() } // Check if the token is still valid
        });

        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid or expired reset key.' });
        }

        // Hash the new password
        const hashedPassword = hashPassword(newPassword);

        // Update user's password and clear resetKey/resetExpires
        await User.updateOne(
            { _id: user._id },
            {
                $set: {
                    password: hashedPassword,
                    resetKey: null,
                    resetExpires: null
                }
            }
        );

        res.json({ success: true,redirectUrl: '/index.html' , message: 'Your password has been successfully reset.' });

    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ success: false, message: 'Error resetting password.' });
    }
});


// Server Listening
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});