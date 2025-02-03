// Import modules
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const mongoose = require('mongoose');
require('dotenv').config();
const bcrypt = require('bcryptjs');
const session = require('express-session');
var multer = require('multer');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

const fs = require('fs');
const uploadsDir = path.join(__dirname, 'uploads');

if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}
var storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/')
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname))
    }
});
var upload = multer({ storage: storage });

// Connection to MongoDB
mongoose.connect(process.env.URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('Error connecting to MongoDB:', err);
});

// User schema
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    email: { type: String, unique: true },
    password: String,
    img: { type: String }
});

const User = mongoose.model('User', userSchema);


// Registration
app.get('/registration', (req, res) => {
    res.render('registration', { message: null });
});

app.post('/registration', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        const existingUsername = await User.findOne({ username });
        if (existingUsername) {
            return res.render('registration', { message: 'User with this username is already exists' });
        }

        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.render('registration', { message: 'User with this email is already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword });

        await newUser.save();
        res.redirect('/login');
    } catch (err) {
        res.status(500).send('Error creating user');
    }
});


// Login
app.get('/login', (req, res) => {
    res.render('login', { message: null });
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = await User.findOne({ username });
        if (!user) {
            return res.render('login', { message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.render('login', { message: 'Incorrect password' });
        }

        req.session.user = user;
        res.redirect('/profile');
    } catch (err) {
        res.status(500).send('Error logging in');
    }
});

// Profile page
app.get('/profile', isAuthenticated, (req, res) => {
    res.render('profile', { user: req.session.user, message: null });
});

// Update profile
app.post('/update_user', isAuthenticated, async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const userId = req.session.user._id;

        const existingUsername = await User.findOne({ username, _id: { $ne: userId } });
        if (existingUsername) {
            return res.render('profile', { user: req.session.user, message: 'User with this username is already exists' });
        }

        const existingEmail = await User.findOne({ email, _id: { $ne: userId } });
        if (existingEmail) {
            return res.render('profile', { user: req.session.user, message: 'User with this email is already exists' });
        }
        
        const updateData = { username, email };
        if (password) {
            updateData.password = await bcrypt.hash(password, 10);
        }

        const updatedUser = await User.findByIdAndUpdate(userId, updateData, { new: true });

        req.session.user = updatedUser; 

        res.redirect('/profile');
    } catch (err) {
        res.status(500).send('Error updating profile')
    }
});

// Delete profile
app.post('/delete_user', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.user._id;
        
        await User.findByIdAndDelete(userId);

        req.session.destroy(err => {
            if (err) {
                return res.status(500).send('Error deleting profile');
            }
            res.redirect('/login');
        });
    } catch (err) {
        res.status(500).send('Error deleting profile');
    }
});

// Update profile image
app.post('/update_avatar', isAuthenticated, upload.single('avatar'), async (req, res) => {
    try {
        if (!req.file) {
            return res.render('profile', { user: req.session.user, message: 'No file uploaded' });
        }

        const userId = req.session.user._id;
        const imagePath = `/uploads/${req.file.filename}`;

        const updatedUser = await User.findByIdAndUpdate(userId, { img: imagePath }, { new: true });

        req.session.user.img = updatedUser.img;
        res.redirect('/profile');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error updating avatar');
    }
});



// Authentification
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.redirect('/login');
}


// Log out
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Error logging out');
        }
        res.redirect('/login');
    });
});


// Reset password
app.get('/reset', (req, res) => {
    res.render('reset', { message: null });
});

app.post('/reset', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.render('reset', { message: 'User not found' });
        }

        const newHashedPassword = await bcrypt.hash(password, 10);

        await User.findByIdAndUpdate(user._id, { password: newHashedPassword }, { new: true });

        res.redirect('/login');
    } catch (err) {
        res.status(500).send('Error updating password')
    }
});


// All users in json 
app.get('/users', async (req, res) => {
    try {
        const users = await User.find()
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: 'Error retrieving users' });
    }
});

app.use((req, res) => {
    res.redirect('/profile');
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}/`));
