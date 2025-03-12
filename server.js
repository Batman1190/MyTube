const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs'); // Add this line
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// Update the static file serving to use absolute path
const UPLOAD_DIR = path.join('G:\\CSR Notes\\MyWATCHTUBE PROJECT', 'uploads');

// Create uploads directory if it doesn't exist
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Configure static serving with proper MIME types
app.use('/uploads', express.static(UPLOAD_DIR, {
    setHeaders: (res, path) => {
        if (path.endsWith('.mp4')) {
            res.set('Content-Type', 'video/mp4');
        } else if (path.endsWith('.webm')) {
            res.set('Content-Type', 'video/webm');
        }
    }
}));

// Simple in-memory user storage (replace with database in production)
const users = [];
const videos = []; // In-memory storage for videos
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// Rate limiting middleware
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

// Apply rate limiting to all routes
app.use(limiter);

// Configure storage for uploaded files
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, UPLOAD_DIR)
    },
    filename: function(req, file, cb) {
        // Sanitize filename
        const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
        cb(null, Date.now() + '_' + sanitizedName)
    }
});

const upload = multer({ 
    storage: storage,
    fileFilter: function(req, file, cb) {
        if (!file.mimetype.startsWith('video/')) {
            return cb(new Error('Only video files are allowed!'));
        }
        cb(null, true);
    }
});

// Authentication Routes
app.post('/api/register', [
    body('username').trim().isLength({ min: 3 }).escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    try {
        // Check for validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, email, password } = req.body;
        
        // Check if user already exists
        if (users.find(u => u.email === email)) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Store user
        users.push({
            username,
            email,
            password: hashedPassword
        });

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Error registering user' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Find user
        const user = users.find(u => u.email === email);
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid password' });
        }

        // Create token
        const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '24h' });
        
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: 'Error logging in' });
    }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Access denied' });

    try {
        const verified = jwt.verify(token.split(' ')[1], JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        res.status(400).json({ error: 'Invalid token' });
    }
};

// Serve uploaded files
app.use('/uploads', express.static(UPLOAD_DIR));

// Ensure all routes can access static files
app.use(express.static(UPLOAD_DIR));

// Get list of videos with complete file paths
app.get('/videos', (req, res) => {
    // Scan the upload directory for video files
    fs.readdir(UPLOAD_DIR, (err, files) => {
        if (err) {
            console.error('Error reading upload directory:', err);
            return res.status(500).json({ error: 'Error reading videos' });
        }

        // Filter for video files and create video objects
        const videoFiles = files.filter(file => {
            const ext = path.extname(file).toLowerCase();
            return ['.mp4', '.webm', '.mov', '.avi'].includes(ext);
        });

        // Update videos array with any files found in directory
        videoFiles.forEach(file => {
            if (!videos.find(v => v.filename === file)) {
                videos.push({
                    filename: file,
                    title: file,
                    description: '',
                    uploadDate: new Date()
                });
            }
        });

        const videosWithPaths = videos.map(video => ({
            ...video,
            url: `/uploads/${video.filename}`,
            thumbnailUrl: `/uploads/${video.filename.replace(/\.[^.]+$/, '')}_thumb.jpg`
        }));

        console.log('Available videos:', videosWithPaths); // Debug log
        res.json(videosWithPaths);
    });
});

// Handle video upload - add console.log for debugging
app.post('/upload', verifyToken, upload.single('video'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded.' });
        }

        // Check file size (e.g., limit to 100MB)
        const maxSize = 100 * 1024 * 1024; // 100MB in bytes
        if (req.file.size > maxSize) {
            // Clean up the uploaded file
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'File too large. Maximum size is 100MB.' });
        }

        console.log('Uploaded file:', req.file); // Debug log
        
        // Validate video metadata
        if (!req.body.title) {
            // Clean up the uploaded file if metadata is invalid
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'Video title is required.' });
        }

        const video = {
            filename: req.file.filename,
            title: req.body.title || 'Untitled',
            description: req.body.description || '',
            uploadedBy: req.user.email,
            uploadDate: new Date()
        };
        videos.push(video);
        
        console.log('Video added:', video); // Debug log

        res.json({
            message: 'Video uploaded successfully',
            filename: req.file.filename
        });
    } catch (error) {
        // Clean up the uploaded file in case of error
        if (req.file) {
            fs.unlinkSync(req.file.path);
        }
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Error uploading video' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});