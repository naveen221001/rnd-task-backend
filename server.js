require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({
  jwksUri: 'https://login.microsoftonline.com/69eaf322-247b-4276-925b-427c5af8d5c3/discovery/v2.0/keys'
});
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'yourSecretKey';

function getKey(header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

function authenticateMicrosoftToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Token missing' });

  jwt.verify(token, getKey, {}, (err, decoded) => {
    if (err) {
      console.error("❌ Microsoft token verification failed:", err);
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = decoded;
    next();
  });
}
// Middleware
app.use(cors());
app.use(express.json());

// Connect to MongoDB Atlas or your MongoDB instance
const mongoURI = process.env.MONGODB_URI ;
mongoose.connect(mongoURI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define Mongoose Schema and Model for Tasks
const taskSchema = new mongoose.Schema({
  user: { type: String, required: true },
  title: { type: String, required: true },
  description: { type: String },
  priority: { type: String, default: 'low' },
  timestamp: { type: String, default: new Date().toLocaleString() },
}, { timestamps: true });
const Task = mongoose.model('Task', taskSchema);

// Define Mongoose Schema and Model for Users
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['member', 'admin'], default: 'member' }
});
const User = mongoose.model('User', userSchema);

// Middleware to verify JWT for protected routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  // Expecting the header to be in the format: "Bearer <token>"
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Root Route (optional)


// GET tasks for the authenticated user
app.get('/api/tasks', authenticateMicrosoftToken, async (req, res) => {
  const user = req.user.preferred_username || req.user.upn || req.user.email;

  try {
    const tasks = await Task.find({ user });
    res.json(tasks);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// User Registration Endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username and password are required.' });
      
    // Check if user exists
    const existingUser = await User.findOne({ username });
    if (existingUser)
      return res.status(400).json({ error: 'Username already exists.' });

    // Hash password and save user
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: 'User created successfully.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// User Login Endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username and password are required.' });
    
    const user = await User.findOne({ username });
    if (!user)
      return res.status(400).json({ error: 'Invalid credentials.' });

    // Compare the password with the stored hash
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword)
      return res.status(400).json({ error: 'Invalid credentials.' });
      
    // Generate JWT token
    const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Protected Task Endpoints: Only accessible to authenticated users

// GET all tasks for the authenticated user
app.get('/api/all-tasks', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403); // 🛑 Block non-admins

  try {
    const tasks = await Task.find().sort({ timestamp: -1 });
    res.json(tasks);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// POST a new task for the authenticated user
app.post('/api/tasks', authenticateMicrosoftToken, async (req, res) => {
  const { title, description, priority, timestamp } = req.body;
  const user = req.user.preferred_username || req.user.upn || req.user.email;

  try {
    const newTask = new Task({ title, description, priority, timestamp, user });
    await newTask.save();
    res.status(201).json({ message: 'Task added' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



// PUT (update) a task (ensure that the task belongs to the authenticated user)
app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const { title, description, priority } = req.body;
    const task = await Task.findById(req.params.id);
    if (!task) return res.status(404).json({ error: 'Task not found.' });
    // Check if the task belongs to the user making the request
    if (task.user !== req.user.username) return res.status(403).json({ error: 'Unauthorized' });
    
    task.title = title || task.title;
    task.description = description || task.description;
    task.priority = priority || task.priority;
    await task.save();
    res.json(task);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE a task (ensure that the task belongs to the authenticated user)
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);
    if (!task) return res.status(404).json({ error: 'Task not found.' });
    if (task.user !== req.user.username) return res.status(403).json({ error: 'Unauthorized' });
    
    await Task.findByIdAndDelete(req.params.id);
    res.json({ message: 'Task deleted.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start the server once the DB connection is established
mongoose.connection.once('open', () => {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
});


const cron = require('node-cron');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

// Run every day at 12:30 PM
cron.schedule('30 12 * * *', async () => {
  console.log("🕒 Running EOD task report job...");

  try {
    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(today.getDate() - 1);

    const formattedDate = yesterday.toISOString().split('T')[0];

    const tasks = await Task.find({
      timestamp: { $regex: formattedDate }
    });

    if (!tasks.length) {
      console.log("ℹ️ No tasks found for yesterday.");
      return;
    }

    // ✅ Generate PDF
    const doc = new PDFDocument({ margin: 50 });
    const pdfPath = path.join(__dirname, `eod_report_${formattedDate}.pdf`);
    const writeStream = fs.createWriteStream(pdfPath);
    doc.pipe(writeStream);

    doc.fontSize(20).fillColor('#b30000').text(`📋 EOD Task Report - ${formattedDate}`, {
      align: 'center',
      underline: true
    });

    doc.moveDown();

    tasks.forEach((task, index) => {
      doc
        .fontSize(14)
        .fillColor('#333')
        .text(`${index + 1}. ${task.title} (${task.priority})`, { continued: true })
        .font('Helvetica-Oblique')
        .text(` — by ${task.user}`);

      doc
        .font('Helvetica')
        .text(`Description: ${task.description}`)
        .text(`Timestamp: ${task.timestamp}`)
        .moveDown(1);
    });

    doc.end();

    // Wait until PDF file is written
    writeStream.on('finish', async () => {
      // ✅ Send Email
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER, // ✅ Replace with actual sender
          pass: process.env.EMAIL_PASS           // ✅ Use app password
        }
      });

      await transporter.sendMail({
        from: '"R&D Portal" <yourcompany.email@gmail.com>',
        to: 'naveenchamaria2001@gmail.com',
        subject: `EOD Task Report - ${formattedDate}`,
        text: `Please find attached the task report for ${formattedDate}.`,
        attachments: [
          {
            filename: `EOD_Report_${formattedDate}.pdf`,
            path: pdfPath
          }
        ]
      });

      console.log("✅ EOD report emailed successfully.");

      // ✅ Delete the tasks from DB
      await Task.deleteMany({ timestamp: { $regex: formattedDate } });
      console.log("🧹 Yesterday's tasks deleted.");

      // Cleanup: delete PDF file
      fs.unlinkSync(pdfPath);
    });

  } catch (error) {
    console.error("❌ EOD report job failed:", error);
  }
});
