require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const cron = require('node-cron');

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
function generatePDF(tasks, filePath, formattedDate) {
  const doc = new PDFDocument({ margin: 40 });
  const red = "#b30000";
  const lightRow1 = "#fff5f5";
  const lightRow2 = "#ffe6e6";

  doc.pipe(fs.createWriteStream(filePath));

  // Header Banner
  doc
    .rect(0, 0, doc.page.width, 60)
    .fill(red)
    .fillColor("white")
    .font("Helvetica-Bold")
    .fontSize(18)
    .text(`R&D Tasks Achieved - ${formattedDate}`, 40, 20, {
      align: "center",
      baseline: "middle",
    });

  let y = 90;

  // Table Header
  doc
    .font("Helvetica-Bold")
    .fontSize(12)
    .fillColor("white")
    .rect(40, y, 520, 30)
    .fill(red)
    .fillColor("white")
    .text("Employee", 50, y + 8, { width: 140, align: "left" })
    .text("Task Title", 200, y + 8, { width: 120, align: "left" })
    .text("Task Description", 340, y + 8, { width: 200, align: "left" });

  y += 30;

  // Table Rows
  tasks.forEach((task, index) => {
    const bgColor = index % 2 === 0 ? lightRow1 : lightRow2;
    doc
      .fillColor(bgColor)
      .rect(40, y, 520, 40)
      .fill(bgColor)
      .fillColor("black")
      .font("Helvetica")
      .fontSize(10)
      .text(task.user, 50, y + 10, { width: 140 })
      .text(task.title, 200, y + 10, { width: 120 })
      .text(task.description, 340, y + 10, { width: 200 });

    y += 40;
  });

  // Footer
  doc
    .fontSize(8)
    .fillColor("gray")
    .text(
      `© R&D Portal | Auto-generated on: ${new Date().toLocaleString()}`,
      40,
      doc.page.height - 40,
      { align: "center" }
    );

  doc.end();
}

// Cron job: Generate and send PDF report at 12:30 PM daily
cron.schedule("* * * * *", async () => {
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

    // Generate PDF
    const pdfPath = path.join(__dirname, `eod_report_${formattedDate}.pdf`);
    generatePDF(tasks, pdfPath, formattedDate);

// Wait a moment to ensure the PDF has been written
setTimeout(async () => {
  const transporter = nodemailer.createTransport({
    host: "smtp.office365.com",
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  await transporter.sendMail({
    from: `"R&D Portal" <${process.env.EMAIL_USER}>`,
    to: "naveenchamaria2001@gmail.com",
    subject: `EOD Task Report - ${formattedDate}`,
    text: `Please find attached the task report for ${formattedDate}.`,
    attachments: [
      {
        filename: `EOD_Report_${formattedDate}.pdf`,
        path: pdfPath,
      },
    ],
  });

  console.log("✅ EOD report emailed successfully.");
  await Task.deleteMany({ timestamp: { $regex: formattedDate } });
  console.log("🧹 Yesterday's tasks deleted.");
  fs.unlinkSync(pdfPath);
}, 1000); // wait 1 second


  } catch (error) {
    console.error("❌ EOD report job failed:", error);
  }
});

// Start the server once the DB connection is established
mongoose.connection.once('open', () => {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
});
