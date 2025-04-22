const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();

// Configure CORS to allow specific origin and include necessary headers
app.use(cors({
  origin: ['https://breastcancer-frontend.vercel.app', 'https://mjshealth-hub.vercel.app','https://auth-backend-qyna.onrender.com', 'http://localhost:5173', "https://v0-breast-cancer-detection.vercel.app",'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// User schema and model with roles
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'doctor', 'nurse', 'patient'], default: 'patient' },
  firstName: { type: String },
  lastName: { type: String },
  specialty: { type: String },
  phoneNumber: { type: String },
  address: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Patient schema and model
const patientSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  fullName: { type: String, required: true },
  dateOfBirth: { type: Date, required: true },
  gender: { type: String, enum: ['male', 'female', 'other'], required: true },
  contactNumber: { type: String, required: true },
  email: { type: String },
  address: { type: String },
  emergencyContact: { type: String },
  bloodType: { type: String },
  allergies: [{ type: String }],
  medicalHistory: { type: String },
  insuranceInfo: { type: String },
  status: { type: String, enum: ['active', 'inactive', 'pending'], default: 'active' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Patient = mongoose.model('Patient', patientSchema);

// Health Record schema and model
const healthRecordSchema = new mongoose.Schema({
  patientId: { type: mongoose.Schema.Types.ObjectId, ref: 'Patient', required: true },
  recordType: { type: String, required: true },
  recordDate: { type: Date, default: Date.now, required: true },
  doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  vitalSigns: {
    temperature: { type: Number },
    bloodPressure: { type: String },
    heartRate: { type: Number },
    respiratoryRate: { type: Number },
    oxygenSaturation: { type: Number }
  },
  diagnosis: { type: String },
  treatment: { type: String },
  medications: [{ 
    name: { type: String },
    dosage: { type: String },
    frequency: { type: String },
    duration: { type: String }
  }],
  labResults: [{ 
    testName: { type: String },
    result: { type: String },
    normalRange: { type: String },
    interpretation: { type: String }
  }],
  notes: { type: String },
  attachments: [{ type: String }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const HealthRecord = mongoose.model('HealthRecord', healthRecordSchema);

// Appointment schema and model
const appointmentSchema = new mongoose.Schema({
  patientId: { type: mongoose.Schema.Types.ObjectId, ref: 'Patient', required: true },
  doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  appointmentDate: { type: Date, required: true },
  endTime: { type: Date },
  appointmentType: { type: String, enum: ['consultation', 'follow-up', 'emergency', 'telehealth'], required: true },
  status: { type: String, enum: ['scheduled', 'completed', 'cancelled', 'no-show'], default: 'scheduled' },
  reason: { type: String },
  notes: { type: String },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Appointment = mongoose.model('Appointment', appointmentSchema);

// Notification schema and model
const notificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['appointment', 'message', 'system', 'alert'], default: 'system' },
  isRead: { type: Boolean, default: false },
  relatedId: { type: mongoose.Schema.Types.ObjectId },
  relatedModel: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const Notification = mongoose.model('Notification', notificationSchema);

// Settings schema and model
const settingsSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  theme: { type: String, enum: ['light', 'dark', 'system'], default: 'system' },
  notifications: {
    email: { type: Boolean, default: true },
    sms: { type: Boolean, default: false },
    app: { type: Boolean, default: true }
  },
  language: { type: String, default: 'en' },
  timezone: { type: String, default: 'UTC' },
  updatedAt: { type: Date, default: Date.now }
});

const Settings = mongoose.model('Settings', settingsSchema);

// Authentication middleware
const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// Role-based access middleware
const authorize = (roles = []) => {
  return async (req, res, next) => {
    try {
      const user = await User.findById(req.user.userId);
      
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      
      if (roles.length && !roles.includes(user.role)) {
        return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
      }
      
      next();
    } catch (error) {
      res.status(500).json({ message: 'Server error' });
    }
  };
};

// Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, role, firstName, lastName, specialty } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({
      email,
      password: hashedPassword,
      role: role || 'patient',
      firstName,
      lastName,
      specialty
    });

    await user.save();

    // Create default settings for the user
    const settings = new Settings({
      userId: user._id
    });
    
    await settings.save();

    // Create token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '1h' }
    );

    res.status(201).json({ token, role: user.role });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Create token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '1h' }
    );

    res.json({ token, role: user.role });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// User endpoints
app.get('/api/users/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/users/me', auth, async (req, res) => {
  try {
    const { firstName, lastName, specialty, phoneNumber, address } = req.body;
    
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    if (specialty) user.specialty = specialty;
    if (phoneNumber) user.phoneNumber = phoneNumber;
    if (address) user.address = address;
    
    await user.save();
    
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Patient endpoints
app.post('/api/patients', auth, authorize(['admin', 'doctor', 'nurse']), async (req, res) => {
  try {
    const {
      fullName,
      dateOfBirth,
      gender,
      contactNumber,
      email,
      address,
      emergencyContact,
      bloodType,
      allergies,
      medicalHistory,
      insuranceInfo
    } = req.body;
    
    const patient = new Patient({
      fullName,
      dateOfBirth,
      gender,
      contactNumber,
      email,
      address,
      emergencyContact,
      bloodType,
      allergies: allergies || [],
      medicalHistory,
      insuranceInfo
    });
    
    await patient.save();
    
    res.status(201).json(patient);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/patients', auth, authorize(['admin', 'doctor', 'nurse']), async (req, res) => {
  try {
    const { page = 1, limit = 10, search, status } = req.query;
    
    const query = {};
    
    if (search) {
      query.$or = [
        { fullName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (status) {
      query.status = status;
    }
    
    const patients = await Patient.find(query)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ createdAt: -1 });
      
    const count = await Patient.countDocuments(query);
    
    res.json({
      patients,
      totalPages: Math.ceil(count / limit),
      currentPage: page
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/patients/:id', auth, authorize(['admin', 'doctor', 'nurse']), async (req, res) => {
  try {
    const patient = await Patient.findById(req.params.id);
    
    if (!patient) {
      return res.status(404).json({ message: 'Patient not found' });
    }
    
    res.json(patient);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/patients/:id', auth, authorize(['admin', 'doctor', 'nurse']), async (req, res) => {
  try {
    const {
      fullName,
      dateOfBirth,
      gender,
      contactNumber,
      email,
      address,
      emergencyContact,
      bloodType,
      allergies,
      medicalHistory,
      insuranceInfo,
      status
    } = req.body;
    
    const patient = await Patient.findById(req.params.id);
    
    if (!patient) {
      return res.status(404).json({ message: 'Patient not found' });
    }
    
    if (fullName) patient.fullName = fullName;
    if (dateOfBirth) patient.dateOfBirth = dateOfBirth;
    if (gender) patient.gender = gender;
    if (contactNumber) patient.contactNumber = contactNumber;
    if (email) patient.email = email;
    if (address) patient.address = address;
    if (emergencyContact) patient.emergencyContact = emergencyContact;
    if (bloodType) patient.bloodType = bloodType;
    if (allergies) patient.allergies = allergies;
    if (medicalHistory) patient.medicalHistory = medicalHistory;
    if (insuranceInfo) patient.insuranceInfo = insuranceInfo;
    if (status) patient.status = status;
    
    patient.updatedAt = Date.now();
    
    await patient.save();
    
    res.json(patient);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/patients/:id', auth, authorize(['admin']), async (req, res) => {
  try {
    const patient = await Patient.findById(req.params.id);
    
    if (!patient) {
      return res.status(404).json({ message: 'Patient not found' });
    }
    
    await patient.remove();
    
    res.json({ message: 'Patient removed' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Health Records endpoints
app.post('/api/health-records', auth, authorize(['admin', 'doctor', 'nurse']), async (req, res) => {
  try {
    const {
      patientId,
      recordType,
      recordDate,
      vitalSigns,
      diagnosis,
      treatment,
      medications,
      labResults,
      notes,
      attachments
    } = req.body;
    
    const healthRecord = new HealthRecord({
      patientId,
      recordType,
      recordDate: recordDate || Date.now(),
      doctorId: req.user.userId,
      vitalSigns,
      diagnosis,
      treatment,
      medications: medications || [],
      labResults: labResults || [],
      notes,
      attachments: attachments || []
    });
    
    await healthRecord.save();
    
    // Create notification for the patient
    const patient = await Patient.findById(patientId);
    if (patient && patient.userId) {
      const notification = new Notification({
        userId: patient.userId,
        title: 'New Health Record',
        message: `A new ${recordType} record has been added to your health records.`,
        type: 'system',
        relatedId: healthRecord._id,
        relatedModel: 'HealthRecord'
      });
      
      await notification.save();
    }
    
    res.status(201).json(healthRecord);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/health-records', auth, async (req, res) => {
  try {
    const { patientId, recordType, page = 1, limit = 10 } = req.query;
    
    const query = {};
    
    if (patientId) {
      query.patientId = patientId;
    }
    
    if (recordType) {
      query.recordType = recordType;
    }
    
    // If user is a patient, only show their records
    if (req.user.role === 'patient') {
      const patient = await Patient.findOne({ userId: req.user.userId });
      if (!patient) {
        return res.status(404).json({ message: 'Patient not found' });
      }
      query.patientId = patient._id;
    }
    
    const healthRecords = await HealthRecord.find(query)
      .populate('patientId', 'fullName')
      .populate('doctorId', 'firstName lastName')
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ recordDate: -1 });
      
    const count = await HealthRecord.countDocuments(query);
    
    res.json({
      healthRecords,
      totalPages: Math.ceil(count / limit),
      currentPage: page
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/health-records/:id', auth, async (req, res) => {
  try {
    const healthRecord = await HealthRecord.findById(req.params.id)
      .populate('patientId', 'fullName')
      .populate('doctorId', 'firstName lastName');
    
    if (!healthRecord) {
      return res.status(404).json({ message: 'Health record not found' });
    }
    
    // If user is a patient, only show their records
    if (req.user.role === 'patient') {
      const patient = await Patient.findOne({ userId: req.user.userId });
      if (!patient || !patient._id.equals(healthRecord.patientId._id)) {
        return res.status(403).json({ message: 'Not authorized to view this record' });
      }
    }
    
    res.json(healthRecord);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/health-records/:id', auth, authorize(['admin', 'doctor', 'nurse']), async (req, res) => {
  try {
    const {
      recordType,
      recordDate,
      vitalSigns,
      diagnosis,
      treatment,
      medications,
      labResults,
      notes,
      attachments
    } = req.body;
    
    const healthRecord = await HealthRecord.findById(req.params.id);
    
    if (!healthRecord) {
      return res.status(404).json({ message: 'Health record not found' });
    }
    
    if (recordType) healthRecord.recordType = recordType;
    if (recordDate) healthRecord.recordDate = recordDate;
    if (vitalSigns) healthRecord.vitalSigns = vitalSigns;
    if (diagnosis) healthRecord.diagnosis = diagnosis;
    if (treatment) healthRecord.treatment = treatment;
    if (medications) healthRecord.medications = medications;
    if (labResults) healthRecord.labResults = labResults;
    if (notes) healthRecord.notes = notes;
    if (attachments) healthRecord.attachments = attachments;
    
    healthRecord.updatedAt = Date.now();
    
    await healthRecord.save();
    
    res.json(healthRecord);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/health-records/:id', auth, authorize(['admin', 'doctor']), async (req, res) => {
  try {
    const healthRecord = await HealthRecord.findById(req.params.id);
    
    if (!healthRecord) {
      return res.status(404).json({ message: 'Health record not found' });
    }
    
    await healthRecord.remove();
    
    res.json({ message: 'Health record removed' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Appointment endpoints
app.post('/api/appointments', auth, async (req, res) => {
  try {
    const {
      patientId,
      doctorId,
      appointmentDate,
      endTime,
      appointmentType,
      reason,
      notes
    } = req.body;
    
    // Validate appointment date
    const date = new Date(appointmentDate);
    if (date < new Date()) {
      return res.status(400).json({ message: 'Appointment date cannot be in the past' });
    }
    
    const appointment = new Appointment({
      patientId,
      doctorId: doctorId || req.user.userId,
      appointmentDate,
      endTime,
      appointmentType,
      reason,
      notes
    });
    
    await appointment.save();
    
    // Create notifications for both doctor and patient
    const doctor = await User.findById(doctorId || req.user.userId);
    const patient = await Patient.findById(patientId);
    
    if (doctor) {
      const notification = new Notification({
        userId: doctor._id,
        title: 'New Appointment',
        message: `You have a new ${appointmentType} appointment scheduled for ${new Date(appointmentDate).toLocaleString()}.`,
        type: 'appointment',
        relatedId: appointment._id,
        relatedModel: 'Appointment'
      });
      
      await notification.save();
    }
    
    if (patient && patient.userId) {
      const notification = new Notification({
        userId: patient.userId,
        title: 'New Appointment',
        message: `You have a new ${appointmentType} appointment scheduled for ${new Date(appointmentDate).toLocaleString()}.`,
        type: 'appointment',
        relatedId: appointment._id,
        relatedModel: 'Appointment'
      });
      
      await notification.save();
    }
    
    res.status(201).json(appointment);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/appointments', auth, async (req, res) => {
  try {
    const { 
      patientId, 
      doctorId, 
      status, 
      startDate, 
      endDate, 
      page = 1, 
      limit = 10 
    } = req.query;
    
    const query = {};
    
    if (patientId) {
      query.patientId = patientId;
    }
    
    if (doctorId) {
      query.doctorId = doctorId;
    }
    
    if (status) {
      query.status = status;
    }
    
    if (startDate && endDate) {
      query.appointmentDate = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    } else if (startDate) {
      query.appointmentDate = { $gte: new Date(startDate) };
    } else if (endDate) {
      query.appointmentDate = { $lte: new Date(endDate) };
    }
    
    // If user is a patient, only show their appointments
    if (req.user.role === 'patient') {
      const patient = await Patient.findOne({ userId: req.user.userId });
      if (!patient) {
        return res.status(404).json({ message: 'Patient not found' });
      }
      query.patientId = patient._id;
    }
    
    // If user is a doctor, only show their appointments
    if (req.user.role === 'doctor') {
      query.doctorId = req.user.userId;
    }
    
    const appointments = await Appointment.find(query)
      .populate('patientId', 'fullName')
      .populate('doctorId', 'firstName lastName')
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ appointmentDate: 1 });
      
    const count = await Appointment.countDocuments(query);
    
    res.json({
      appointments,
      totalPages: Math.ceil(count / limit),
      currentPage: page
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/appointments/:id', auth, async (req, res) => {
  try {
    const appointment = await Appointment.findById(req.params.id)
      .populate('patientId', 'fullName')
      .populate('doctorId', 'firstName lastName');
    
    if (!appointment) {
      return res.status(404).json({ message: 'Appointment not found' });
    }
    
    // If user is a patient, only show their appointments
    if (req.user.role === 'patient') {
      const patient = await Patient.findOne({ userId: req.user.userId });
      if (!patient || !patient._id.equals(appointment.patientId._id)) {
        return res.status(403).json({ message: 'Not authorized to view this appointment' });
      }
    }
    
    // If user is a doctor, only show their appointments
    if (req.user.role === 'doctor' && !req.user.userId.equals(appointment.doctorId._id)) {
      return res.status(403).json({ message: 'Not authorized to view this appointment' });
    }
    
    res.json(appointment);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/appointments/:id', auth, async (req, res) => {
  try {
    const {
      appointmentDate,
      endTime,
      appointmentType,
      status,
      reason,
      notes
    } = req.body;
    
    const appointment = await Appointment.findById(req.params.id);
    
    if (!appointment) {
      return res.status(404).json({ message: 'Appointment not found' });
    }
    
    // Check authorization
    if (req.user.role === 'patient') {
      const patient = await Patient.findOne({ userId: req.user.userId });
      if (!patient || !patient._id.equals(appointment.patientId)) {
        return res.status(403).json({ message: 'Not authorized to update this appointment' });
      }
      
      // Patients can only update certain fields
      if (reason) appointment.reason = reason;
      if (status === 'cancelled') appointment.status = status;
    } else if (req.user.role === 'doctor' && !req.user.userId.equals(appointment.doctorId)) {
      return res.status(403).json({ message: 'Not authorized to update this appointment' });
    } else {
      // Doctors and admins can update all fields
      if (appointmentDate) appointment.appointmentDate = appointmentDate;
      if (endTime) appointment.endTime = endTime;
      if (appointmentType) appointment.appointmentType = appointmentType;
      if (status) appointment.status = status;
      if (reason) appointment.reason = reason;
      if (notes) appointment.notes = notes;
    }
    
    appointment.updatedAt = Date.now();
    
    await appointment.save();
    
    // Create notification for status change
    if (status && status !== appointment.status) {
      const patient = await Patient.findById(appointment.patientId);
      const doctor = await User.findById(appointment.doctorId);
      
      if (patient && patient.userId) {
        const notification = new Notification({
          userId: patient.userId,
          title: 'Appointment Status Updated',
          message: `Your appointment scheduled for ${new Date(appointment.appointmentDate).toLocaleString()} has been ${status}.`,
          type: 'appointment',
          relatedId: appointment._id,
          relatedModel: 'Appointment'
        });
        
        await notification.save();
      }
      
      if (doctor) {
        const notification = new Notification({
          userId: doctor._id,
          title: 'Appointment Status Updated',
          message: `The appointment scheduled for ${new Date(appointment.appointmentDate).toLocaleString()} has been ${status}.`,
          type: 'appointment',
          relatedId: appointment._id,
          relatedModel: 'Appointment'
        });
        
        await notification.save();
      }
    }
    
    res.json(appointment);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/appointments/:id', auth, async (req, res) => {
  try {
    const appointment = await Appointment.findById(req.params.id);
    
    if (!appointment) {
      return res.status(404).json({ message: 'Appointment not found' });
    }
    
    // Check authorization
    if (req.user.role === 'patient') {
      const patient = await Patient.findOne({ userId: req.user.userId });
      if (!patient || !patient._id.equals(appointment.patientId)) {
        return res.status(403).json({ message: 'Not authorized to delete this appointment' });
      }
    } else if (req.user.role === 'doctor' && !req.user.userId.equals(appointment.doctorId)) {
      return res.status(403).json({ message: 'Not authorized to delete this appointment' });
    }
    
    await appointment.remove();
    
    res.json({ message: 'Appointment removed' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Notification endpoints
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const { page = 1, limit = 10, isRead } = req.query;
    
    const query = { userId: req.user.userId };
    
    if (isRead !== undefined) {
      query.isRead = isRead === 'true';
    }
    
    const notifications = await Notification.find(query)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ createdAt: -1 });
      
    const count = await Notification.countDocuments(query);
    
    res.json({
      notifications,
      totalPages: Math.ceil(count / limit),
      currentPage: page,
      unreadCount: await Notification.countDocuments({ userId: req.user.userId, isRead: false })
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/notifications/:id/read', auth, async (req, res) => {
  try {
    const notification = await Notification.findById(req.params.id);
    
    if (!notification) {
      return res.status(404).json({ message: 'Notification not found' });
    }
    
    if (!notification.userId.equals(req.user.userId)) {
      return res.status(403).json({ message: 'Not authorized to update this notification' });
    }
    
    notification.isRead = true;
    
    await notification.save();
    
    res.json(notification);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/notifications/read-all', auth, async (req, res) => {
  try {
    await Notification.updateMany(
      { userId: req.user.userId, isRead: false },
      { $set: { isRead: true } }
    );
    
    res.json({ message: 'All notifications marked as read' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/notifications/:id', auth, async (req, res) => {
  try {
    const notification = await Notification.findById(req.params.id);
    
    if (!notification) {
      return res.status(404).json({ message: 'Notification not found' });
    }
    
    if (!notification.userId.equals(req.user.userId)) {
      return res.status(403).json({ message: 'Not authorized to delete this notification' });
    }
    
    await notification.remove();
    
    res.json({ message: 'Notification removed' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Settings endpoints
app.get('/api/settings', auth, async (req, res) => {
  try {
    let settings = await Settings.findOne({ userId: req.user.userId });
    
    if (!settings) {
      settings = new Settings({ userId: req.user.userId });
      await settings.save();
    }
    
    res.json(settings);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/settings', auth, async (req, res) => {
  try {
    const { theme, notifications, language, timezone } = req.body;
    
    let settings = await Settings.findOne({ userId: req.user.userId });
    
    if (!settings) {
      settings = new Settings({ userId: req.user.userId });
    }
    
    if (theme) settings.theme = theme;
    if (notifications) settings.notifications = notifications;
    if (language) settings.language = language;
    if (timezone) settings.timezone = timezone;
    
    settings.updatedAt = Date.now();
    
    await settings.save();
    
    res.json(settings);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Analytics endpoints
app.get('/api/analytics/patients', auth, authorize(['admin', 'doctor']), async (req, res) => {
  try {
    const totalPatients = await Patient.countDocuments();
    const activePatients = await Patient.countDocuments({ status: 'active' });
    const inactivePatients = await Patient.countDocuments({ status: 'inactive' });
    const pendingPatients = await Patient.countDocuments({ status: 'pending' });
    
    const patientsByGender = await Patient.aggregate([
      { $group: { _id: '$gender', count: { $sum: 1 } } }
    ]);
    
    const newPatients = await Patient.countDocuments({
      createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
    });
    
    res.json({
      totalPatients,
      activePatients,
      inactivePatients,
      pendingPatients,
      patientsByGender,
      newPatients
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/analytics/appointments', auth, authorize(['admin', 'doctor']), async (req, res) => {
  try {
    const totalAppointments = await Appointment.countDocuments();
    const scheduledAppointments = await Appointment.countDocuments({ status: 'scheduled' });
    const completedAppointments = await Appointment.countDocuments({ status: 'completed' });
    const cancelledAppointments = await Appointment.countDocuments({ status: 'cancelled' });
    const noShowAppointments = await Appointment.countDocuments({ status: 'no-show' });
    
    const appointmentsByType = await Appointment.aggregate([
      { $group: { _id: '$appointmentType', count: { $sum: 1 } } }
    ]);
    
    const upcomingAppointments = await Appointment.countDocuments({
      appointmentDate: { $gte: new Date() },
      status: 'scheduled'
    });
    
    res.json({
      totalAppointments,
      scheduledAppointments,
      completedAppointments,
      cancelledAppointments,
      noShowAppointments,
      appointmentsByType,
      upcomingAppointments
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/analytics/health-records', auth, authorize(['admin', 'doctor']), async (req, res) => {
  try {
    const totalRecords = await HealthRecord.countDocuments();
    
    const recordsByType = await HealthRecord.aggregate([
      { $group: { _id: '$recordType', count: { $sum: 1 } } }
    ]);
    
    const recentRecords = await HealthRecord.countDocuments({
      createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
    });
    
    res.json({
      totalRecords,
      recordsByType,
      recentRecords
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
