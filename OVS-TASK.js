// Import dependencies
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

// Initialize app
const app = express();
app.use(express.json());

// MongoDB connection
mongoose.connect('mongodb://localhost/multi-tenant-ecommerce', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
});

// JWT secret
const JWT_SECRET = 'your_jwt_secret';

// Define Schemas
const vendorSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  stock: { type: Number, required: true },
  vendor: { type: mongoose.Schema.Types.ObjectId, ref: 'Vendor', required: true },
  createdAt: { type: Date, default: Date.now },
});

const orderSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  quantity: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'shipped'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
});

// Models
const Vendor = mongoose.model('Vendor', vendorSchema);
const Product = mongoose.model('Product', productSchema);
const Order = mongoose.model('Order', orderSchema);

// Middleware for JWT authentication
const authenticateVendor = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.vendor = await Vendor.findById(decoded.id);
    if (!req.vendor) return res.status(401).json({ error: 'Unauthorized' });
    next();
  } catch (err) {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100,
});
app.use('/api/', apiLimiter);

// Vendor registration
app.post(
  '/api/vendors/register',
  [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Invalid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      const vendor = new Vendor({ name, email, password: hashedPassword });
      await vendor.save();
      res.status(201).json({ message: 'Vendor registered successfully' });
    } catch (err) {
      res.status(500).json({ error: 'Vendor registration failed' });
    }
  }
);

// Vendor login
app.post(
  '/api/vendors/login',
  [body('email').isEmail(), body('password').notEmpty()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;

    try {
      const vendor = await Vendor.findOne({ email });
      if (!vendor || !(await bcrypt.compare(password, vendor.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign({ id: vendor._id }, JWT_SECRET, { expiresIn: '1h' });
      res.json({ token });
    } catch (err) {
      res.status(500).json({ error: 'Login failed' });
    }
  }
);

// Product management
app.post('/api/products', authenticateVendor, async (req, res) => {
  const { name, price, stock } = req.body;

  try {
    const product = new Product({ name, price, stock, vendor: req.vendor._id });
    await product.save();
    res.status(201).json(product);
  } catch (err) {
    res.status(500).json({ error: 'Failed to add product' });
  }
});

app.get('/api/products', authenticateVendor, async (req, res) => {
  const { page = 1, limit = 10 } = req.query;

  try {
    const products = await Product.find({ vendor: req.vendor._id })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

app.put('/api/products/:id', authenticateVendor, async (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  try {
    const product = await Product.findOneAndUpdate(
      { _id: id, vendor: req.vendor._id },
      updates,
      { new: true }
    );

    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json(product);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update product' });
  }
});

app.delete('/api/products/:id', authenticateVendor, async (req, res) => {
  const { id } = req.params;

  try {
    const product = await Product.findOneAndDelete({ _id: id, vendor: req.vendor._id });
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json({ message: 'Product deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

// Order management
app.get('/api/orders', authenticateVendor, async (req, res) => {
  try {
    const orders = await Order.find({})
      .populate({
        path: 'product',
        match: { vendor: req.vendor._id },
      })
      .exec();

    const filteredOrders = orders.filter(order => order.product !== null);
    res.json(filteredOrders);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.put('/api/orders/:id', authenticateVendor, async (req, res) => {
  const { id } = req.params;

  try {
    const order = await Order.findById(id).populate('product');
    if (!order || order.product.vendor.toString() !== req.vendor._id.toString()) {
      return res.status(404).json({ error: 'Order not found' });
    }

    order.status = 'shipped';
    await order.save();
    res.json(order);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update order status' });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
