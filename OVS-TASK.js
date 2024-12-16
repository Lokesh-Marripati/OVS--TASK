//  Objective: Create a backend API for a multi-tenant e-commerce system where multiple vendors can register, manage their products, and handle orders. Use Node.js, Express.js, and MongoDB for the backend.     --- 
// Task Requirements:   1. Vendor Management   Vendors should be able to register and login.   JWT-based authentication is required.   Vendors can manage only their products and orders.     Vendor Schema:   name (String)   email (String, unique)   password (Hashed)   createdAt (Date, default: current timestamp)       --- 
//  2. Product Management   Vendors can add, update, delete, and list their products.   Implement pagination for the product list.     Product Schema:   name (String)   price (Number)   stock (Number)   vendor (Reference to Vendor)   createdAt (Date, default: current timestamp)       --- 
//  3. Order Management   Vendors can view orders placed for their products.   Implement a route to mark an order as shipped.     Order Schema:   product (Reference to Product)   quantity (Number)   status (Enum: ["pending", "shipped"], default: pending)   createdAt (Date, default: current timestamp)      
// 4. API Endpoints   Authentication:   1. POST /api/vendors/register - Vendor registration     2. POST /api/vendors/login - Vendor login       Product Management: 3. POST /api/products - Add a new product 4. GET /api/products - List all products (pagination required: ?page=1&limit=10) 5. PUT /api/products/:id - Update product details 6. DELETE /api/products/:id - Delete a product   Order Management: 7. GET /api/orders - List all orders for the vendor’s products 8. PUT /api/orders/:id - Mark an order as shipped     ---   5. Security Requirements   Protect all routes with JWT authentication.   Vendors can only access their own data (e.g., they cannot modify another vendor's products or view their orders).       ---   6. Additional Requirements   Validate all incoming data using Joi or express-validator.   Use MongoDB Indexes to optimize product searches and queries.   Handle errors gracefully and return appropriate HTTP status codes.       ---   Bonus Points (Optional):   1. Deploy the API to a platform like Heroku or Render.     2. Add basic rate-limiting using a library like express-rate-limit.     3. Write basic test cases using Jest or Mocha.         ---   Deliverables:   1. Source code in a GitHub repository with proper documentation.     2. Postman collection or cURL commands for testing the API.     3. A short write-up explaining the structure of the application and how to run it.         ---   Evaluation Criteria:   1. Code Quality: Clean, modular, and readable code with appropriate comments.     2. Security: Proper implementation of authentication and authorization.     3. Scalability: Ability to handle multiple vendors and their products efficiently.     4. Performance: Pagination and MongoDB optimization techniques.    
// 5. Problem-Solving Approach: Thought process in handling real-world scenarios like multi-tenancy.  




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
