const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const dbPool = require('./db'); // Adjust the path to your db.js file

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// Validate email format
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Validate mobile format
function isValidMobile(mobile) {
    const mobileRegex = /^[0-9]{10}$/;
    return mobileRegex.test(mobile);
}

// Authentication route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Validate inputs
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        const connection = await dbPool.getConnection();

        const [userRow] = await connection.execute(
            'SELECT usr_user_id, username, first_name, last_name, password, first_login, is_logged_in FROM authentication INNER JOIN users ON users.user_id = authentication.usr_user_id WHERE username = ?',
            [username]
        );

        connection.release();

        if (userRow.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }
        console.log(userRow)

        const user = userRow[0];

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
            expiresIn: '1h',
        });

        // Store token in the database
        const updateTokenQuery = 'UPDATE authentication SET token = ? WHERE usr_user_id = ?';
        await dbPool.query(updateTokenQuery, [token, user.id]);

        res.status(200).json({ token, first_login: user.first_login[0], username: user.username, first_name: user.first_name, last_name: user.last_name });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Registration route
app.post('/register', async (req, res) => {
    const { username, email, mobile, firstName, lastName, age, gender, profileBase64 } = req.body;

    // Validate inputs
    if (!username || !email || !mobile || !firstName || !lastName || !age || !gender || !profileBase64) {
        return res.status(400).json({ message: 'All fields are required' });
    }


    if (!isValidEmail(email)) {
        return res.status(400).json({ message: 'Invalid email format' });
    }

    if (!isValidMobile(mobile)) {
        return res.status(400).json({ message: 'Invalid mobile format' });
    }

    // Generate a random password
    const randomPassword = Math.random().toString(36).slice(-8); // 8-character random string

    try {
        const connection = await dbPool.getConnection();

        // Check if username or email already exists
        const [existingUser] = await connection.execute(
            'SELECT * FROM authentication INNER JOIN users ON authentication.usr_user_id = users.user_id WHERE username = ? OR email = ?',
            [username, email]
        );

        if (existingUser.length > 0) {
            connection.release();
            return res.status(400).json({ message: 'Username or email already exists' });
        }

        // Hash the random password
        const hashedPassword = await bcrypt.hash(randomPassword, 10);

        // Insert user data into user table with base64 profile image
        const insertUserQuery =
            'INSERT INTO users (profile, first_name, last_name, gender, age) VALUES (?, ?, ?, ?, ?)';
        const [insertAuthResult] = await connection.query(insertUserQuery, [profileBase64, firstName, lastName, gender, age]);

        const user_id = insertAuthResult.insertId;
        console.log(user_id)
        // Insert new user into authentication table
        const insertAuthQuery =
            'INSERT INTO authentication (username, password, email, mobile, usr_user_id) VALUES (?, ?, ?, ?, ?)';
        await connection.query(insertAuthQuery, [username, hashedPassword, email, mobile, user_id]);


        connection.release();

        res.status(201).json({ message: 'Registration successful', password: randomPassword });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Change password route
app.post('/change-password', async (req, res) => {
    const { username, password, confirmPassword } = req.body;
  
    // Validate inputs
    if (!username || !password || !confirmPassword) {
      return res.status(400).json({ message: 'All fields are required' });
    }
  
    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Password and confirm password do not match' });
    }
  
    try {
      const connection = await dbPool.getConnection();
  
      // Retrieve user by username
      const [userRow] = await connection.execute('SELECT usr_user_id, password FROM authentication WHERE username = ?', [username]);
      if (userRow.length === 0) {
        connection.release();
        return res.status(404).json({ message: 'User not found' });
      }
  
      const user = userRow[0];
  
      // Hash the new password
      const hashedNewPassword = await bcrypt.hash(password, 10);
  
      // Update user's password
      await connection.execute('UPDATE authentication SET password = ?, first_login = 0, is_logged_in = 1 WHERE usr_user_id = ?', [hashedNewPassword, user.usr_user_id]);
  
      connection.release();
  
      res.status(200).json({ message: 'Password changed successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
