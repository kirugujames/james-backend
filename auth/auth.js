import connection from './../database.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;

//authenticate user
export async function authenticateUser(username, password) {
    try {
        const [rows] = await connection.query('SELECT * FROM user WHERE username = ?', [username]);
        if (rows.length === 0) {
            return { message: "User not found", data: null, statusCode: 404 };
        }

        const user = rows[0];
        const isPasswordValid = await bcrypt.compare(password.trim(), user.password);

        if (!isPasswordValid) {
            return { message: "Invalid credentials", data: null, statusCode: 401 };
        }

        if (user.is_logged_in) {
            return { message: "User already logged in from another device", data: null, statusCode: 403 };
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, role_id: user.role_id },
            JWT_SECRET_KEY,
            { expiresIn: '1h' }
        );

        await connection.query(
            'UPDATE user SET session_token = ?, is_logged_in = TRUE WHERE id = ?',
            [token, user.id]
        );

        const role = await getRoleById(user.role_id);
        const userData = {
            id: user.id,
            username: user.username,
            role_id: user.role_id,
            role_name: role.data?.role_name,
            token: token
        };

        return {
            message: "Authentication successful",
            data: userData,
            statusCode: 200
        };

    } catch (err) {
        console.error('Error in authenticateUser:', err.message);
        return {
            message: "Internal server error",
            data: null,
            statusCode: 500
        };
    }
}
//register user
export async function registerUser(username, password, email, role_id) {
    try {
        const existingUser = await connection.query(
            'SELECT * FROM user WHERE username = ?',
            [username]
        );

        if (existingUser[0].length > 0) {
            return {
                message: "Username already taken",
                data: null,
                statusCode: 409
            };
        }

        const hashedPassword = await bcrypt.hash(password.trim(), 10);

        const result = await connection.query(
            'INSERT INTO user (username, password, email, role_id) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, email, role_id]
        );

        return {
            message: "User registered successfully",
            data: { id: result[0].insertId },
            statusCode: 201
        };
    } catch (err) {
        console.error('Error in registerUser:', err.message);
        if (err.code === 'ER_DUP_ENTRY') {
            return {
                message: "Email already registered",
                data: null,
                statusCode: 409
            };
        }
        return {
            message: "Internal server error",
            data: null,
            statusCode: 500
        };
    }
}

//get user by id
export async function getUserById(id) {
    try {
        const result = await connection.query(
            'SELECT id, username, email, role_id FROM user WHERE id = ?',
            [id]
        );

        if (result[0].length > 0) {
            return {
                message: "User found",
                data: result[0][0],
                statusCode: 200
            };
        } else {
            return {
                message: "User not found",
                data: null,
                statusCode: 404
            };
        }
    } catch (err) {
        console.error('Error in getUserById:', err.message);
        return {
            message: "Internal server error",
            data: null,
            statusCode: 500
        };
    }
}

//get all users
export async function getAllUsers() {
    try {
        const result = await connection.query(
            'SELECT id, username, email, role_id FROM user'
        );
        return {
            message: "Users fetched successfully",
            data: result[0],
            statusCode: 200
        };
    } catch (err) {
        console.error('Error in getAllUsers:', err.message);
        return {
            message: "Internal server error",
            data: null,
            statusCode: 500
        };
    }
}

//create role
export async function createRole(name) {
    try {
        const result = await connection.query('INSERT INTO role (role_name) VALUES (?)', [name]);
        return {
            message: "Role created successfully",
            data: { id: result[0].insertId },
            statusCode: 201
        };
    } catch (error) {
        console.error('Error in createRole:', error);
        if (error.code === 'ER_DUP_ENTRY') {
            return {
                message: "Role already exists",
                data: null,
                statusCode: 409
            };
        }
        return {
            message: "Internal server error",
            data: null,
            statusCode: 500
        };
    }
}

//get role by id
export async function getRoleById(id) {
    try {
        const result = await connection.query(
            'SELECT * FROM role WHERE id = ?',
            [id]
        ); if (result[0].length > 0) {
            return {
                message: "Role found",
                data: result[0][0],
                statusCode: 200
            };
        }
        else {
            return {
                message: "Role not found",
                data: null,
                statusCode: 404
            };
        }
    } catch (error) {
        return {
            message: "Internal server error",
            data: null,
            statusCode: 500
        };
    }
}

