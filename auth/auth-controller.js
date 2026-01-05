import { Sequelize } from "sequelize";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { User, Role } from "./models/index.js";
import { sendOtp, verifyOtp } from "../utils/otp-service.js";
import { sendEmail } from "../utils/send-email.js";
import crypto from "crypto";

dotenv.config();
const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;

// Register User
export async function registerUser(req) {
  const { username, password, email, role_id } = req.body;
  try {
    const existingUser = await User.findOne({ where: { username } });
    if (existingUser)
      return { statusCode: 409, message: "Username already exists", data: null };

    const hashedPassword = await bcrypt.hash(password.trim(), 10);
    const user = await User.create({ username: email, password: hashedPassword, email, role_id });

    await sendEmail({
      to: email,
      subject: "Welcome to Our Service",
      message: `Hello , your member code is  ${username} and password  is ${password}, your account has been created successfully.`,
    });

    return {
      statusCode: 201,
      message: "User registered successfully",
      data: user,
    };
  } catch (err) {
    if (err.name == "SequelizeForeignKeyConstraintError") {
      return { statusCode: 500, message: "role not found", data: null };
    }
    return { statusCode: 500, message: err.message.split(":")[0], data: null };
  }
}
export async function registerUserAsMember(username, password, role_id, email) {
  try {
    const existingUser = await User.findOne({ where: { username } });
    if (existingUser)
      return { statusCode: 409, message: "Username already exists", data: null };

    const hashedPassword = await bcrypt.hash(password.trim(), 10);
    const user = await User.create({ username, password: hashedPassword, email, role_id });

    await sendEmail({
      to: email,
      subject: "Welcome to Our Service",
      message: `Hello , your member code is  ${username} and password  is ${password}, your account has been created successfully.`,
    });

    return {
      statusCode: 201,
      message: "User registered successfully",
      data: user,
    };
  } catch (err) {
    if (err.name == "SequelizeForeignKeyConstraintError") {
      return { statusCode: 500, message: "role not found", data: null };
    }
    return { statusCode: 500, message: err.message.split(":")[0], data: null };
  }
}
//get all users
export async function getAllUsers() {
  try {
    const result = await User.findAll()
    return {
      message: "users fetched successfully",
      statusCode: 200,
      data: result
    }
  } catch (error) {
    return {
      message: error.message.split(":")[0],
      statusCode: 500,
      data: null
    }
  }
}
// Authenticate User
export async function authenticateUser(req) {
  const { username, password } = req.body; // username can be email
  try {
    const user = await User.findOne({
      where: {
        [Sequelize.Op.or]: [
          { username: username },
          { email: username }
        ]
      }
    });

    if (!user)
      return { statusCode: 404, message: "User not found", data: null };

    if (user.status === "deactivated")
      return { statusCode: 403, message: "Account is deactivated. Please contact admin.", data: null };

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword)
      return { statusCode: 401, message: "Invalid credentials", data: null };

    // if (user.is_logged_in)
    //   return { statusCode: 403, message: "User already logged in", data: null };

    const token = jwt.sign(
      { id: user.id, username: user.username, role_id: user.role_id },
      JWT_SECRET_KEY,
      { expiresIn: "24h" }
    );

    const refreshToken = jwt.sign(
      { id: user.id },
      JWT_SECRET_KEY,
      { expiresIn: "7d" }
    );

    await user.update({
      session_token: token,
      refresh_token: refreshToken,
      is_logged_in: true
    });

    const roleResult = await getRoleById(user?.role_id);
    const userData = {
      email: user?.email,
      role_name: roleResult.data?.role_name,
      username: user?.username,
      is_logged_in: user?.is_logged_in,
      id: user?.id,
      role_id: user?.role_id,
      status: user?.status
    }

    // Optional: Send OTP if enabled
    // await sendOtp(user.email);

    const data = {
      token: token,
      refreshToken: refreshToken,
      user: userData
    }

    return {
      statusCode: 200,
      message: "Login successful",
      data: data,
    };
  } catch (err) {
    console.error("Auth Error:", err);
    return { statusCode: 500, message: err.message, data: null };
  }
}

// Verify OTP
export async function verifyAuthOtp(req) {
  try {
    const result = await verifyOtp(req);
    console.log(result);
    if (!result.ok)
      return { statusCode: 400, message: "Invalid OTP", data: null };

    return { statusCode: 200, message: "OTP verified successfully", data: null };
  } catch (err) {
    return { statusCode: 500, message: err.message, data: null };
  }
}

// Resend OTP
export async function resendOtp(req) {
  const { email } = req.body;
  try {
    const result = await sendOtp(email);
    if (!result.ok)
      return { statusCode: 500, message: "Failed to resend OTP", data: null };

    return { statusCode: 200, message: "OTP resent successfully", data: null };
  } catch (err) {
    return { statusCode: 500, message: err.message, data: null };
  }
}

// Forgot Password - Send Link
export async function forgotPassword(req) {
  const { email } = req.body;
  try {
    const user = await User.findOne({ where: { email } });
    if (!user)
      return { statusCode: 404, message: "User with this email not found", data: null };

    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetExpires = new Date(Date.now() + 3600000); // 1 hour

    await user.update({
      reset_password_token: resetToken,
      reset_password_expires: resetExpires
    });

    const resetLink = `${process.env.CLIENT_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;

    await sendEmail({
      to: email,
      subject: "Password Reset Request",
      message: `You requested a password reset. Please click the link below to reset your password:\n\n${resetLink}\n\nIf you did not request this, please ignore this email.`,
    });

    return { statusCode: 200, message: "Password reset link sent to email", data: null };
  } catch (err) {
    return { statusCode: 500, message: err.message, data: null };
  }
}

// Reset Password with Token
export async function resetPasswordWithToken(req) {
  const { token, newPassword } = req.body;
  try {
    const user = await User.findOne({
      where: {
        reset_password_token: token,
        reset_password_expires: { [Sequelize.Op.gt]: new Date() }
      }
    });

    if (!user)
      return { statusCode: 400, message: "Invalid or expired reset token", data: null };

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await user.update({
      password: hashedPassword,
      reset_password_token: null,
      reset_password_expires: null
    });

    return { statusCode: 200, message: "Password has been reset successfully", data: null };
  } catch (err) {
    return { statusCode: 500, message: err.message, data: null };
  }
}

// Change Password (Authenticated)
export async function changePassword(req) {
  const { email, oldPassword, newPassword } = req.body;
  try {
    const user = await User.findOne({ where: { email } });
    if (!user)
      return { statusCode: 404, message: "User not found", data: null };

    const validPassword = await bcrypt.compare(oldPassword, user.password);
    if (!validPassword)
      return { statusCode: 400, message: "Invalid current password", data: null };

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await user.update({ password: hashedPassword });

    return { statusCode: 200, message: "Password changed successfully", data: null };
  } catch (err) {
    return { statusCode: 500, message: err.message, data: null };
  }
}

// Activate / Deactivate User
export async function toggleUserStatus(req) {
  const { id, status } = req.body; // status: active or deactivated
  try {
    const user = await User.findByPk(id);
    if (!user)
      return { statusCode: 404, message: "User not found", data: null };

    await user.update({ status });
    return { statusCode: 200, message: `User account ${status} successfully`, data: null };
  } catch (err) {
    return { statusCode: 500, message: err.message, data: null };
  }
}

// Logout
export async function logoutUser(req) {
  const { username } = req.user;
  try {
    const user = await User.findOne({ where: { username } });
    if (!user)
      return { statusCode: 404, message: "User not found", data: null };

    await user.update({ session_token: null, is_logged_in: false });
    return { statusCode: 200, message: "Logout successful", data: null };
  } catch (err) {
    return { statusCode: 500, message: err.message, data: null };
  }
}

// Create Role
export async function createRole(req) {
  const { name } = req.body;
  const role_name = name;
  try {
    const existingRole = await Role.findOne({ where: { role_name } });
    if (existingRole)
      return { statusCode: 409, message: "Role already exists", data: null };

    const role = await Role.create({ role_name });
    return { statusCode: 201, message: "Role created successfully", data: role };
  } catch (err) {
    return { statusCode: 500, message: err.message, data: null };
  }
}

// Get Roles
export async function getRoles() {
  try {
    const roles = await Role.findAll();
    return { statusCode: 200, message: "Roles retrieved", data: roles };
  } catch (err) {
    return { statusCode: 500, message: err.message, data: null };
  }
}

// Update Role
export async function updateRole(req) {
  const { id, name } = req.body
  const role_name = name
  try {
    const role = await Role.findByPk(id);
    if (!role)
      return { statusCode: 404, message: "Role not found", data: null };

    await role.update({ role_name });
    return { statusCode: 200, message: "Role updated successfully", data: role };
  } catch (err) {
    return { statusCode: 500, message: err.message, data: null };
  }
}

// Delete Role
export async function deleteRole(req) {
  const { id } = req.params;
  try {
    const role = await Role.findByPk(id);
    if (!role)
      return { statusCode: 404, message: "Role not found", data: null };

    await role.destroy();
    return { statusCode: 200, message: "Role deleted successfully", data: null };
  } catch (err) {
    return { statusCode: 500, message: err.message, data: null };
  }
}

//get role  by  id 
export async function getRoleById(id) {
  try {
    const role = await Role.findByPk(id);

    if (!role) {
      return { statusCode: 404, message: "Role not found", data: null };
    }

    return {
      statusCode: 200,
      message: "Role retrieved successfully",
      data: role,
    };
  } catch (err) {
    return { statusCode: 500, message: err.message, data: null };
  }
}

// Refresh Access Token
export async function refreshAccessToken(req) {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return { statusCode: 400, message: "Refresh token is required", data: null };
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET_KEY);
    const user = await User.findOne({
      where: {
        id: decoded.id,
        refresh_token: refreshToken
      }
    });

    if (!user) {
      return { statusCode: 401, message: "Invalid refresh token", data: null };
    }

    if (user.status === "deactivated") {
      return { statusCode: 403, message: "Account is deactivated", data: null };
    }

    const newAccessToken = jwt.sign(
      { id: user.id, username: user.username, role_id: user.role_id },
      JWT_SECRET_KEY,
      { expiresIn: "24h" }
    );

    await user.update({ session_token: newAccessToken });

    return {
      statusCode: 200,
      message: "Token refreshed successfully",
      data: { token: newAccessToken }
    };
  } catch (err) {
    return { statusCode: 401, message: "Invalid or expired refresh token", data: null };
  }
}
