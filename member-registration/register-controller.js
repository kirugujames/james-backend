import dotenv from "dotenv";
import MemberRegistration from "./models/memberRegistration.js";
import { registerUserAsMember } from "../auth/auth-controller.js";
import { randomBytes } from "crypto";

dotenv.config();

// Register member
export async function registerMember(req) {
  console.log("Incoming register request:", req.body);

  const {
    first_name,
    last_name,
    email,
    dob,
    gender,
    phone,
    idNo,
    Constituency,
    ward,
    county,
    area_of_interest,
    doc_type,
    username,
    role_id,
    transaction_id,
  } = req.body;

  const password = generateStrongTempPassword();

  try {
    // Check for duplicates
    const existing = await MemberRegistration.findOne({
      where: {
        email: email,
      },
    });

    const phoneCheck = await MemberRegistration.findOne({ where: { phone } });
    const idCheck = await MemberRegistration.findOne({ where: { idNo } });

    if (existing) {
      return {
        message: "Email already registered",
        data: null,
        statusCode: 409,
      };
    }

    if (phoneCheck) {
      return {
        message: "Phone number already registered",
        data: null,
        statusCode: 409,
      };
    }

    if (idCheck) {
      return {
        message: "ID number already registered",
        data: null,
        statusCode: 409,
      };
    }

    // Generate member code
    const member_code = generateMemberCode();

    // Create member
    const member = await MemberRegistration.create({
      first_name,
      last_name,
      email,
      dob,
      gender,
      phone,
      idNo,
      constituency: Constituency,
      ward,
      county,
      area_of_interest,
      doc_type,
      member_code,
      transaction_id,
      is_paid: transaction_id ? true : false,
      status: "active",
    });

    // Create user login account too
    const authResponse = await registerUserAsMember(member_code, password, role_id, email);

    console.log("User registration response:", authResponse);

    return {
      message: "Member registered successfully",
      data: {
        id: member.id,
        member_code,
      },
      statusCode: 201,
    };
  } catch (error) {
    console.error("Register Error:", error);
    return {
      message: error.message || "Internal server error",
      data: null,
      statusCode: 500,
    };
  }
}

// Generate unique member code
function generateMemberCode() {
  const prefix = "SFU";
  const randomNumber = Math.floor(100000 + Math.random() * 900000);
  return `${prefix}-${randomNumber}`;
}

// Get all members
export async function getAllMembers() {
  try {
    const members = await MemberRegistration.findAll();
    return {
      message: "Members fetched successfully",
      data: members,
      statusCode: 200,
    };
  } catch (error) {
    return {
      message: error.message,
      data: null,
      statusCode: 500,
    };
  }
}

// Get member by ID
export async function getMember(id) {
  try {
    const member = await MemberRegistration.findByPk(id);
    if (!member) {
      return {
        message: "Member not found",
        data: null,
        statusCode: 404,
      };
    }
    return {
      message: "Member fetched successfully",
      data: member,
      statusCode: 200,
    };
  } catch (error) {
    return {
      message: error.message,
      data: null,
      statusCode: 500,
    };
  }
}

// Get member by National ID
export async function getMemberByIdNo(idNo) {
  try {
    const member = await MemberRegistration.findOne({ where: { idNo } });
    if (!member) {
      return {
        message: "Member not found with that ID number",
        data: null,
        statusCode: 404,
      };
    }
    return {
      message: "Member fetched successfully",
      data: member,
      statusCode: 200,
    };
  } catch (error) {
    return {
      message: error.message,
      data: null,
      statusCode: 500,
    };
  }
}

// Delete member
export async function deleteMember(id) {
  try {
    const member = await MemberRegistration.findByPk(id);
    if (!member) {
      return {
        message: "Member not found",
        data: null,
        statusCode: 404,
      };
    }

    await member.destroy();
    return {
      message: "Member deleted successfully",
      data: null,
      statusCode: 200,
    };
  } catch (error) {
    console.log(error)
    return {
      message: error.message,
      data: null,
      statusCode: 500,
    };
  }
}

// Update member
export async function updateMember(req) {
  try {
    const {
      first_name,
      last_name,
      email,
      dob,
      gender,
      phone,
      idNo,
      constituency,
      ward,
      county,
      area_of_interest,
      doc_type,
      id,
    } = req.body;

    const member = await MemberRegistration.findByPk(id);
    if (!member) {
      return {
        message: "Member not found",
        statusCode: 404,
      };
    }

    await member.update({
      first_name,
      last_name,
      email,
      dob,
      gender,
      phone,
      idNo,
      constituency,
      ward,
      county,
      area_of_interest,
      doc_type,
    });

    return {
      message: "Member updated successfully",
      data: member,
      statusCode: 200,
    };
  } catch (error) {
    return {
      message: error.message,
      data: null,
      statusCode: 500,
    };
  }

}

// Toggle Member Status (Withdrawn/Active)
export async function toggleMemberStatus(req) {
  const { id, status } = req.body; // active or withdrawn
  try {
    const member = await MemberRegistration.findByPk(id);
    if (!member) {
      return {
        message: "Member not found",
        statusCode: 404,
      };
    }

    await member.update({ status });
    return {
      message: `Member status updated to ${status} successfully`,
      data: member,
      statusCode: 200,
    };
  } catch (error) {
    return {
      message: error.message,
      data: null,
      statusCode: 500,
    };
  }
}

function generateStrongTempPassword() {
  return randomBytes(6)
    .toString("base64")
    .replace(/[^a-zA-Z0-9]/g, "")
    .slice(0, 10);
}
