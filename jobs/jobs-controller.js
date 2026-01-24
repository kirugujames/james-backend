import dotenv from "dotenv";
import Job from "./Models/Job.js";
import JobApplication from "./Models/JobApplication.js";
import { sendEmail } from "../utils/send-email.js";
dotenv.config();

// create job
export async function createJob(req) {
  try {
    const { job_title, description } = req.body;
    const postedBy = req?.user?.username ?? "admin";

    const job = await Job.create({
      job_title,
      description,
      posted_by: postedBy,
    });

    return {
      message: "Job created successfully",
      data: job,
      statusCode: 201,
    };
  } catch (error) {
    console.error("Create job error:", error);
    return {
      message: "Failed to create job, please retry",
      data: null,
      statusCode: 500,
    };
  }
}

// get all jobs
export async function getAllJobs(req) {
  try {
    const { active } = req.query;
    const where = {};
    if (active === "true") {
      where.status = "Active";
    } else if (active === "false") {
      where.status = "Inactive";
    }
    const jobs = await Job.findAll({ where });
    return {
      message: "jobs retrieved successfully",
      data: jobs,
      statusCode: 200,
    };
  } catch (error) {
    console.error("Get all jobs error:", error);
    return {
      message: "failed to fetch jobs",
      statusCode: 500,
      data: null,
    };
  }
}

// get job listing by id
export async function getJobListingById(id) {
  try {
    const job = await Job.findByPk(id);
    if (!job) {
      return {
        message: "no job listing found",
        statusCode: 404,
        data: null,
      };
    }
    return {
      message: "job fetched successfully",
      statusCode: 200,
      data: job,
    };
  } catch (error) {
    console.error("Get job by ID error:", error);
    return {
      message: "failed to fetch job listing",
      statusCode: 500,
      data: null,
    };
  }
}

// delete job listing
export async function deleteJob(id) {
  try {
    const job = await Job.findByPk(id);
    if (!job) {
      return {
        message: "no job listing found",
        statusCode: 404,
        data: null,
      };
    }

    await job.destroy();
    return {
      message: "job listing deleted successfully",
      statusCode: 200,
      data: null,
    };
  } catch (error) {
    console.error("Delete job error:", error);
    return {
      message: "job listing deletion failed",
      statusCode: 500,
      data: null,
    };
  }
}

// update job listing
export async function updateJobListing(req) {
  const { job_title, description, status, id } = req.body;

  try {
    const job = await Job.findByPk(id);
    if (!job) {
      return {
        message: "no job listing found",
        statusCode: 404,
        data: null,
      };
    }

    await job.update({ job_title, description, status });

    return {
      message: "job listing updated successfully",
      statusCode: 200,
      data: null,
    };
  } catch (error) {
    console.error("Update job error:", error);
    return {
      message: "failed to update job listing",
      statusCode: 500,
      data: null,
    };
  }
}

// Apply for a job
export async function applyForJob(req) {
  try {
    const { job_id, first_name, last_name, email, phone, document, cover_letter } = req.body;

    const job = await Job.findByPk(job_id);
    if (!job) {
      return {
        message: "Job listing not found",
        statusCode: 404,
        data: null,
      };
    }

    const application = await JobApplication.create({
      job_id,
      first_name,
      last_name,
      email,
      phone,
      document,
      cover_letter,
      status: "Pending",
    });

    return {
      message: "Application submitted successfully",
      statusCode: 201,
      data: application,
    };
  } catch (error) {
    console.error("Apply for job error:", error);
    return {
      message: error.message || "Failed to submit application",
      statusCode: 500,
      data: null,
    };
  }
}

// Update application status
export async function updateJobApplicationStatus(req) {
  try {
    const { id, status } = req.body;

    const validStatuses = ["Pending", "Reviewed", "Shortlisted", "Rejected", "Accepted"];
    if (!validStatuses.includes(status)) {
      return {
        message: "Invalid status value",
        statusCode: 400,
        data: null,
      };
    }

    const application = await JobApplication.findByPk(id);
    if (!application) {
      return {
        message: "Application not found",
        statusCode: 404,
        data: null,
      };
    }

    await application.update({ status });

    // Send email notification
    try {
      const { email, first_name } = application;
      let emailMessage = `Dear ${first_name},\n\nYour job application status has been updated to: ${status}.`;

      if (status === 'Rejected' && req.body.reason) {
        emailMessage += `\n\nReason: ${req.body.reason}`;
      }

      emailMessage += `\n\nBest regards,\nRecruitment Team`;

      await sendEmail({
        to: email,
        subject: `Job Application Update: ${status}`,
        message: emailMessage
      });
    } catch (emailError) {
      console.error("Failed to send status update email:", emailError);
      // Continue execution, do not fail the request just because email failed
    }

    return {
      message: `Application status updated to ${status} successfully`,
      statusCode: 200,
      data: application,
    };
  } catch (error) {
    console.error("Update application status error:", error);
    return {
      message: error.message || "Internal server error",
      statusCode: 500,
      data: null,
    };
  }
}

// Get all applications
export async function getAllJobApplications() {
  try {
    const applications = await JobApplication.findAll({
      include: [{ model: Job, attributes: ["job_title"] }],
    });
    return {
      message: "Job applications fetched successfully",
      statusCode: 200,
      data: applications,
    };
  } catch (error) {
    console.error("Get all job applications error:", error);
    return {
      message: error.message,
      statusCode: 500,
      data: null,
    };
  }
}

// Get applications for a specific job
export async function getApplicationsByJob(jobId) {
  try {
    const applications = await JobApplication.findAll({
      where: { job_id: jobId },
    });
    return {
      message: "Job applications fetched successfully",
      statusCode: 200,
      data: applications,
    };
  } catch (error) {
    console.error("Get applications by job error:", error);
    return {
      message: error.message,
      statusCode: 500,
      data: null,
    };
  }
}

