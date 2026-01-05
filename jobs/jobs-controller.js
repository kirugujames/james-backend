import dotenv from "dotenv";
import Job from "./Models/Job.js";
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
export async function getAllJobs() {
  try {
    const jobs = await Job.findAll();
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

