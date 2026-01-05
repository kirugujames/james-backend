import Blog from "./Models/Blog.js";
import BlogCategory from "./Models/BlogCategory.js";
import Comment from "./Models/Comments.js";

// Get all blogs
export async function getAllBlog() {
  try {
    const blogs = await Blog.findAll();
    return { message: "Blogs fetched successfully", data: blogs, statusCode: 200 };
  } catch (error) {
    return { message: error.message, error: error.message, statusCode: 500 };
  }
}

// Create blog
export async function createBlog(req) {
  try {
    const { title, category, content, image, isMain } = req.body;
    const posted_by = req.user?.username || "Anonymous";
    const blog = await Blog.create({ title, category, content, image, posted_by, isMain });
    return { message: "Blog created successfully", data: { id: blog.id }, statusCode: 201 };
  } catch (error) {
    return { message: error.message, error: error.message, statusCode: 500 };
  }
}

//get main  blog
export async function getMainBlog(data) {
  console.log(data)
  try {
    const result = await Blog.findAll({ where: { isMain: data } });
    return { message: "Blog retrieved successfully", statusCode: 200, data: result }
  } catch (error) {
    return { message: error.message, error: error.message, statusCode: 500 };
  }
}

//create blog category
export async function addBlogCategory(req) {
  try {
    const { category } = req.body;
    const posted_by = req.user?.username || "Anonymous";
    const blogCategory = await BlogCategory.create({ category, posted_by });
    return { message: "Blog Category created successfully", data: { id: blogCategory.id }, statusCode: 201 };
  } catch (error) {
    if (error.name === 'SequelizeUniqueConstraintError') {
      return { message: "Blog category exists", error: error.message, statusCode: 500 };
    }
    return { message: error.message, error: error.message, statusCode: 500 };
  }
}

export async function getAllBlogCategory(req) {
  try {
    const blogCategory = await BlogCategory.findAll();
    return { message: "Blog Category retrieved successfully", data: blogCategory, statusCode: 201 };
  } catch (error) {
    return { message: error.message, error: error.message, statusCode: 500 };
  }
}
export async function getAllBlogByCategory(req) {
  const { category } = req.query;
  try {
    const blog = await Blog.findAll({
      where: { category: category }
    });
    console.log(blog)
    return { message: "Blogs retrieved successfully", data: blog, statusCode: 201 };
  } catch (error) {
    console.log(error.message)
    return { message: error.message, error: error.message, statusCode: 500 };
  }
}
// Get blog by ID
export async function getBlogById(id) {
  try {
    const blog = await Blog.findByPk(id, { include: Comment });
    if (!blog) return { message: "Blog not found", data: null, statusCode: 404 };
    return { message: "Blog fetched successfully", data: blog, statusCode: 200 };
  } catch (error) {
    return { message: error.message, error: error.message, statusCode: 500 };
  }
}

// Update blog by ID
export async function updateBlogById(req) {
  try {
    const { title, category, content, image, id } = req.body;
    const blog = await Blog.findByPk(id);
    if (!blog) return { message: "Blog not found", data: null, statusCode: 404 };

    await blog.update({ title, category, content, image });
    return { message: "Blog updated successfully", data: null, statusCode: 200 };
  } catch (error) {
    return { message: error.message, error: error.message, statusCode: 500 };
  }
}

// Delete blog by ID
export async function deleteBlogById(id) {
  try {
    const blog = await Blog.findByPk(id);
    if (!blog) return { message: "Blog not found", data: null, statusCode: 404 };

    await blog.destroy();
    return { message: "Blog deleted successfully", data: null, statusCode: 200 };
  } catch (error) {
    return { message: error.message, error: error.message, statusCode: 500 };
  }
}

// Get blogs for landing page (latest 3)
export async function getLandingBlogs() {
  try {
    const blogs = await Blog.findAll({
      limit: 3,
      order: [['createdAt', 'DESC']]
    });
    return { message: "Landing blogs fetched successfully", data: blogs, statusCode: 200 };
  } catch (error) {
    return { message: error.message, error: error.message, statusCode: 500 };
  }
}


