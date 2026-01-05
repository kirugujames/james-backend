import Blog from "./Models/Blog.js";
import Comment from "./Models/Comments.js";
import MemberRegistration from "../member-registration/models/memberRegistration.js";

// Comment on blog
export async function commentOnBlog(req) {
  const { blog_id, message, commenter_name, email } = req.body;
  try {
    const member = await MemberRegistration.findAll({ where: { email } })
    console.log(req.body)
    console.log(member);
    if (member.length === 0) {
      return { message: "member not found", statusCode: 404 };
    }

    const blog = await Blog.findByPk(blog_id);
    if (!blog) return { message: "Blog not found", data: null, statusCode: 404 };

    const comment = await Comment.create({ blog_id, message, commenter_name });
    return { message: "Comment added successfully", data: { id: comment.id }, statusCode: 201 };
  } catch (error) {
    return { message: error.message, error: error.message, statusCode: 500 };
  }
}

// Delete comment by ID
export async function deleteComment(id) {
  try {
    const comment = await Comment.findByPk(id);
    if (!comment) return { message: "Comment not found", data: null, statusCode: 404 };

    await comment.destroy();
    return { message: "Comment deleted successfully", data: null, statusCode: 200 };
  } catch (error) {
    return { message: error.message, error: error.message, statusCode: 500 };
  }
}

// Get comment by ID
export async function getCommentById(id) {
  try {
    const comment = await Comment.findByPk(id);
    if (!comment) return { message: "Comment not found", data: null, statusCode: 404 };
    return { message: "Comment fetched successfully", data: comment, statusCode: 200 };
  } catch (error) {
    return { message: error.message, error: error.message, statusCode: 500 };
  }
}

// Get comments by blog ID
export async function getCommentByBlogId(id) {
  try {
    const comments = await Comment.findAll({ where: { blog_id: id } });
    return { message: "Comments fetched successfully", data: comments, statusCode: 200 };
  } catch (error) {
    return { message: error.message, error: error.message, statusCode: 500 };
  }
}

// Get all comments
export async function getAllComments() {
  try {
    const comments = await Comment.findAll({ include: Blog });
    return { message: "Comments fetched successfully", data: comments, statusCode: 200 };
  } catch (error) {
    return { message: error.message, error: error.message, statusCode: 500 };
  }
}
