import connection from '../database.js';

export async function getBlog() {
 const  resutl = await connection.query('SELECT *  FROM blog');
 const response = {
    "message": "Blogs fetched successfully",
    "data": resutl[0],
    "statusCode": 200
 }
 return response
}

export async function createBlog(name, email) {
 const  resutl = await connection.query('INSERT INTO blog (name, email) VALUES (?, ?)', [name, email]);
 const response = {
    "message": "Blog created successfully",
    "data": { id: resutl[0].insertId},
    "statusCode": 201
 }

 return response
}

export async function getBlogById(id) {
 const  resutl = await connection.query('SELECT *  FROM blog WHERE id = ?', [id]);  
 const response = {
    "message": "Blog fetched successfully",
    "data": resutl[0],
    "statusCode": 200
 }
 return response
}
