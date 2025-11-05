import express from 'express';
import dotenv from 'dotenv';
import { getBlog,createBlog, getBlogById } from './blog-apis/bog.js';
import { verifyToken } from './utils/jwtInterceptor.js';
import { createRole,authenticateUser,registerUser } from './auth/auth.js';
import { startSessionCleaner } from './utils/cron_job.js';

const app = express();

dotenv.config();

app.use(express.json());

startSessionCleaner();

//port configuration
const PORT = process.env.PORT || 3000;

//error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});


app.get('/blogs', verifyToken, async(req, res) => {
  const response =  await getBlog();
  res.status(response.statusCode).send(response);
});

app.get('/blogs/:id', verifyToken,  async(req, res) => {
  const id = req.params.id;
  const response =  await getBlogById(id);
  res.status(response.statusCode).send(response);
});

app.post('/blogs/create', verifyToken, async(req, res) => {
  const { name, email } = req.body;
  const response =  await createBlog(name, email);
  res.status(response.statusCode).send(response);
});

//create  rols endpoint
app.post("/auth/role/create", async (req, res) => {
  const { name } = req.body;
  const response = await createRole(name);
  res.status(response.statusCode).send(response);
});

//register endpoint
app.post("/auth/register", async (req, res) => {
  const { username,email,password,role_id } = req.body;
  const response = await registerUser(username,password,email,role_id);
  res.status(response.statusCode).send(response);
});

//login endpoint
app.post("/auth/login", async (req, res) => {
  const { username,password } = req.body;
  const response = await authenticateUser(username, password);
  res.status(response.statusCode).send(response);
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});