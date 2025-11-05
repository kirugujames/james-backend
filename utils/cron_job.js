import cron from 'node-cron';
import jwt from 'jsonwebtoken';
import connection from './../database.js';

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;

//run every minute
export function startSessionCleaner() {
 cron.schedule('* * * * *', async () => {
  console.log('Checking for expired sessions...');
  try {
    const [users] = await connection.query(
      'SELECT id, username, session_token FROM user WHERE is_logged_in = TRUE AND session_token IS NOT NULL'
    );

    for (const user of users) {
      try {
        jwt.verify(user.session_token, JWT_SECRET_KEY);
      } catch (err) {
        if (err.name === 'TokenExpiredError') {
          await connection.query(
            'UPDATE user SET is_logged_in = FALSE, session_token = NULL WHERE id = ?',
            [user.id]
          );
          console.log(`User ${user.username} session expired — auto logged out.`);
        }
      }
    }
  } catch (err) {
    console.error('Error checking sessions:', err.message);
  }
});
}
