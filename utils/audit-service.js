import { logAction } from "../audit-trails/audit-trail-controller.js";

export const auditMiddleware = (actionName) => {
    return async (req, res, next) => {
        const originalSend = res.send;
        res.send = function (data) {
            // Only log successful operations or specific intentional logs
            if (res.statusCode >= 200 && res.statusCode < 400) {
                try {
                    const user_id = req.user ? req.user.id : (req.body && req.body.userId ? req.body.userId : null);

                    // Filter sensitive data from body
                    const sanitizedBody = { ...req.body };
                    const sensitiveFields = ['password', 'token', 'access_token', 'refreshToken', 'otp'];
                    sensitiveFields.forEach(field => {
                        if (sanitizedBody[field]) sanitizedBody[field] = '********';
                    });

                    const action = actionName || `${req.method} ${req.originalUrl}`;
                    const details = JSON.stringify({
                        method: req.method,
                        url: req.originalUrl,
                        body: sanitizedBody,
                        params: req.params,
                        query: req.query,
                        statusCode: res.statusCode
                    });

                    const ip_address = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;

                    logAction(user_id, action, details, ip_address);
                } catch (err) {
                    console.error("Audit log interceptor error:", err.message);
                }
            }
            return originalSend.apply(res, arguments);
        };
        next();
    };
};
