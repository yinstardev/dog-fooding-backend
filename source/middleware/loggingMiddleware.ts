import { Request, Response, NextFunction } from 'express';
import logging from '../config/logging';

const loggingMiddleware = (req: Request, res: Response, next: NextFunction) => {
    logging.info(`METHOD: [${req.method}] - URL: [${req.url}] - IP: [${req.socket.remoteAddress}]`);

    res.on('finish', () => {
        logging.info(`METHOD: [${req.method}] - URL: [${req.url}] - STATUS: [${res.statusCode}] - IP: [${req.socket.remoteAddress}]`);
    });

    next();
};

export default loggingMiddleware;
