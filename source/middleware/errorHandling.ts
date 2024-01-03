import { Request, Response, NextFunction, ErrorRequestHandler } from 'express';

const errorHandling: ErrorRequestHandler = (err, req, res, next) => {
    res.status(500).json({ message: 'Internal Server Error' });
};

export default errorHandling;
