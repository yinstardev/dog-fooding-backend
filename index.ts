import http from 'http';
import express from 'express';
import passport from 'passport';
import logging from './source/config/logging';
import config from './source/config/config';
import axios from 'axios';
import './source/config/passport';
import jwt from 'jsonwebtoken';

require('dotenv').config();

const app = express();

const httpServer = http.createServer(app);
const fe_url = process.env.FE_URL || "";

app.use((req, res, next) => {
    logging.info(`METHOD: [${req.method}] - URL: [${req.url}] - IP: [${req.socket.remoteAddress}]`);

    res.on('finish', () => {
        logging.info(`METHOD: [${req.method}] - URL: [${req.url}] - STATUS: [${res.statusCode}] - IP: [${req.socket.remoteAddress}]`);
    });

    next();
});

app.use(passport.initialize());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use((req, res, next) => {
    const allowedOrigins = [`${fe_url}`];
    const origin = req.headers.origin || 'http://localhost:3000';
    
    if (allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    }

    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    if (req.method == 'OPTIONS') {
        res.header('Access-Control-Allow-Methods', 'PUT, POST, PATCH, DELETE, GET');
        return res.status(200).json({});
    }

    next();
});

app.get('/',(req,res) => {
    res.status(200).json({
        "Status":"Server Running",
        "PORT" : "1337"
    })
})


app.get('/login', passport.authenticate('saml', config.saml.options), (req, res) => {
    return res.redirect(`${fe_url}/dashboard`);
});



app.post('/login/callback', 
    passport.authenticate('saml', { session: false }), 
    (req: any, res) => {
        // Create and handle JWT token
        const jwtToken = jwt.sign(
            { username: req.user.nameID },
            jwt_secret,
            { expiresIn: '23h' }
        );

        // Send the JWT token to the client
        res.redirect(`${fe_url}/token-handler?token=${jwtToken}`);
    }
);

app.get('/whoami', (req, res, next) => {
    logging.info(req.user, "user info");
    return res.status(200).json({ user: req.user });
});

app.get('/healthcheck', (req, res, next) => {
    return res.status(200).json({ messgae: 'Server is runngggging!' });
});



app.post('/getauthtoken', async (req, res) => {
    const { username } = req.body;  // Extract username from request body

    if (!username) {
        return res.status(400).json({ error: 'Username is required' });
    }

    const postData = `secret_key=${process.env.SECRET_KEY}&username=${username}&access_level=FULL`;
    try {
        const response = await axios.post(`${process.env.BASE_URL}`, postData, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'text/plain'
            }
        });
        res.status(200).json(response.data);
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


const jwt_secret = process.env.JWT_SECRET || '';

app.get('/validate-token', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1]; 

    if (!token) {
        return res.status(401).json({ message: "No token provided" });
    }

    jwt.verify(token, jwt_secret, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: "Invalid token" });
        }

        res.json({ valid: true, user: decoded });
    });
});

app.use((req, res, next) => {
    const error = new Error('Not found');

    res.status(404).json({
        message: error.message
    });
});

httpServer.listen(config.server.port, () => logging.info(`Server is running on port ${config.server.port}`));

export default app;