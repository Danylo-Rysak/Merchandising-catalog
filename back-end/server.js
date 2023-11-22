import express from 'express';
import fs from 'fs';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';

const saltRounds = 10;

const app = express();
app.use(express.json());
app.use(cors({
    origin: ["http://localhost:5173"],
    methods: ["POST", "GET"],
    credentials: true,
}));
app.use(cookieParser());

const usersFilePath = './data/users.json';
let users = [];
try {
    const data = fs.readFileSync(usersFilePath, 'utf8');
    users = JSON.parse(data);
} catch (error) {
    console.error('Error reading users file:', error);
}

const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are not authenticated" })
    } else {
        jwt.verify(token, "jwt-secret-token", (err, decoded) => {
            if (err) {
                return res.json({Error: err.message})
            } else {
                req.email = decoded.email;
                next();
            }
        })
    }
}

app.get('/', verifyUser, (req, res) => {
    return res.json({Status: "Success", email: req.email});
})

app.post('/registration', (req, res) => {
    bcrypt.hash(req.body.password.toString(), saltRounds, (err, hash) => {
        if (err) return res.json({ Error: err.message });

        const newUser = {
            email: req.body.email,
            password: hash,
        };

        users.push(newUser);

        fs.writeFile(usersFilePath, JSON.stringify(users, null, 2), (err) => {
            if (err) return res.json({ Error: err.message });

            return res.json({ Status: 'Success', newUser });
        });
    });
});

app.post('/login', (req, res) => {
    const user = users.find((u) => u.email === req.body.email);

    if (!user) {
        return res.json({ Error: 'No email existed' });
    }

    bcrypt.compare(req.body.password.toString(), user.password, (err, response) => {
        if (err) return res.json({ Error: err.message });

        if (response) {
            const email = res[0]?.email;
            const token = jwt.sign({email}, "jwt-secret-key", {expiresIn: '1d'})
            res.cookie('token', token);
            return res.json({ Status: 'Success' });
        } else {
            return res.json({ Error: 'Password not matched' });
        }
    });
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({Status: "Success"});
})

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({Status: "Success"});
})

let products = [];
try {
    const data = fs.readFileSync('./data/products.json', 'utf8');
    products = JSON.parse(data);
} catch (error) {
    console.error('Error reading products file:', error);
}

app.get('/products', (req, res) => {
    res.json(products);
});

app.get('/products/:id', (req, res) => {
    const productId = parseInt(req.params.id);
    const product = products.find((p) => p.id === productId);

    if (!product) {
        return res.status(404).json({ Error: 'Product not found' });
    }

    res.json(product);
});

app.listen(8080, () => {
    console.log('Running ...');
});
