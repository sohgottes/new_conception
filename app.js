const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const bcrypt = require('bcrypt');
const flash = require('connect-flash');
const path = require('path');
const multer = require('multer');
const User = require('./models/User');
const Image = require('./models/Image');

const app = express();

// Conectando ao MongoDB
mongoose.connect('mongodb://localhost:3000/myTshirtShop', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB conectado...'))
    .catch(err => console.log(err));

// Configuração do EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware para formulários
app.use(express.urlencoded({ extended: false }));

// Configuração do Express-Session
app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Flash middleware
app.use(flash());

// Configuração do caminho dos arquivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Passport Config
passport.use(new LocalStrategy(async (username, password, done) => {
    try {
        const user = await User.findOne({ username });
        if (!user) {
            return done(null, false, { message: 'Usuário não encontrado' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return done(null, false, { message: 'Senha incorreta' });
        }

        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});

// Middleware para exibir mensagens flash
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error');
    next();
});

// Rotas
app.get('/', (req, res) => res.render('index'));

app.get('/register', (req, res) => res.render('register'));

app.post('/register', async (req, res) => {
    const { fullName, cpf, email, address, password, password2 } = req.body;
    let errors = [];

    if (password !== password2) {
        errors.push({ msg: 'Senhas não coincidem' });
    }

    if (errors.length > 0) {
        res.render('register', {
            errors,
            fullName,
            cpf,
            email,
            address,
            password,
            password2
        });
    } else {
        const newUser = new User({ fullName, cpf, email, address, password });

        try {
            await newUser.save();
            req.flash('success_msg', 'Você está registrado e pode logar');
            res.redirect('/login');
        } catch (err) {
            console.log(err);
            res.render('register', { errors: [{ msg: 'Erro ao registrar o usuário' }], fullName, cpf, email, address, password, password2 });
        }
    }
});

app.get('/login', (req, res) => res.render('login'));

app.post('/login', passport.authenticate('local', {
    successRedirect: '/account',
    failureRedirect: '/login',
    failureFlash: true
}));

app.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'Você saiu');
    res.redirect('/login');
});

app.get('/account', (req, res) => {
    if (!req.isAuthenticated()) {
        req.flash('error_msg', 'Por favor faça login para acessar essa página');
        res.redirect('/login');
    } else {
        res.render('account', { user: req.user });
    }
});

app.get('/create', (req, res) => {
    if (!req.isAuthenticated()) {
        req.flash('error_msg', 'Por favor faça login para acessar essa página');
        res.redirect('/login');
    } else {
        res.render('create');
    }
});

// Configuração do multer para upload de imagens
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage });

app.post('/upload', upload.single('image'), async (req, res) => {
    if (!req.isAuthenticated()) {
        req.flash('error_msg', 'Por favor faça login para acessar essa página');
        res.redirect('/login');
    } else {
        const newImage = new Image({
            filename: req.file.filename,
            uploadedBy: req.user._id
        });

        try {
            await newImage.save();
            req.flash('success_msg', 'Imagem enviada para aprovação');
            res.redirect('/create');
        } catch (err) {
            console.log(err);
            req.flash('error_msg', 'Erro ao enviar a imagem');
            res.redirect('/create');
        }
    }
});

app.get('/cart', (req, res) => {
    if (!req.isAuthenticated()) {
        req.flash('error_msg', 'Por favor faça login para acessar essa página');
        res.redirect('/login');
    } else {
        res.render('cart', { cart: req.session.cart || [] });
    }
});

app.post('/checkout', (req, res) => {
    const { paymentMethod } = req.body;

    // Lógica para processar o pagamento

    req.session.cart = [];
    req.flash('success_msg', 'Compra realizada com sucesso');
    res.redirect('/cart');
});

app.get('/contact', (req, res) => res.render('contact'));

app.post('/contact', (req, res) => {
    const { name, email, message } = req.body;

    // Lógica para processar a mensagem de contato

    req.flash('success_msg', 'Mensagem enviada com sucesso');
    res.redirect('/contact');
});

app.get('/admin', async (req, res) => {
    if (!req.isAuthenticated() || req.user.email !== 'admin@example.com') {
        req.flash('error_msg', 'Acesso negado');
        res.redirect('/login');
    } else {
        const images = await Image.find({ status: 'pending' });
        res.render('admin', { images });
    }
});

app.post('/admin/approve/:id', async (req, res) => {
    if (!req.isAuthenticated() || req.user.email !== 'admin@example.com') {
        req.flash('error_msg', 'Acesso negado');
        res.redirect('/login');
    } else {
        try {
            await Image.findByIdAndUpdate(req.params.id, { status: 'approved' });
            req.flash('success_msg', 'Imagem aprovada');
            res.redirect('/admin');
        } catch (err) {
            console.log(err);
            req.flash('error_msg', 'Erro ao aprovar a imagem');
            res.redirect('/admin');
        }
    }
});

app.post('/admin/reject/:id', async (req, res) => {
    if (!req.isAuthenticated() || req.user.email !== 'admin@example.com') {
        req.flash('error_msg', 'Acesso negado');
        res.redirect('/login');
    } else {
        try {
            await Image.findByIdAndUpdate(req.params.id, { status: 'rejected' });
            req.flash('success_msg', 'Imagem rejeitada');
            res.redirect('/admin');
        } catch (err) {
            console.log(err);
            req.flash('error_msg', 'Erro ao rejeitar a imagem');
            res.redirect('/admin');
        }
    }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, console.log(`Servidor rodando na porta ${PORT}`));
