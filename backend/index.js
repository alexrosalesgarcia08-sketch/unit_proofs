//JS
//common JS -> antigua, mas compatible
// ES MODULE ->Lads mas reeciente "Import from"

const express=require('express');
const mongoose= require('mongoose');
const bodyparser=require('body-parser');
const cookieParser=require('cookie-parser');
const User=require('./models/user');
const db=require('./config/config').get(process.env.NODE_ENV);
const { auth } = require('./middleware/auth');


const app=express();
// app use
app.use(bodyparser.urlencoded({extended : false}));
app.use(bodyparser.json());
app.use(cookieParser());

// database connection
mongoose.Promise=global.Promise;
mongoose.connect(db.DATABASE,{ useNewUrlParser: true,useUnifiedTopology:true },function(err){
    if(err) console.log(err);
    console.log("database is connected");
});


// adding new user (sign-up route)
app.post('/api/register', async function (req, res) {
    if (req.body.password != req.body.password2) return res.status(400).json({ message: "password not match" });
    try {
        const newuser = new User(req.body);
        const user = await User.findOne({ email: newuser.email });
        if (user) return res.status(400).json({ auth: false, message: "email exits" });

        const doc = await newuser.save();
        return res.status(200).json({
            success: true,
            user: doc
        });
    } catch (error) {
        console.log(error);
        return res.status(400).json({ success: false });
    }
});


// login user
app.post('/api/login', async function (req, res) {
    //solo se LET cuando se redeclara un valor
    const token = req.cookies.auth;
    //Para evitar el uso de callbacks usamos funciones asincronas
    //Manejamos el error try/catch
    //Manejamos en donde exista y ya esta logeado con IF
    try {
        // findByToken lanza error si no hay token o es invalido/expirado -> lo tratamos como "no logeado"
        let logged = null;
        if (token) {
            try {
                logged = await User.findByToken(token);
            } catch (e) {
                logged = null;
            }
        }
        if (logged) return res.status(400).json({
            error: true,
            message: "You are already logged in"
        });

        const user = await User.findOne({ 'email': req.body.email });
        if (!user) return res.status(400).json({ isAuth: false, message: 'Auth failed' });

        const isMatch = await user.comparePassword(req.body.password);
        if (!isMatch) return res.status(400).json({ isAuth: false, message: 'Auth failed' });

        await user.generateToken();
        return res.status(200).cookie('auth', user.token, { httpOnly: true }).json({
            isAuth: true,
            id: user._id,
            email: user.email
        });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: error.message });
    }
});

//logout user
app.get('/api/logout', auth, async function (req, res) {
    try {
        await req.user.deleteToken();
        res.clearCookie('auth');
        return res.sendStatus(200);
    } catch (error) {
        console.log(error);
        return res.status(400).send(error);
    }
});

// get logged in user
app.get('/api/profile', auth, function (req, res) {
    res.json({
        isAuth: true,
        id: req.user._id,
        email: req.user.email,
        name: [req.user.firstname, req.user.lastname].filter(Boolean).join(' ')
    });
});


app.get('/',function(req,res){
    res.status(200).send(`Welcome to login , sign-up api`);
});

// listening port
const PORT=process.env.PORT||3000;
app.listen(PORT,()=>{
    console.log(`app is live at ${PORT}`);
});