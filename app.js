const crypto = require('crypto');
const express = require('express');
const bodyParser = require('body-parser');
const uuid = require('uuid');
const mysql = require('mysql');
const app = express();

app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({extended: true}));

//connect mysql
const con = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'users'
});

//password
const RandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
    .toString('hex') //convert to hexa
    .slice(0, length); //return number
};

const sha512 = function(password,salt){
    const hash = crypto.createHmac('sha512',salt); //using sha512
    hash.update(password);
    const value=hash.digest('hex');
    return {
        salt:salt,
        passwordHash:value
    };
};

function saltHashPassword(userPassword){
    const salt = RandomString(16); //generate 16 random string
    const passwordData = sha512(userPassword, salt);
    return passwordData;
}

function checkHashPassword(userPassword,salt){
    const passwordData = sha512(userPassword,salt);
    return passwordData;
}

app.post('/register/',(req,res,next)=>{
    const post_data = req.body;

    const uid = uuid.v4();
    const plain_password = post_data.password;
    const hash_data = saltHashPassword(plain_password);
    const password = hash_data.passwordHash;
    const salt = hash_data.salt;

    const name = post_data.name;
    const email = post_data.email;

    con.query('SELECT * FROM user where email=?', [email], function(err,result,fields){
        con.on('error', function(err){
            console.log('[MySQL ERROR]', err);
        });
        if(result && result.length){
            res.json('User Already Exist!');
        }else{
            con.query('INSERT INTO `user`(`unique_id`, `name`, `email`, `password`, `salt`, `created_at`, `updated_at`) VALUES (?,?,?,?,?,NOW(),NOW())',[uid,name,email,password,salt],function(err,result,fields){
                con.on('error', function(err){
                    console.log('[MySQL ERROR]', err);
                    res.json('Register error: ', err);
                });
                return res.status(200).json({
                    error: false,
                    message: 'User Created'
                });
            })
        }
    });
});

app.post('/login/', (req,res,next)=>{
    const post_data = req.body;

    const user_password = post_data.password;
    const email = post_data.email;

    con.query('SELECT * FROM user where email=?', [email], function(err,result,fields){
        con.on('error', function(err){
            console.log('[MySQL ERROR]', err);
        });
        if(result && result.length){
            const id = result[0].unique_id;
            const name = result[0].name;
            const salt = result[0].salt;
            const password = result[0].password;
            const hash_password = checkHashPassword(user_password,salt).passwordHash;
            if (password == hash_password){
                return res.status(200).json({
                    error: false,
                    message: 'success',
                    loginResult: {
                        userId: `${id}`,
                        name: `${name}`,
                    }
                });
            }else{
                res.end(JSON.stringify('Wrong Password!'));
            }
        }else{
            res.json('User Does Not Exist!');
        }
    });
})

/*
app.get("/",(req,res,next)=>{
    console.log('password :12334');
    const encrypt = saltHashPassword('valdy');
    console.log('encrypt: ' +encrypt.passwordHash);
    console.log('salt: ' +encrypt.salt);
});

*/

const PORT = process.env.PORT || 8000
app.listen(PORT, () => {
    console.log("Server is up and listening on " + PORT)
})

