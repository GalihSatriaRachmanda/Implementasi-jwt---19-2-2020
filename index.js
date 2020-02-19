const express = require('express');
const session = require ('express-session');
const bodyParser = require ('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require("bcryptjs");
const db = require('./mysql.js');
const app = express();
const port = 8080;

app.set('view engine','ejs');
app.use(express.static('public'));
app.use(
    session({
        secret: 'secret',
        resave: true,
        saveUninitialized: true
    })
);

app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());

app.post('/login', function(req,res){
    var email = req.body.email;
    db.query('SELECT * FROM akun WHERE email = ?',email, function(err,akun){
        if (err) throw err;
        else if (akun.length > 0 && bcrypt.compareSync(req.body.password, akun[0].password) == true){
                    jwt.sign({session}, 'secretkey', {expiresIn: '300s'}, function(err, token){
                        req.session.loggedin = true;
                        req.session.email = email;
                        db.query('UPDATE akun SET token = ? WHERE email = ? ',[token, email]);
                        res.json(token)
                    })    
                } 
        else {
            res.json({
                message: 'email atau password salah'
            });
            }
        });
    });


app.post('/register',function(req,res){
    const register_data = {
        nama: req.body.nama,
        email: req.body.email,
        password: req.body.password
    };
    db.query('SELECT* FROM akun WHERE email = ?', register_data.email, function(err, rows){
        if(err) throw err;
        else if (rows.length > 0){
            res.json({
                message: 'Alamat email anda sudah terdaftar'
            })
        }else{
            register_data.password = bcrypt.hashSync(req.body.password, 10)
            db.query('INSERT INTO akun SET ?', register_data, function(err, result){
                if(err) throw err;
                else{
                    res.json(register_data);
                }
            });
        }
    });
});

app.get('/', verifyToken, function(req, res){
    jwt.verify(req.token, 'secretkey', function(err, authData){
        if(err){
            res.sendStatus(403);
        }else{
            if(req.session.loggedin == true) {
            db.query('SELECT * FROM akun', function(err, result){
                if(err) throw err;
                else{
                    res.json(result);
                }
                })
            }
            else{
                res.sendStatus(403);
            }       
        }
    });
});

app.get('/profile', verifyToken, function(req, res){
    jwt.verify(req.token, 'secretkey', function(err, authData){
        if(err){
            res.sendStatus(403);
        }else{
            if(req.session.loggedin == true) {
            db.query('SELECT * FROM akun WHERE token = ?', req.token , function(err, result){
                if(err) throw err;
                else{
                    res.json(result);
                }
                })
            }
            else{
                res.sendStatus(403);
            }       
        }
    });
});

app.get('/logout', verifyToken, function(req,res){
    jwt.verify(req.token, 'secretkey', function(err, authData){
        if(err){
            res.sendStatus(403);
        }else{
        if(req.session.loggedin == true) {
            db.query('UPDATE akun SET token = ? WHERE token = ? ',['', req.token]);
            req.session.loggedin = false;
            res.json({
                message: 'anda telah logout'
            });
        }
        else{
            res.sendStatus(403);
        }       
}
});
});

app.delete("/delete", verifyToken, (req, res) => {
    jwt.verify(req.token, 'secretkey', function(err, authData){
        if(err){
            res.sendStatus(403);
        }else{
            if(req.session.loggedin == true) {
            db.query('DELETE FROM akun WHERE id_akun = ? AND token = ?', [req.body.id_akun, req.token], function(err, result){
                if(err) throw err;
                else if (result.affectedRows > 0){
                    res.json({
                        message: 'akun telah terhapus'
                    });
                }else{
                    res.sendStatus(403);
                }
            })
        }
        else{
            res.sendStatus(403);
        }
        }
    })
})

app.patch("/edit", verifyToken, (req, res) => {
    hash = bcrypt.hashSync(req.body.password, 10)
    jwt.verify(req.token, 'secretkey', function(err, authData){
        if(err){
            res.sendStatus(403);
        }else{
            if(req.session.loggedin == true) {
            const sql ="UPDATE akun SET nama = ? , email = ? , password = ?  WHERE id_akun = ? AND token = ? ";
            db.query(sql, [ req.body.nama, req.body.email, hash, req.body.id_akun, req.token], function(err, result){
        if(err) throw err;
        else if (result.affectedRows > 0){
            db.query('SELECT * FROM akun WHERE id_akun= ?', req.body.id_akun, function(err, result){
                if(err) throw err;
                else{
                    res.json(result);
                }
                })
        }else{
            res.sendStatus(403)
        }
        })
        }
        else{
            res.sendStatus(403);
        }
    }
    })
})

function verifyToken(req, res, next){
    const bearerHeader = req.headers['authorization'];

    if(typeof bearerHeader !== 'undefined'){
        const bearer = bearerHeader.split(' ');
        const bearerToken = bearer[1];
        req.token = bearerToken;
        next();
    }else{
        res.sendStatus(403)
    }
}

app.listen(port, function(){
    console.log('Server di ' + port);
});
