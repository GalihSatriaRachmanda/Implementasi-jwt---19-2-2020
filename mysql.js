const mysql = require('mysql');

db = mysql.createConnection({
    host : 'localhost',
    user: 'root',
    password: '',
    database: 'node',
    multipleStatements: true
});

db.connect(function(err){
    if (err) throw err;
    else{
        console.log('Database terkoneksi');
    }
});

module.exports = db;