var page = require('webpage').create();
page.open('http://localhost:8000/echo_server/', function() {
    setTimeout(function() {
        page.render('echo_server.png');
        phantom.exit();
    }, 2000);
});
