TrustKitServer
==============


Why do you need a server?
-------------------------

If you plan to enable the reporting functionality of TrustKit, then you would need to setup a server that can receive the reports.  As the reports are sent via HTTPs in the form of a POST request with JSON data, you'll need to setup a server that can receive such requests and be able to parse the JSON data and preferably store them in a database for analysis later.  The subject of a server setup and database setup is actually beyond the scope of TrustKit.  However, we do present here a very simple sample web server setup based on express to help speed up the construction of a server for testing purposes.  It basically just print out whatever JSON data it receives from the POST request.  Real web server setup would need more planning and more detail configuration (so don’t use the following).  

Steps to create a server
------------------------

Assuming that you've already installed Express, do the following (if you don't have express, please go to http://expressjs.com and follow their instructions on how to get started and install express and express-generator)

    $ express myserver
    $ cd myserver
    $ npm install
    $ npm i multer (if you get error about cannot find module 'multer')
    copy the myapp.js from this git repository to your current dir
    $ node myapp.js (that will start your server running on port 3000 of your localhost)


On the client side (open a new terminal), you can also use the following curl command to see if you can connect to your server properly before trying out a client app running TrustKit:

    $ curl -H "Content-Type: application/json" -X POST -d '{"username":"xyz","password":"abc"}' http://localhost:3000

On your server terminal, you should see the following after the client is connected to it successfully:

    $ node myapp.js
    Example app listening at http://:::3000
    { username: 'xyz', password: 'abc' }

Note that this server is setup to receive http requests rather than https.  So, in production system, you'd probably need to change the myapp.js to respond to https requests or use proxies to proxy requests to your nodejs app after they've terminated the SSL endpoint.  
