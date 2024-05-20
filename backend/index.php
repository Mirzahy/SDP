<?php

require 'vendor/autoload.php';
require 'rest/routes/user_routes.php';
require 'rest/routes/agent_routes.php';
require 'rest/routes/property_routes.php';



Flight::route('/', function () {
    echo 'hello world!';
  });


Flight::start();