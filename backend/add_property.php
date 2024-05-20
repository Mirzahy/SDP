<?php

require_once __DIR__ . "/rest/services/PropertyService.class.php"; 

$payload = $_REQUEST;

$property_service = new PropertyService();

$property = $property_service->addProperty($payload);
