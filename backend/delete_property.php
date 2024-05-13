<?php

require_once __DIR__ . "/rest/services/PropertyService.class.php"; 

$property_id = $_REQUEST['id']; 


if($property_id == NULL || $property_id == '') {
    header('HTTP/1.1 400 Bad Request'); 
    die(json_encode(['error' => "You must provide a valid property ID!"]));
}


$property_service = new PropertyService();
$property_service->delete_property($property_id); 


echo json_encode(['message' => 'You have successfully deleted the property!']);
