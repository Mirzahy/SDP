<?php

require_once __DIR__ . "/rest/services/PropertyService.class.php"; // Ensure the path is correct.

$property_service = new PropertyService();

$categories = $property_service->get_categories(); // This method must exist in your PropertyService class

header('Content-Type: application/json');

echo json_encode($categories);
?>
