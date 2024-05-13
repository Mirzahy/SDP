<?php
require_once __DIR__ . '/rest/services/PropertyService.class.php';

$property_service = new PropertyService();

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_REQUEST['id'])) {
    $property_id = $_REQUEST['id'];
    $payload = $_POST;

    try {
        $property_service->edit_property($property_id, $payload);
        echo json_encode(['success' => 'Property has been updated successfully']);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
} elseif ($_SERVER['REQUEST_METHOD'] == 'GET' && isset($_REQUEST['id'])) {
    $property_id = $_REQUEST['id'];
    $property = $property_service->get_property_by_id($property_id);
    header('Content-Type: application/json');
    echo json_encode($property);
} else {
    header('Content-Type: application/json');
    http_response_code(400);
    echo json_encode(['error' => 'Bad request']);
}
?>
