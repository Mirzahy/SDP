<?php

require_once __DIR__ . "/rest/services/PropertyService.class.php"; // Correct the path

$payload = $_REQUEST;

$params = [
    "start" => (int)$payload['start'],
    "search" => $payload['search']['value'],
    "draw" => $payload['draw'],
    "limit" => (int)$payload['length'],
    "order_column" => $payload['order'][0]['name'],
    "order_direction" => $payload['order'][0]['dir'],
];

$property_service = new PropertyService();

$data = $property_service->get_properties_paginated($params['start'], $params['limit'], $params['search'], $params['order_column'], $params['order_direction']);

foreach($data['data'] as $id => $property){
    $data['data'][$id]['action'] = 
    '<button class="btn btn-primary" onclick="PropertyService.open_edit_property_modal('.$property['idproperties'].')">Edit</button>
    <button class="btn btn-danger" onclick="PropertyService.delete_property('.$property['idproperties'].')">Delete</button>';
}

// Response
echo json_encode([
    'draw' => $params['draw'],
    'data' => $data['data'],
    'recordsFiltered' => $data['count'],
    'recordsTotal' => $data['count'],
    'end' => $data['count']
]);
?>
