<?php

require_once __DIR__ . '/rest/services/UserService.class.php';

$payload = $_REQUEST;

$user_service = new UserService();

if($payload['id'] != NULL && $payload['id'] != ''){
    $user = $user_service->edit_user($payload);
} else {
    unset($payload['id']);
    $user = $user_service->addUser($payload);
}

echo json_encode(['message' => "User successfuly registered!", 'data' => $user]);

