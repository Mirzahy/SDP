<?php

require_once __DIR__ . "/rest/services/UserService.class.php"; 






$user_service = new UserService();

$data = $user_service->get_users();







// Response
echo json_encode([
    'data' => $data,
]);
