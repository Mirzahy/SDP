<?php
require_once __DIR__ . '/rest/services/UserService.class.php';

$user_service = new UserService();

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_REQUEST['id'])) {
    $user_id = $_REQUEST['id'];
    $payload = $_POST; 

    try {
        $user_service->edit_user($user_id, $payload);
        echo json_encode(['success' => 'User has been updated successfully']);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
} elseif ($_SERVER['REQUEST_METHOD'] == 'GET' && isset($_REQUEST['id'])) {
    $user_id = $_REQUEST['id'];
    $user = $user_service->get_user_by_id($user_id);
    header('Content-Type: application/json');
    echo json_encode($user);
} else {
    header('Content-Type: application/json');
    http_response_code(400);
    echo json_encode(['error' => 'Bad request']);
}
?>
