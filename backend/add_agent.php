<?php

require_once __DIR__ . '/rest/services/AgentService.class.php';

$payload = $_REQUEST;

$agent_service = new UserService();

if($payload['id'] != NULL && $payload['id'] != ''){
    $agent = $agent_service->edit_agent($payload);
} else {
    unset($payload['id']);
    $user = $user_service->addAgent($payload);
}

echo json_encode(['message' => "Agent added!", 'data' => $user]);

