<?php

require_once __DIR__ . "/rest/services/AgentService.class.php"; 


$agent_id = $_REQUEST['id'];


if($agent_id == NULL || $agent_id == '') {
    header('HTTP/1.1 400 Bad Request'); 
    die(json_encode(['error' => "You must provide a valid agent ID!"]));
}

$agent_service = new AgentService();

$agent_service->delete_agent($agent_id);

echo json_encode(['message' => 'You have successfully deleted the agent!']);
