<?php

require_once __DIR__ . "/rest/services/AgentService.class.php"; 

$params = [
    "start" => (int)($_REQUEST['start'] ?? 0),
    "search" => $_REQUEST['search']['value'] ?? '',
    "draw" => (int)($_REQUEST['draw'] ?? 1),
    "limit" => (int)($_REQUEST['length'] ?? 10),
    "order_column" => $_REQUEST['order'][0]['name'] ?? 'name',
    "order_direction" => $_REQUEST['order'][0]['dir'] ?? 'ASC',
];

$agent_service = new AgentService();

$data = $agent_service->get_agents_paginated($params['start'], $params['limit'], $params['search'], $params['order_column'], $params['order_direction']);

foreach($data['data'] as $id => $agent){
    $data['data'][$id]['action'] = 
    '<button class="btn btn-primary" onclick="AgentService.open_edit_agent_modal('.$agent['idagents'].')">Edit</button>
    <button class="btn btn-danger" onclick="AgentService.delete_agent('.$agent['idagents'].')">Delete</button>';
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
