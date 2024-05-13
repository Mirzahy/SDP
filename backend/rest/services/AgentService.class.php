<?php

require_once __DIR__ . "/../dao/AgentDao.class.php";

class AgentService {
    private $agent_dao;

    public function __construct() {
        $this->agent_dao = new AgentDao();
    }

    public function addAgent($agent) {
        return $this->agent_dao->addAgent($agent);
    }

    public function get_agents_paginated($offset, $limit, $search, $order_column, $order_direction) {
        $count = $this->agent_dao->count_agents_paginated($search)['count'];
        $rows = $this->agent_dao->get_agents_paginated($offset, $limit, $search, $order_column, $order_direction);
        
        return [
            'count' => $count,
            'data' => $rows
        ];
    }

    public function delete_agent($idagents) {
        $this->agent_dao->delete_agent($idagents);
    }

    public function get_agent_by_id($idagents) {
        return $this->agent_dao->get_agent_by_id($idagents);
    }

    public function edit_agent($idagents, $agent) {
        $this->agent_dao->edit_agent($idagents, $agent);
    }

}

