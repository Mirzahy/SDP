<?php

require_once __DIR__ . "/BaseDao.class.php";

class AgentDao extends BaseDao
{
    public function __construct()
    {
        parent::__construct("agents");
    }

    public function addAgent($agent)
    {
        return $this->insert('agents', $agent);
    }

    public function count_agents_paginated($search) {
        $query = "SELECT COUNT(*) AS count
                  FROM agents
                  WHERE LOWER(name) LIKE CONCAT('%', :search, '%') OR 
                        LOWER(surname) LIKE CONCAT('%', :search, '%') OR
                        LOWER(email) LIKE CONCAT('%', :search, '%')";
        return $this->query_unique($query, [
            'search' => strtolower($search)
        ]);
    }
    
    public function get_agents_paginated($offset, $limit, $search, $order_column, $order_direction) {
        $valid_columns = ['name', 'surname', 'email'];
        $valid_directions = ['ASC', 'DESC'];
    
        $order_column = in_array($order_column, $valid_columns) ? $order_column : 'name';
        $order_direction = in_array($order_direction, $valid_directions) ? $order_direction : 'ASC';
    
        $query = "SELECT *
                  FROM agents
                  WHERE LOWER(name) LIKE CONCAT('%', :search, '%') OR
                        LOWER(surname) LIKE CONCAT('%', :search, '%') OR
                        LOWER(email) LIKE CONCAT('%', :search, '%')
                  ORDER BY {$order_column} {$order_direction}
                  LIMIT :offset, :limit";
        return $this->query($query, [
            'search' => strtolower($search),
            'offset' => (int)$offset,
            'limit' => (int)$limit
        ]);
    }

    public function delete_agent($idagents) {
        $query = "DELETE FROM agents WHERE idagents = :idagents";
        $this->execute($query, [
            'idagents' => $idagents
        ]);
    }

    public function get_agent_by_id($idagents) {
        return $this->query_unique(
            "SELECT * FROM agents WHERE idagents = :idagents", 
            ["idagents" => $idagents]);
    }

    public function edit_agent($idagents, $agent) {
        $query  = "UPDATE agents
                   SET name = :name,
                       surname = :surname,
                       email = :email
                   WHERE idagents = :idagents";
        $this->execute($query, [
            'idagents' => $idagents,
            'name' => $agent['name'],
            'surname' => $agent['surname'],
            'email' => $agent['email']
        ]);
    }

    
}
