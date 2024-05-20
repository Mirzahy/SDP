<?php

require_once __DIR__ . "/BaseDao.class.php";

class UserDao extends BaseDao
{

    public function __construct()
    {
        parent::__construct("users");
    }

    public function addUser($user)
    {
        return $this->insert('users', $user);
    }

    public function count_users_paginated($search) {
        $query = "SELECT COUNT(*) AS count
                  FROM users
                  WHERE LOWER(username) LIKE CONCAT('%', :search, '%') OR 
                        LOWER(email) LIKE CONCAT('%', :search, '%')";
        return $this->query_unique($query, [
            'search' => strtolower($search)
        ]);
    }
    public function get_users(){
      
            $query = "SELECT * FROM users";
            return $this->query_without_param($query);
        
    }
    
    public function get_users_paginated($offset, $limit, $search, $order_column, $order_direction) {
        $valid_columns = ['username', 'email']; // These are the columns you can sort by
        $valid_directions = ['ASC', 'DESC'];
    
        $order_column = in_array($order_column, $valid_columns) ? $order_column : 'username';
        $order_direction = in_array($order_direction, $valid_directions) ? $order_direction : 'ASC';
    
        $query = "SELECT *
                  FROM users
                  WHERE LOWER(username) LIKE CONCAT('%', :search, '%') OR
                        LOWER(email) LIKE CONCAT('%', :search, '%')
                  ORDER BY {$order_column} {$order_direction}
                  LIMIT :offset, :limit";
        return $this->query($query, [
            'search' => strtolower($search),
            'offset' => (int)$offset,
            'limit' => (int)$limit
        ]);
    }


    
    public function delete_user($user_id) {
        $query = "DELETE FROM users WHERE idUsers = :user_id";
        $this->execute($query, [
            'user_id' => $user_id
        ]);
        return true;
    }
    

   
}