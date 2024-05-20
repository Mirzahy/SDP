<?php

require_once __DIR__ . "/../dao/UserDao.class.php";

class UserService
{
    private $user_dao;

    public function __construct()
    {
        $this->user_dao = new UserDao();
    }

    public function addUser($user)
    {
        return $this->user_dao->addUser($user);
    }


    public function get_users_paginated($offset, $limit, $search, $order_column, $order_direction)
    {
        $count = $this->user_dao->count_users_paginated($search)['count'];
        $rows= $this->user_dao->get_users_paginated($offset, $limit, $search, $order_column, $order_direction);

        return ['count' => $count, 'data' => $rows];
    }


    public function delete_user($user_id) {
        $result = $this->user_dao->delete_user($user_id);
        if ($result > 0) {
            return ['success' => true, 'message' => 'User successfully deleted'];
        } else {
            return ['success' => false, 'message' => 'No user found with that ID, or deletion failed'];
        }
    }

    public function get_user_by_id($user_id)
    {
        return $this->user_dao->get_user_by_id($user_id);
    }

    public function get_users(){
        return $this->user_dao->get_users();
    }


}