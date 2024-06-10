<?php

require_once __DIR__ . '/../dao/AuthDao.class.php';
require 'vendor/autoload.php';
use \Firebase\JWT\JWT;

class AuthService {
    private $auth_dao;
    private $key = "your_secret_key"; // Replace with your actual secret key

    public function __construct() {
        $this->auth_dao = new AuthDao();
    }

    public function get_user_by_email($email){
        return $this->auth_dao->get_user_by_email($email);
    }

    public function authenticate($email, $password) {
        $user = $this->get_user_by_email($email);

        if(!$user || !password_verify($password, $user['password'])) {
            return null;
        }

        unset($user['password']); // Remove password from user data
        
        $jwt_payload = [
            'user' => $user,
            'iat' => time(),
            'exp' => time() + (60 * 60 * 24) // Token valid for 1 day
        ];

        $token = JWT::encode($jwt_payload, $this->key, 'HS256');
        return ['user' => $user, 'token' => $token];
    }
}
?>
