<?php

require_once __DIR__ . '/../services/AuthService.class.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

Flight::set('auth_service', new AuthService());

/**
 * @OA\Post(
 *     path="/auth/login",
 *     summary="User login",
 *     tags={"auth"},
 *     @OA\RequestBody(
 *         required=true,
 *         @OA\JsonContent(
 *             @OA\Property(property="email", type="string", example="user@example.com"),
 *             @OA\Property(property="password", type="string", example="password123")
 *         )
 *     ),
 *     @OA\Response(
 *         response=200,
 *         description="Successful login",
 *         @OA\JsonContent(
 *             @OA\Property(property="id", type="integer"),
 *             @OA\Property(property="email", type="string"),
 *             @OA\Property(property="name", type="string"),
 *             @OA\Property(property="token", type="string", description="JWT token")
 *         )
 *     ),
 *     @OA\Response(
 *         response=403,
 *         description="Invalid username or password",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="Invalid username or password")
 *         )
 *     )
 * )
 */
Flight::group('/auth', function() {
    Flight::route('POST /login', function(){
        $request = Flight::request();
        $data = $request->data->getData();
        $email = $data['email'];

        $auth_service = Flight::get('auth_service');
    
        $user = $auth_service->get_user_by_email($email);
    
        if(!$user || !password_verify($data['password'], $user['password'])){
            Flight::halt(403, "Invalid username or password");
        }
    
        unset($user['password']);
    
        $jwt_payload = [
            'user' => $user,
            'iat' => time(),
            'exp' => time() + (60*60*24) // valid for one day
        ];
    
        $token = JWT::encode(
            $jwt_payload,
            JWT_SECRET,
            'HS256'
        );
    
        Flight::json(array_merge($user, ['token' => $token]));
    });

    /**
     * @OA\Post(
     *     path="/auth/logout",
     *     summary="User logout",
     *     tags={"auth"},
     *     @OA\Response(
     *         response=200,
     *         description="Successful logout",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Logout successful")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Missing or invalid authentication header",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Missing authentication header")
     *         )
     *     )
     * )
     */
    Flight::route('POST /logout', function() {
        try {
            $token = Flight::request()->getHeader("Authorization");
            if(!$token) {
                Flight::halt(401, "Missing authentication header");
            }

            $decoded_token = JWT::decode($token, new Key(JWT_SECRET, 'HS256'));

            Flight::json([
                'jwt_decoded' => $decoded_token,
                'user' => $decoded_token->user
            ]);
        } catch (\Exception $e) {
            Flight::halt(401, $e->getMessage());
        }
    });
});
