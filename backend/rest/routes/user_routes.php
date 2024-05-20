<?php

use OpenApi\Annotations as OA;
require_once __DIR__ . '/../services/UserService.class.php';

Flight::set('user_service', new UserService());

Flight::group('/users', function() {

    /**
     * @OA\Get(
     *      path="/users",
     *      tags={"users"},
     *      summary="Get all users",
     *      @OA\Response(
     *           response=200,
     *           description="Array of all users in the database"
     *      )
     * )
     */
    Flight::route('GET /', function() {
        $user_service = Flight::get('user_service');
        $data = $user_service->get_users();
        Flight::json(['data' => $data]);
    });

    /**
     * @OA\Post(
     *     path="/users",
     *     summary="Add a new user",
     *     tags={"users"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(ref="#/components/schemas/User")
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="User added",
     *         @OA\JsonContent(ref="#/components/schemas/User")
     *     )
     * )
     */
    Flight::route('POST /', function() {
        $user_service = Flight::get('user_service');
        $payload = Flight::request()->data->getData();
        $user = $user_service->addUser($payload);
        Flight::json(['message' => "User added!", 'data' => $user], 201);
    });

    /**
     * @OA\Delete(
     *     path="/users/{id}",
     *     summary="Delete a user",
     *     tags={"users"},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User deleted",
     *         @OA\JsonContent(type="object", @OA\Property(property="message", type="string"))
     *     )
     * )
     */
    Flight::route('DELETE /@id', function($id) {
        $user_service = Flight::get('user_service');

        if (empty($id)) {
            Flight::json(['error' => "You must provide a valid user ID!"], 400);
            return;
        }

        $result = $user_service->delete_user($id);

        if ($result['success']) {
            Flight::json(['message' => 'You have successfully deleted the user!']);
        } else {
            Flight::json(['error' => 'No user found with that ID.'], 404);
        }
    });

    /**
     * @OA\Post(
     *     path="/users/{id}",
     *     summary="Update a user",
     *     tags={"users"},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(ref="#/components/schemas/User")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User updated",
     *         @OA\JsonContent(type="object", @OA\Property(property="success", type="string"))
     *     )
     * )
     */
    // Flight::route('POST /@id', function($id) {
    //     $user_service = Flight::get('user_service');
    //     $payload = Flight::request()->data->getData();

    //     if (!empty($id)) {
    //         try {
    //             $user_service->edit_user($id, $payload);
    //             Flight::json(['success' => 'User has been updated successfully']);
    //         } catch (Exception $e) {
    //             Flight::json(['error' => $e->getMessage()], 500);
    //         }
    //     } else {
    //         Flight::json(['error' => 'Bad request'], 400);
    //     }
    // });

    /**
     * @OA\Get(
     *     path="/users/{id}",
     *     summary="Get a user by ID",
     *     tags={"users"},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User details",
     *         @OA\JsonContent(ref="#/components/schemas/User")
     *     )
     * )
     */
    Flight::route('GET /@id', function($id) {
        $user_service = Flight::get('user_service');

        if (!empty($id)) {
            $user = $user_service->get_user_by_id($id);
            Flight::json($user);
        } else {
            Flight::json(['error' => 'Bad request'], 400);
        }
    });
});

/**
 * @OA\Schema(
 *     schema="User",
 *     type="object",
 *     required={"username", "email", "password"},
 *     @OA\Property(property="idUsers", type="integer", readOnly=true),
 *     @OA\Property(property="username", type="string"),
 *     @OA\Property(property="email", type="string"),
 *     @OA\Property(property="password", type="string")
 * )
 */

// Start Flight
