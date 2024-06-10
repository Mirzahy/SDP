<?php

use OpenApi\Annotations as OA;
require_once __DIR__ . '/../services/AgentService.class.php';

Flight::set('agent_service', new AgentService());

Flight::group('/agents', function() {

    /**
     * @OA\Get(
     *      path="/agents",
     *      tags={"agents"},
     *      summary="Get all agents",
     *      @OA\Response(
     *           response=200,
     *           description="Array of all agents in the database"
     *      )
     * )
     */
    Flight::route('GET /', function() {
        $agent_service = Flight::get('agent_service');
        $data = $agent_service->get_agents();
        Flight::json(['data' => $data]);
    });

    /**
     * @OA\Post(
     *     path="/agents",
     *     summary="Add a new agent",
     *     tags={"agents"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(ref="#/components/schemas/Agent")
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Agent added",
     *         @OA\JsonContent(ref="#/components/schemas/Agent")
     *     )
     * )
     */
    Flight::route('POST /', function() {
        $agent_service = Flight::get('agent_service');
        $payload = Flight::request()->data->getData();
        $agent = $agent_service->addAgent($payload);
        Flight::json(['message' => "Agent added!", 'data' => $agent], 201);
    });

    /**
     * @OA\Delete(
     *     path="/agents/{id}",
     *     summary="Delete an agent",
     *     tags={"agents"},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Agent deleted",
     *         @OA\JsonContent(type="object", @OA\Property(property="message", type="string"))
     *     )
     */
    Flight::route('DELETE /@id', function($id) {
        $agent_service = Flight::get('agent_service');

        if (empty($id)) {
            Flight::json(['error' => "You must provide a valid agent ID!"], 400);
            return;
        }

        $agent_service->delete_agent($id);
        Flight::json(['message' => 'Agent deleted successfully!']);
    });

    /**
     * @OA\Post(
     *     path="/agents/{id}",
     *     summary="Update an agent",
     *     tags={"agents"},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(ref="#/components/schemas/Agent")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Agent updated",
     *         @OA\JsonContent(type="object", @OA\Property(property="success", type="string"))
     *     )
     */
    Flight::route('POST /@id', function($id) {
        $agent_service = Flight::get('agent_service');
        $payload = Flight::request()->data->getData();

        if (!empty($id)) {
            try {
                $agent_service->edit_agent($id, $payload);
                Flight::json(['success' => 'Agent has been updated successfully']);
            } catch (Exception $e) {
                Flight::json(['error' => $e->getMessage()], 500);
            }
        } else {
            Flight::json(['error' => 'Bad request'], 400);
        }
    });

    /**
     * @OA\Get(
     *     path="/agents/{id}",
     *     summary="Get an agent by ID",
     *     tags={"agents"},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Agent details",
     *         @OA\JsonContent(ref="#/components/schemas/Agent")
     *     )
     * )
     */
    Flight::route('GET /@id', function($id) {
        $agent_service = Flight::get('agent_service');

        if (!empty($id)) {
            $agent = $agent_service->get_agent_by_id($id);
            Flight::json($agent);
        } else {
            Flight::json(['error' => 'Bad request'], 400);
        }
    });
});

/**
 * @OA\Schema(
 *     schema="Agent",
 *     type="object",
 *     required={"name", "surname", "email"},
 *     @OA\Property(property="idagents", type="integer", readOnly=true),
 *     @OA\Property(property="name", type="string"),
 *     @OA\Property(property="surname", type="string"),
 *     @OA\Property(property="email", type="string")
 * )
 */
