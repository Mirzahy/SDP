<?php

use OpenApi\Annotations as OA;
require_once __DIR__ . '/../services/PropertyService.class.php';

Flight::set('property_service', new PropertyService());

Flight::group('/properties', function() {

    /**
     * @OA\Get(
     *      path="/properties",
     *      tags={"properties"},
     *      summary="Get all properties",
     *      @OA\Response(
     *           response=200,
     *           description="Array of all properties in the database"
     *      )
     * )
     */
    Flight::route('GET /', function() {
        $property_service = Flight::get('property_service');
        $data = $property_service->get_properties();

        foreach ($data as $id => $property) {
            $data[$id]['action'] = 
            '<button class="btn btn-primary" onclick="PropertyService.open_edit_property_modal(' . $property['idproperties'] . ')">Edit</button>
            <button class="btn btn-danger" onclick="PropertyService.delete_property(' . $property['idproperties'] . ')">Delete</button>';
        }

        Flight::json(['data' => $data]);
    });

    /**
     * @OA\Post(
     *     path="/properties",
     *     summary="Add a new property",
     *     tags={"properties"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(ref="#/components/schemas/Property")
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Property added",
     *         @OA\JsonContent(ref="#/components/schemas/Property")
     *     )
     * )
     */
    Flight::route('POST /', function() {
        $property_service = Flight::get('property_service');
        $payload = Flight::request()->data->getData();
        $property = $property_service->addProperty($payload);
        Flight::json(['message' => "Property added!", 'data' => $property], 201);
    });

    /**
     * @OA\Delete(
     *     path="/properties/{id}",
     *     summary="Delete a property",
     *     tags={"properties"},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Property deleted",
     *         @OA\JsonContent(type="object", @OA\Property(property="message", type="string"))
     *     )
     * )
     */
    Flight::route('DELETE /@id', function($id) {
        $property_service = Flight::get('property_service');

        if (empty($id)) {
            Flight::json(['error' => "You must provide a valid property ID!"], 400);
            return;
        }

        $result = $property_service->delete_property($id);

        if ($result['success']) {
            Flight::json(['message' => 'You have successfully deleted the property!']);
        } else {
            Flight::json(['error' => 'No property found with that ID.'], 404);
        }
    });

    /**
     * @OA\Post(
     *     path="/properties/{id}",
     *     summary="Update a property",
     *     tags={"properties"},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(ref="#/components/schemas/Property")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Property updated",
     *         @OA\JsonContent(type="object", @OA\Property(property="success", type="string"))
     *     )
     * )
     */
    Flight::route('POST /@id', function($id) {
        $property_service = Flight::get('property_service');
        $payload = Flight::request()->data->getData();

        if (!empty($id)) {
            try {
                $property_service->edit_property($id, $payload);
                Flight::json(['success' => 'Property has been updated successfully']);
            } catch (Exception $e) {
                Flight::json(['error' => $e->getMessage()], 500);
            }
        } else {
            Flight::json(['error' => 'Bad request'], 400);
        }
    });

    /**
     * @OA\Get(
     *     path="/properties/{id}",
     *     summary="Get a property by ID",
     *     tags={"properties"},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Property details",
     *         @OA\JsonContent(ref="#/components/schemas/Property")
     *     )
     * )
     */
    Flight::route('GET /@id', function($id) {
        $property_service = Flight::get('property_service');

        if (!empty($id)) {
            $property = $property_service->get_property_by_id($id);
            Flight::json($property);
        } else {
            Flight::json(['error' => 'Bad request'], 400);
        }
    });
});

/**
 * @OA\Schema(
 *     schema="Property",
 *     type="object",
 *     required={"Name", "Description", "Price"},
 *     @OA\Property(property="idproperties", type="integer", readOnly=true),
 *     @OA\Property(property="Name", type="string"),
 *     @OA\Property(property="Description", type="string"),
 *     @OA\Property(property="Price", type="number")
 * )
 */

