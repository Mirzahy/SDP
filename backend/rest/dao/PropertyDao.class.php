<?php

require_once __DIR__ . "/BaseDao.class.php";

class PropertyDao extends BaseDao {

    public function __construct() {
        parent::__construct("properties");
    }

    public function addProperty($property) {
        return $this->insert('properties', $property);
    }

    public function get_all_properties() {
        return $this->query("SELECT * FROM properties", []);
    }

    public function count_properties_paginated($search) {
        $query = "SELECT COUNT(*) AS count
                  FROM properties
                  WHERE LOWER(name) LIKE CONCAT('%', :search, '%') OR
                        LOWER(description) LIKE CONCAT('%', :search, '%')";
        return $this->query_unique($query, [
            'search' => strtolower($search)
        ]);
    }
    
    public function get_properties_paginated($offset, $limit, $search, $order_column, $order_direction) {
        $valid_columns = ['name', 'price', 'description'];
        $valid_directions = ['ASC', 'DESC'];

        $order_column = in_array($order_column, $valid_columns) ? $order_column : 'name';
        $order_direction = in_array($order_direction, $valid_directions) ? $order_direction : 'ASC';

        $query = "SELECT *
                  FROM properties
                  WHERE LOWER(name) LIKE CONCAT('%', :search, '%') OR
                        LOWER(description) LIKE CONCAT('%', :search, '%')
                  ORDER BY {$order_column} {$order_direction}
                  LIMIT :offset, :limit";
        return $this->query($query, [
            'search' => strtolower($search),
            'offset' => (int)$offset,
            'limit' => (int)$limit
        ]);
    }

    public function delete_property($id) {
        $query = "DELETE FROM properties WHERE idproperties = :id";
        $this->execute($query, [
            'id' => $id
        ]);
    }

    public function get_property_by_id($id) {
        return $this->query_unique(
            "SELECT * FROM properties WHERE idproperties = :id", 
            ["id" => $id]);
    }

    public function edit_property($id, $property) {
        $query  = "UPDATE properties
                   SET name = :name,
                       description = :description,
                       price = :price,
                       image = :image
                   WHERE idproperties = :id";
        $this->execute($query, [
            'id' => $id, 
            'name' => $property['name'],
            'description' => $property['description'],
            'price' => $property['price'],
            'image' => $property['Image']
        ]);
    }

    public function get_categories() {
        $query = "SELECT category_id, category_name FROM categories";
        return $this->query($query, []);
    }
}
