<?php

require_once __DIR__ . "/../dao/PropertyDao.class.php";

class PropertyService {
    private $property_dao;

    public function __construct() {
        $this->property_dao = new PropertyDao();
    }

    public function addProperty($property) {
        
        return $this->property_dao->addProperty($property);
    }

    public function get_properties_paginated($offset, $limit, $search, $order_column, $order_direction) {
        $count = $this->property_dao->count_properties_paginated($search)['count'];
        $rows = $this->property_dao->get_properties_paginated($offset, $limit, $search, $order_column, $order_direction);

        return ['count' => $count, 'data' => $rows];
    }

    public function delete_property($id) {
       
        $this->property_dao->delete_property($id);
    }

    public function get_property_by_id($id) {
        return $this->property_dao->get_property_by_id($id);
    }

    public function edit_property($id, $property) {
        
        $this->property_dao->edit_property($id, $property);
    }

    public function get_categories() {
        
        return $this->property_dao->get_categories();
    }

   
}
