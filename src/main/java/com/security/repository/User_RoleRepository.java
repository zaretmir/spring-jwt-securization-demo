package com.security.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.security.model.User_Role;

public interface User_RoleRepository extends JpaRepository<User_Role, Long> {
	
	List<User_Role> findByUserpk(Long userpk);


}
