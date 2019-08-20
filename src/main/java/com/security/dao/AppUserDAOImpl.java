package com.security.dao;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.security.model.AppUser;
import com.security.repository.UserRepository;

@Component
public class AppUserDAOImpl implements AppUserDAO {
	
	@Autowired
	UserRepository userRepo;

	@Override
	public AppUser findByUsername(String username) {
		return userRepo.findByUsername(username);
	}

	@Override
	public AppUser save(AppUser user) {
		return userRepo.save(user);
	}

}
