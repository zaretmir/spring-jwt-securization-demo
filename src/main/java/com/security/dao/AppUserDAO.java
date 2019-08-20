package com.security.dao;

import com.security.model.AppUser;

public interface AppUserDAO {
	
	AppUser findByUsername(String username);
	
	AppUser save(AppUser user);

}
