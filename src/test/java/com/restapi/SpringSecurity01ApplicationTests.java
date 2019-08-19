package com.restapi;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

import com.security.model.AppUser;
import com.security.model.Role;
import com.security.model.User_Role;
import com.security.repository.RoleRepository;
import com.security.repository.UserRepository;
import com.security.repository.User_RoleRepository;

@RunWith(SpringRunner.class)
@SpringBootTest
public class SpringSecurity01ApplicationTests {
	
	@Autowired
	private UserRepository userRepo;
	
	@Autowired
	private RoleRepository roleRepo;
	
	@Autowired
	private User_RoleRepository user_RoleRepository;
	
	
	@Autowired
	private BCryptPasswordEncoder encoder;

	@Test
	public void UserRepoTest() {
		
		// Get roles
		Role adminRole = roleRepo.findByRolename("ADMIN");
		Role userRole = roleRepo.findByRolename("USER");
		
		
		// Create users		
		AppUser sami = new AppUser();
		sami.setUsername("sami");
		sami.setPassword(encoder.encode("sami"));	
		
		
		AppUser kevin = new AppUser();
		kevin.setUsername("kevin");
		kevin.setPassword(encoder.encode("kevin"));
		
		AppUser samiFetched = userRepo.save(sami);
		AppUser kevinFetched = userRepo.save(kevin);
		
		User_Role sam = new User_Role(sami.getId(), adminRole.getId());
		User_Role kev = new User_Role(kevin.getId(), userRole.getId());

		
		user_RoleRepository.save(sam);
		user_RoleRepository.save(kev);

		assertTrue(samiFetched.getUsername().equalsIgnoreCase(samiFetched.getUsername()));
		
		}

}
