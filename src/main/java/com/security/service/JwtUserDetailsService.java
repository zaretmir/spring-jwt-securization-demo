package com.security.service;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.security.builder.AppUserBuilder;
import com.security.dao.AppUserDAO;
import com.security.dto.AppUserDTO;
import com.security.model.AppUser;
import com.security.model.Role;
import com.security.model.User_Role;
import com.security.repository.RoleRepository;
import com.security.repository.User_RoleRepository;

@Service
public class JwtUserDetailsService implements UserDetailsService {
	
	@Autowired
	AppUserDAO userDAO;
	
	@Autowired
	RoleRepository roleRepo;
	
	@Autowired
	User_RoleRepository urRepo;
	
	@Autowired
	PasswordEncoder encoder;
	

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		AppUser us = userDAO.findByUsername(username);
		
		Collection<? extends GrantedAuthority> roles = getAuthorities(us);
		
		UserDetails usDetails = new User(us.getUsername(), us.getPassword(), roles);
		
		return usDetails;
	}
	
	private Collection<? extends GrantedAuthority> getAuthorities(AppUser user) {
		
		Long userid = user.getId();
		List<User_Role> userRoles = urRepo.findByUserpk(userid);
		List<Long> rolesId = userRoles.stream().map( (ur) -> ur.getRolepk()).collect(Collectors.toList());
		List<Role> roles = rolesId.stream().map( (rid) -> roleRepo.findOneById(rid) ).collect(Collectors.toList());
		String[] roleNames = roles.stream().map( (r) -> r.getRolename() ).toArray(String[]::new);
		
		Collection<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(roleNames);
		return authorities;		
    }
	
	public AppUser save(AppUserDTO user) {
		
		AppUser newUser = AppUserBuilder.convertToEntity(user);
		newUser.setPassword(encoder.encode(newUser.getPassword()));
		AppUser savedUser = userDAO.save(newUser);
		
		// Assign ROLE_USER to new user
		Long ROLE_USER_ID = roleRepo.findByRolename("USER").getId();
		User_Role role = new User_Role(savedUser.getId(), ROLE_USER_ID);
		urRepo.save(role);		
		
		return savedUser;
	}
	
	

}
