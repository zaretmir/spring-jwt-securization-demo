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
import org.springframework.stereotype.Service;

import com.security.model.AppUser;
import com.security.model.Role;
import com.security.model.User_Role;
import com.security.repository.RoleRepository;
import com.security.repository.UserRepository;
import com.security.repository.User_RoleRepository;

@Service
public class UserService implements UserDetailsService {

	@Autowired
	UserRepository userRepository;
	
	@Autowired
	RoleRepository roleRepo;
	
	@Autowired
	User_RoleRepository urRepo;
	
		
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser us = userRepository.findByUsername(username);
		
		
		
		
		
		
		/*List<GrantedAuthority> roles = new ArrayList<>();
		
		roles.add(new SimpleGrantedAuthority("ADMIN"));
		*/
		Collection<? extends GrantedAuthority> roles = getAuthorities(us);
		
		
		/*
		List<GrantedAuthority> roles = new ArrayList<>();
		Collection<Role> userRoles = us.getRoles();
		for (Role role:userRoles) {
			roles.add(new SimpleGrantedAuthority(role.getRolename()));		
		}
		*/
		
		
		UserDetails usDetails = new User(us.getUsername(), us.getPassword(), roles);
		
		return usDetails;
		
	}
	/*
	private static Collection<? extends GrantedAuthority> getAuthorities(AppUser user) {
        String[] userRoles = user.getRoles().stream().map((role) -> role.getRolename()).toArray(String[]::new);
        Collection<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(userRoles);
        return authorities;
    }
    */
	
	private Collection<? extends GrantedAuthority> getAuthorities(AppUser user) {
		Long userid = user.getId();
		List<User_Role> userRoles = urRepo.findByUserpk(userid);
		List<Long> rolesId = userRoles.stream().map( (ur) -> ur.getRolepk()).collect(Collectors.toList());
		List<Role> roles = rolesId.stream().map( (rid) -> roleRepo.findOneById(rid) ).collect(Collectors.toList());
		String[] roleNames = roles.stream().map( (r) -> r.getRolename() ).toArray(String[]::new);
		
		Collection<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(roleNames);
		return authorities;
		
		
    }

}
