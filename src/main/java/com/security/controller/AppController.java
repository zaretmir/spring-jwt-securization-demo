package com.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.security.config.JwtTokenUtil;
import com.security.dto.AppUserDTO;
import com.security.model.JwtRequest;
import com.security.model.JwtResponse;
import com.security.repository.UserRepository;
import com.security.service.JwtUserDetailsService;


@RestController
@CrossOrigin
public class AppController {
	
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Autowired
	private JwtUserDetailsService userDetailsService;
	
	@Autowired
	UserRepository userRepo;
	
	@GetMapping("home")
	public ResponseEntity<String> welcome() {		
		return new ResponseEntity<String>("Welcome!", HttpStatus.OK);
	}
	
	//@Secured("ADMIN")
	@PreAuthorize("hasAuthority('ADMIN')")
	@GetMapping("app/admins-only")
	public ResponseEntity<String> adminsMethod() {		
		return new ResponseEntity<String>("This content is for admins only", HttpStatus.OK);
	}
	
	//@Secured("USER")
	@PreAuthorize("hasAuthority('USER')")
	@GetMapping("app/user-only")
	public ResponseEntity<String> userMethod() {		
		return new ResponseEntity<String>("This content is for users only", HttpStatus.OK);
	}
	
	@GetMapping("app/unspec-role")
	public ResponseEntity<String> unspecMethod() {		
		return new ResponseEntity<String>("This content is for anyone", HttpStatus.OK);
	}
	
	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest) throws Exception {

		authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());

		final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());

		final String token = jwtTokenUtil.generateToken(userDetails);

		return ResponseEntity.ok(new JwtResponse(token));
	}

	@RequestMapping(value = "/register", method = RequestMethod.POST)
	public ResponseEntity<?> saveUser(@RequestBody AppUserDTO user) throws Exception {
		return ResponseEntity.ok(userDetailsService.save(user));
	}
	
	private void authenticate(String username, String password) throws Exception {
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		} catch (DisabledException e) {
			throw new Exception("USER_DISABLED", e);
		} catch (BadCredentialsException e) {
			throw new Exception("INVALID_CREDENTIALS", e);
		}
	}
	

}
