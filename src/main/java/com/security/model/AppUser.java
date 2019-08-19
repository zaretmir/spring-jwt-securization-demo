package com.security.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;


@Entity
@Table(name="appuser")
public class AppUser {
	
	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	@Column(name="user_id")
	private Long id;
	
	@Column(name="username")
	private String username;
	
	@Column(name="password")
	private String password;
	
	/*
	@ManyToMany(cascade = CascadeType.MERGE)
	@JoinTable(
			name="user_role",
			joinColumns= {@JoinColumn(name="user_id", referencedColumnName="user_id")},
			inverseJoinColumns= {@JoinColumn(name="role_id", referencedColumnName="role_id")}
			)
	private List<Role> roles;
	*/

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	/*
	public List<Role> getRoles() {
		return roles;
	}

	public void setRoles(List<Role> roles) {
		this.roles = roles;
	}
	*/

	/*
	public Collection<GrantedAuthority> getAuthorities() {
		List<GrantedAuthority> list = new ArrayList<GrantedAuthority>();
		
		for (Role role:roles) {
			list.add(new SimpleGrantedAuthority(role.getRolename()));			
		}		
		return list;
	}*/


}
