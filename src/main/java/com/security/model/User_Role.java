package com.security.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.Table;

@Entity
@Table(name="user_role")
@IdClass(User_Role_Id.class)
public class User_Role {
	
	@Id
	@Column(name="userpk")
	private Long userpk;
	
	@Id
	@Column(name="rolepk")
	private Long rolepk;

	public Long getUserpk() {
		return userpk;
	}

	public void setUserpk(Long userpk) {
		this.userpk = userpk;
	}

	public Long getRolepk() {
		return rolepk;
	}

	public void setRolepk(Long rolepk) {
		this.rolepk = rolepk;
	}
	
	public User_Role(Long userpk, Long rolepk) {
		this.userpk = userpk;
		this.rolepk = rolepk;
	}
	
	public User_Role() { }
	
	
	
	

}
