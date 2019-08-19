package com.security.model;

import java.io.Serializable;
import java.util.Objects;

public class User_Role_Id implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 6667544753391594388L;
	
	private Long userpk;
	
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
	
	@Override
	public boolean equals(Object o) {
		
		if (this == o)
			return true;
		if (o == null || o.getClass() != this.getClass())
			return false;
		
		User_Role user_role = (User_Role) o;
		
		return (user_role.getRolepk() == this.rolepk && user_role.getUserpk() == this.userpk);
		
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(getUserpk(), getRolepk());
	}
	

}
