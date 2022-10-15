package com.springJwt.service;

import java.util.List;

import com.springJwt.model.Role;
import com.springJwt.model.User;

public interface UserService {
	User saveUser(User user);

	Role saveRole(Role role);

	void addRoleToUser(String username, String roleName);

	User getUser(String username);

	List<User> getUsers();
}
