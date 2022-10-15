package com.springJwt.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.springJwt.model.User;

public interface UserRepo extends JpaRepository<User, Long> {
	User findByUsername(String username);
}
