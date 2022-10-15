package com.springJwt.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.springJwt.model.User;
import com.springJwt.service.UserService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {
	private final UserService userService;

	@GetMapping("/users")
	public ResponseEntity<List<User>> getUser() {
		return ResponseEntity.ok().body(userService.getUsers());
	}
}
