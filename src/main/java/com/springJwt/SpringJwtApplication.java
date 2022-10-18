package com.springJwt;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.springJwt.model.Role;
import com.springJwt.model.User;
import com.springJwt.service.UserService;

@SpringBootApplication
public class SpringJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringJwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

			userService.saveUser(new User(null, "Karthik", "kd", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Prabhas", "pd", "4321", new ArrayList<>()));
			userService.saveUser(new User(null, "Yash", "yd", "1111", new ArrayList<>()));
			userService.saveUser(new User(null, "Ram", "rd", "2222", new ArrayList<>()));

			userService.addRoleToUser("kd", "ROLE_ADMIN");
			userService.addRoleToUser("kd", "ROLE_SUPER_ADMIN");
			userService.addRoleToUser("rd", "ROLE_USER");
			userService.addRoleToUser("pd", "ROLE_MANAGER");
			userService.addRoleToUser("yd", "ROLE_ADMIN");
		}; 
	}
}
