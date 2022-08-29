package com.jwtauthapi.jwtauthrestapi;

import com.jwtauthapi.jwtauthrestapi.model.AppUser;
import com.jwtauthapi.jwtauthrestapi.model.Role;
import com.jwtauthapi.jwtauthrestapi.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.HashSet;

@SpringBootApplication
public class JwtauthrestapiApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtauthrestapiApplication.class, args);
	}

	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
//			userService.saveRole(new Role(null, "ROLE_USER"));
//			userService.saveRole(new Role(null, "ROLE_MANAGER"));
//			userService.saveRole(new Role(null, "ROLE_ADMIN"));
//			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
//
//			userService.saveUser(new AppUser(null, "John Wick", "john", "1234", new HashSet<>()));
//			userService.saveUser(new AppUser(null, "Will Smith", "will", "1234", new HashSet<>()));
//			userService.saveUser(new AppUser(null, "Jim Carrey", "jim", "1234", new HashSet<>()));
//			userService.saveUser(new AppUser(null, "Arnold Schwarzenneger", "arnold", "1234", new HashSet<>()));
//
//			userService.addRoleToUser("john", "ROLE_USER");
//			userService.addRoleToUser("john", "ROLE_MANAGER");
//			userService.addRoleToUser("will", "ROLE_MANAGER");
//			userService.addRoleToUser("jim", "ROLE_ADMIN");
//			userService.addRoleToUser("arnold", "ROLE_SUPER_ADMIN");
//			userService.addRoleToUser("arnold", "ROLE_ADMIN");
//			userService.addRoleToUser("arnold", "ROLE_USER");
		};
	}
}
