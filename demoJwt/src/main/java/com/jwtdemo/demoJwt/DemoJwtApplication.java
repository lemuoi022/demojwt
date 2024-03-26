package com.jwtdemo.demoJwt;

import com.jwtdemo.demoJwt.domain.Role;
import com.jwtdemo.demoJwt.domain.User;
import com.jwtdemo.demoJwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class DemoJwtApplication{

	public static void main(String[] args) {
		SpringApplication.run(DemoJwtApplication.class, args);
	}

//	@Autowired
//	UserRepository userRepository;
//	@Autowired
//	PasswordEncoder passwordEncoder;
//
//	@Override
//	public void run(String... args) throws Exception {
//		// Khi chương trình chạy
//		// Insert vào csdl một user.
//		User user = new User();
//		user.setEmail("muoi@gmail.com");
//		user.setPassword(passwordEncoder.encode("muoi123"));
//		user.setRole(Role.USER);
//		userRepository.save(user);
//		System.out.println(user);
//	}
}
