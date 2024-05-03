package com.jwtdemo.demoJwt;

import com.jwtdemo.demoJwt.model.request.RegisterRequest;
import com.jwtdemo.demoJwt.service.AuthenticationService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.jwtdemo.demoJwt.domain.user.Role.ADMIN;
import static com.jwtdemo.demoJwt.domain.user.Role.MANAGER;

@SpringBootApplication
public class DemoJwtApplication{

	public static void main(String[] args) {
		SpringApplication.run(DemoJwtApplication.class, args);
	}
	@Bean
	public CommandLineRunner commandLineRunner(
			AuthenticationService service
	) {
		return args -> {
			var admin = RegisterRequest.builder()
					.firstname("Admin")
					.lastname("Admin")
					.email("admin@mail.com")
					.password("123456")
					.role(ADMIN)
					.build();
			System.out.println("Admin token: " + service.register(admin));

			var manager = RegisterRequest.builder()
					.firstname("Admin")
					.lastname("Admin")
					.email("manager@mail.com")
					.password("123456")
					.role(MANAGER)
					.build();
			System.out.println("Manager token: " + service.register(manager));

		};
	}

//	@Autowired
//	UserRepository userRepository;
//	@Autowired
//	PasswordEncoder passwordEncoder;
//
//	@Override
//	public void run(String... args) throws Exception {
//		User user = new User();
//		user.setEmail("muoi@gmail.com");
//		user.setPassword(passwordEncoder.encode("muoi123"));
//		user.setRole(Role.USER);
//		userRepository.save(user);
//		System.out.println(user);
//	}
}
