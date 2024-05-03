package com.jwtdemo.demoJwt.Controller;

import com.jwtdemo.demoJwt.model.request.LoginRequest;
import com.jwtdemo.demoJwt.model.response.LoginResponse;
import com.jwtdemo.demoJwt.domain.user.User;
import com.jwtdemo.demoJwt.exception.EmailAlreadyExistsException;
import com.jwtdemo.demoJwt.service.AuthenticationService;
import com.jwtdemo.demoJwt.model.request.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/api/bieuquyet/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;
    @PostMapping("/register")
    public ResponseEntity<LoginResponse> register(@RequestBody RegisterRequest request) throws Exception {
        String tempEmail = request.getEmail();
        if(tempEmail !=null && !"".equals(tempEmail)) {
           Optional<User> userOptional = service.fetchUserByEmailId(tempEmail);

            if (userOptional.isPresent()) {
                throw new EmailAlreadyExistsException("User with "+tempEmail+" is already exist");
            }

        }
        return ResponseEntity.ok(service.register(request));

    }
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request){
        return ResponseEntity.ok(service.login(request)) ;
    }
}
