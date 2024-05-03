package com.jwtdemo.demoJwt.Controller;

import com.jwtdemo.demoJwt.model.request.ChangePasswordRequest;
import com.jwtdemo.demoJwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/bieuquyet/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService service;

    @PatchMapping
    public ResponseEntity<?> changePassword(
            @RequestBody ChangePasswordRequest request,
            Principal cndUser
    ) {
        service.changePassword(request, cndUser);
        return ResponseEntity.ok().build();
    }
}
