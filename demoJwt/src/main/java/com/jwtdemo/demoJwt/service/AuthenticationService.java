package com.jwtdemo.demoJwt.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwtdemo.demoJwt.domain.token.Token;
import com.jwtdemo.demoJwt.domain.token.TokenType;
import com.jwtdemo.demoJwt.model.request.LoginRequest;
import com.jwtdemo.demoJwt.model.response.LoginResponse;
import com.jwtdemo.demoJwt.model.request.RegisterRequest;
import com.jwtdemo.demoJwt.domain.user.User;
import com.jwtdemo.demoJwt.repository.TokenRepository;
import com.jwtdemo.demoJwt.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private  final AuthenticationManager authenticationManager;
    public LoginResponse register(RegisterRequest request){
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        var saveduser = repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(saveduser, jwtToken);
        return LoginResponse.builder().token(jwtToken).build();
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();
        tokenRepository.save(token);
    }
    private void revokeAllUserTokens(User user){
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }
    public LoginResponse login(LoginRequest request){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user =  repository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return LoginResponse.builder().token(jwtToken).build();
    }

    public Optional<User> fetchUserByEmailId(String email) {
        return repository.findByEmail(email);
    }
}
