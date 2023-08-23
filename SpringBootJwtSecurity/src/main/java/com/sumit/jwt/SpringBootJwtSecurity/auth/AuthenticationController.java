package com.sumit.jwt.SpringBootJwtSecurity.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.NoSuchAlgorithmException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    private final AutheticateService service;
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) throws NoSuchAlgorithmException {
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/autheticate")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody AuthenticationRequest request) throws NoSuchAlgorithmException {
        return ResponseEntity.ok(service.authenticate(request));
    }

}
