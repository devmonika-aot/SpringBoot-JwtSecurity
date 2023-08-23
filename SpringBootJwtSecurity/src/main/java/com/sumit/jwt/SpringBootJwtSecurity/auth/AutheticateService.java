package com.sumit.jwt.SpringBootJwtSecurity.auth;

import com.sumit.jwt.SpringBootJwtSecurity.repo.UserRepo;
import com.sumit.jwt.SpringBootJwtSecurity.service.JwtService;
import com.sumit.jwt.SpringBootJwtSecurity.user.Role;
import com.sumit.jwt.SpringBootJwtSecurity.user.User;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;

@Service
@RequiredArgsConstructor
public class AutheticateService {

  private final UserRepo userRepo;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  public AuthenticationResponse register(RegisterRequest request) throws NoSuchAlgorithmException {
    User user =
        User.builder()
            .fisrtName(request.getFirstName())
            .lastName(request.getLastName())
            .email(request.getEmail())
            .password(passwordEncoder.encode(request.getPassword()))
            .role(Role.USER)
            .build();
    userRepo.save(user);
    String jwtToken = jwtService.generateToken(user);
    return AuthenticationResponse.builder().token(jwtToken).build();
  }
  /*
  This method is used to generate new token for existing User.

   */
  public AuthenticationResponse authenticate(AuthenticationRequest request)
      throws NoSuchAlgorithmException {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
    // If controls comes to this line, It means User is already authnticated else would have thrown
    // exception
    User user = userRepo.findByEmail(request.getEmail()).orElseThrow();
    String jwtToken = jwtService.generateToken(user);
    return AuthenticationResponse.builder().token(jwtToken).build();
  }
}
