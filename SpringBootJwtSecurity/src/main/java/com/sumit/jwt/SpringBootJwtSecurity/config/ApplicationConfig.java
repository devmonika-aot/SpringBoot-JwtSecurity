package com.sumit.jwt.SpringBootJwtSecurity.config;

import com.sumit.jwt.SpringBootJwtSecurity.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
  /* NOTES
     No need to give autowired as We already mention @RequiredArgsConstructor
  */
  private final UserRepo userRepo;

  @Bean
  public UserDetailsService userDetailService() {
      /*
      As UserDetailsService is a functional interface, it can be implemented with lambda expression.
       */
    return (userName ->
        userRepo
            .findByEmail(userName)
            .orElseThrow(() -> new UsernameNotFoundException("USER DOESNT EXIST")));
  }
  /*
  Basically AuthenticationProvider is used to tell which password encoder has been used etc

   */
  @Bean
  public AuthenticationProvider authenticationProvider(){
    DaoAuthenticationProvider authProvider =new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailService());
    authProvider.setPasswordEncoder(passwordEncoder());
    return authProvider;

  }
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager();

  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
