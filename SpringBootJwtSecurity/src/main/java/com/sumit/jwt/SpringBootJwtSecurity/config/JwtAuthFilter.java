package com.sumit.jwt.SpringBootJwtSecurity.config;

import com.sumit.jwt.SpringBootJwtSecurity.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
/* NOTES
   It will create constructor of any final field
*/
public class JwtAuthFilter extends OncePerRequestFilter {
  /* NOTES
     As per diagram, JwtAuthFilter filter should be executed per request thats why It is extending
     OncePerRequestFilter
  */
  // No need to mention @Autowired as we already mention @RequiredArgsConstructor
  private final JwtService jwtService;
  private final UserDetailsService userDeatilService;

  @SneakyThrows
  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain)
      throws ServletException, IOException {
    final String authHeader =
        request.getHeader("Authorization"); // headers name that contains JWT Token
    final String jwt;
    final String userEmail;
    // Case - 1 If request is without JWT
    System.out.println("authHeader "+authHeader);
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      filterChain.doFilter(request, response); // done with this request, get next request
      return;
    }
    // Case - 2 Request has jwt, check User exist or not for the requested jwt
    jwt = authHeader.substring(7);
    userEmail = jwtService.extractUserName(jwt); // Here id we call as subject in jwt
    /* NOTES
     SecurityContextHolder is used to hold the user deatils, So It will tell us weather USER
     is already authenticated or not. If It is already authenticated, no need to perform
     authentication again.
    */
    if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      UserDetails userDetails = this.userDeatilService.loadUserByUsername(userEmail);
      /*NOTES
      1) Here, We are fetching UserDetails from database( Note: User name i.e subject is coming with token)
      2) After Getting userDetails from Database, We are verifying weather token belong with the user or not
      3) if token belong to the user then, we will update SecurityContextHolder to set User as validated
       */
      if (jwtService.isTokenValid(jwt, userDetails)) {
        // So nce the user is verified, We will have to set the security context to make use
        // authenticated
        UsernamePasswordAuthenticationToken authenticationToken =
            new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
      }
      filterChain.doFilter(request, response);
    }
  }
}
