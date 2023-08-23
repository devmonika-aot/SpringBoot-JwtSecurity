package com.sumit.jwt.SpringBootJwtSecurity.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
@Slf4j
public class JwtService {

  private String encodedKey = null;
  public static final String SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";



  public String extractUserName(String jwt) throws NoSuchAlgorithmException {
    return extactAllClaims(jwt).getSubject();
  }

  /*
  Token Generation method without any extra claims
  */
  public String generateToken(UserDetails userDetails) throws NoSuchAlgorithmException {
    return generateToken(new HashMap<>(), userDetails);
  }

  public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails)
      throws NoSuchAlgorithmException {
    return Jwts.builder()
        .setClaims(extraClaims) // If we have to set any extra claims other than inbuild
        .setSubject(userDetails.getUsername()) // Id by which it will be verified
        .setIssuedAt(new Date(System.currentTimeMillis())) // token generation time
        .setExpiration(
            new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // token expiration time
        .signWith(getSignKey(),SignatureAlgorithm.HS256)//HmacSHA384
        .compact();
  }
  /*
  @param UserDetails userDetails -> We need to verify weather the token belongs to
  corresponding User or not.
   */
  public boolean isTokenValid(String token, UserDetails userDetails)
      throws NoSuchAlgorithmException {
    String userName = extractUserName(token);
    return (userName.equalsIgnoreCase(userDetails.getUsername()) && isTokenIsExpired(token));
  }

  private boolean isTokenIsExpired(String token) throws NoSuchAlgorithmException {
    return extactAllClaims(token).getExpiration().before(new Date());
  }

  /* NOTES
  This method has been used to extarct Claims from jwt token.
  Claims is nothing but body and header of jwt token.
  It contain information like subject(which is id), issuer name, issuer date, expiry date etc
  */
  private Claims extactAllClaims(String token) throws NoSuchAlgorithmException {
    return Jwts.parserBuilder()
        .setSigningKey(getSignKey()) // for verify signature in jwt token
        .build()
        .parseClaimsJws(token)
        .getBody();
  }

  private Key getSignKey() {
    byte[] keyBytes= Decoders.BASE64.decode(SECRET);
    return Keys.hmacShaKeyFor(keyBytes);
  }
//  private Key generateSecretKey() throws NoSuchAlgorithmException {
//    KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA384");
//    SecureRandom secureRandom = new SecureRandom();
//    keyGenerator.init(secureRandom);
//    Key secretKey = keyGenerator.generateKey();
//    log.info("Generated Key is {}", secretKey);
//    // For Encoding
//    encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
//   // encodedKey = " 404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
//    log.info("Encoded Key is {}", encodedKey);
//    // For Decoding
//    byte[] keyBytes = Decoders.BASE64.decode(encodedKey);
//    log.info("Key byte {}", keyBytes);
//    log.info("after decoding Keys.hmacShaKeyFor(keyBytes {}", Keys.hmacShaKeyFor(keyBytes));
//    return Keys.hmacShaKeyFor(keyBytes);
//  }
}
