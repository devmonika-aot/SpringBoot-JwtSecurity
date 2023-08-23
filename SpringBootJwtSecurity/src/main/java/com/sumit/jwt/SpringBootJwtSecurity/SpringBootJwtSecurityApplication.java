package com.sumit.jwt.SpringBootJwtSecurity;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@SpringBootApplication
public class SpringBootJwtSecurityApplication {

	public static void main(String[] args) throws NoSuchAlgorithmException {

//
//		byte[] keyBytes= Decoders.BASE64.decode(encodedKey);
//		Key decodeKey  = Keys.hmacShaKeyFor(keyBytes);

		SpringApplication.run(SpringBootJwtSecurityApplication.class, args

		);
	}

}
