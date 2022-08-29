package com.jwtauthapi.jwtauthrestapi.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.*;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDate;
import java.util.Date;
import java.util.stream.Collectors;


@Component
@Getter
// TODO: to be implemented
public class JwtUtil {
    private Authentication authentication;
    @Value("${myapp.jwt.secret-key}")
    private String secretKey;

    public String generateAccessToken(HttpServletRequest request) {
//        UserDetails user =(UserDetails) authentication.getPrincipal();
//        Algorithm algorithm = Algorithm.HMAC256(secretKeyGetter.getSecretKey().getBytes());
//        return JWT.create()
//                .withSubject(user.getUsername())
//                .withIssuedAt(new Date())
//                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
//                .withIssuer(request.getRequestURL().toString())
//                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
//                .sign(algorithm);

        return null;
    }

    public String generateRefreshToken(HttpServletRequest request) {
//        UserDetails user =(UserDetails) authentication.getPrincipal();
//        Algorithm algorithm = Algorithm.HMAC256(secretKeyGetter.getSecretKey().getBytes());
//
//        return JWT.create()
//                .withSubject(user.getUsername())
//                .withExpiresAt(java.sql.Date.valueOf(LocalDate.now().plusDays(1)))
//                .withIssuer(request.getRequestURL().toString())
//                .sign(algorithm);
        return null;
    }

}
