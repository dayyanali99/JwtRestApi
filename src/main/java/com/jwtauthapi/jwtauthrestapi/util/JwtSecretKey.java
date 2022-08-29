package com.jwtauthapi.jwtauthrestapi.util;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("myapp.jwt")
@Getter
@Setter
public class JwtSecretKey {
    private String secretKey;
}
