package com.example.Authentication.Security;

import com.example.Authentication.Entity.User;
import io.jsonwebtoken.*;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Component
public class JwtTokenUtil {
    private static final long EXPIRE_DURATION = 24*60*60*1000;

    private String SECRET_KEY = "abc123def123";

    public String generateAccessToken(User user){
        return Jwts.builder()
                .setSubject(String.format("%s,%s", user.getId(), user.getEmail()))
                .setIssuer("Matrix")
                .claim("role", "USER")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE_DURATION))
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();
    }

    private static final Logger LOGGER = (Logger) LoggerFactory.getLogger(JwtTokenUtil.class);

    public boolean validateAccessToken(String token){
        try {
            Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token);
            return true;
        }
        catch (ExpiredJwtException ex){
            LOGGER.error("JWT expired", ex.getMessage());
        }
        catch (IllegalArgumentException ex){
            LOGGER.error("Token is null, empty of only whitespace", ex.getMessage());
        }
        catch (MalformedJwtException ex){
            LOGGER.error("JWT is invalid", ex);
        }
        catch (UnsupportedJwtException ex){
            LOGGER.error("JWT is not supported", ex);
        }
        catch (SignatureException ex){
            LOGGER.error("Signature validation failed");
        }
        return false;
    }

    public String getSubject(String token){
        return parseClaims(token).getSubject();
    }

    Claims parseClaims(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
    }
}
