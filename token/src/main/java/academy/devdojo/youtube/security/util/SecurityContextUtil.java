package academy.devdojo.youtube.security.util;

import academy.devdojo.youtube.core.model.ApplicationUser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Adriano Rabello 25/05/2022 13:52:07
 **/

@Slf4j
public class SecurityContextUtil {

    private SecurityContextUtil() {

    }


    @SneakyThrows
    public static void setSecurityContext(SignedJWT signedJWT) {
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
        String userName = jwtClaimsSet.getSubject();

        if (userName == null)
            throw new JOSEException("User name missin from jwt");

        List<String> authorities = jwtClaimsSet.getStringListClaim("authorities");

        ApplicationUser applicationUser = ApplicationUser.builder()
                .id((Long) jwtClaimsSet.getClaim("userId"))
                .username(userName)
                .role(String.join(",", authorities))
                .build();

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(applicationUser,
                null,
                createAuthorities(authorities));

        auth.setDetails(signedJWT.serialize());
        SecurityContextHolder.getContext().setAuthentication(auth);
    }


    private static List<SimpleGrantedAuthority> createAuthorities(List<String> authorities) {

        return authorities
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }


}
