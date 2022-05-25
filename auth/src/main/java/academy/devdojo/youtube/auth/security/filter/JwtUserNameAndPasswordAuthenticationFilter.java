package academy.devdojo.youtube.auth.security.filter;

import academy.devdojo.youtube.core.model.ApplicationUser;
import academy.devdojo.youtube.core.property.JwtConfiguration;
import academy.devdojo.youtube.token.creator.TokenCreator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

import static java.util.stream.Collectors.toList;

/**
 * @autor Adriano Rabello
 */

@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Slf4j
public class JwtUserNameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtConfiguration jwtConfiguration;
    private final TokenCreator tokenCreator;

    @Override
    @SneakyThrows
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) {

        log.info("Attemping authentication ");

        ApplicationUser applicationUser = new ObjectMapper().readValue(request.getInputStream(), ApplicationUser.class);

        if (applicationUser == null)
            throw new UsernameNotFoundException("Unable to retrieve username or password ");

        log.info("Creating authentication object for userDetails servece '{}' loadding by user ", applicationUser.getUsername());

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                applicationUser.getUsername(),
                applicationUser.getPassword(),
                Collections.emptyList());

        usernamePasswordAuthenticationToken.setDetails(applicationUser);

        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);

    }

    @Override
    @SneakyThrows
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain, Authentication auth) {
        log.info("Success login for the user ", auth.getName());

        SignedJWT signedJWT = tokenCreator.createSignedJWT(auth);

        String encrypeted = tokenCreator.encryptToken(signedJWT);

        log.info("Generintind successul token to response header ");

        response.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN, " + jwtConfiguration.getHeader().getName());

        response.addHeader(jwtConfiguration.getHeader().getName(),
                jwtConfiguration.getHeader().getPrefix() + encrypeted);

    }

    @SneakyThrows
    private SignedJWT createSignedJWT(Authentication auth) {
        log.info("Starting to create  the signed JWT ");
        ApplicationUser applicationUser = (ApplicationUser) auth.getPrincipal();
        JWTClaimsSet jwtClainSet = createJWTClainSet(auth, applicationUser);
        KeyPair rsaKeys = generateKeyPair();

        JWK jwk = new RSAKey.Builder(((RSAPublicKey) rsaKeys.getPublic())).keyID(UUID.randomUUID().toString()).build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .jwk(jwk)
                .type(JOSEObjectType.JWT)
                .build(),
                jwtClainSet);

        RSASSASigner signer = new RSASSASigner(rsaKeys.getPrivate());
        signedJWT.sign(signer);

        log.info("Serilized token '{}' ", signedJWT.serialize());

        return signedJWT;
    }

    private JWTClaimsSet createJWTClainSet(Authentication auth, ApplicationUser applicationUser) {
        log.info("Creating JWTClainSet ");

        return new JWTClaimsSet.Builder().subject(applicationUser.getUsername())
                .claim("authorities",
                        auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(toList()))
                .issuer("http://academy.devdojo")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + jwtConfiguration.getExpiration() * 1000))
                .build();
    }

    @SneakyThrows
    private KeyPair generateKeyPair() {
        log.info("Generating Key pair");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

}
