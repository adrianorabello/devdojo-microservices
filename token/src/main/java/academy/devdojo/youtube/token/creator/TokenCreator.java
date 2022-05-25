package academy.devdojo.youtube.token.creator;


import academy.devdojo.youtube.core.model.ApplicationUser;
import academy.devdojo.youtube.core.property.JwtConfiguration;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class TokenCreator {

    private final JwtConfiguration jwtConfiguration;

    @SneakyThrows
    public SignedJWT createSignedJWT(Authentication auth) {
        log.info("Inside Signed token ");
        ApplicationUser applicationUser = (ApplicationUser) auth.getPrincipal();
        JWTClaimsSet jwtClaimSet = createJWTClaimSet(auth, applicationUser);
        KeyPair rsakeys = generateKeyPear();
        log.info("Build JWK from RSA keys ");
        JWK jwk = new RSAKey.Builder((RSAPublicKey) rsakeys
                .getPublic())
                .keyID(UUID.randomUUID().toString())
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .jwk(jwk)
                .type(JOSEObjectType.JWT)
                .build(), jwtClaimSet);
        log.info("Assigning token with private RSA ");
        RSASSASigner signer = new RSASSASigner(rsakeys.getPrivate());
        signedJWT.sign(signer);
        log.info("serialize token '{}'", signedJWT.serialize());
        return signedJWT;
    }

    private JWTClaimsSet createJWTClaimSet(Authentication auth, ApplicationUser applicationUser) {
        log.info("Inside create JWTClaimsSet");
        return new JWTClaimsSet.Builder()
                .subject(applicationUser.getUsername())
                .claim("authorities", auth.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .issuer("devdojo microservice")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + (jwtConfiguration.getExpiration() * 1000)))
                .build();


    }

    @SneakyThrows
    private KeyPair generateKeyPear() {
        log.info("Generate key pear ");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.genKeyPair();
    }


    public String encryptToken(SignedJWT signedJWT) throws JOSEException {
        DirectEncrypter directEncrypter = new DirectEncrypter(jwtConfiguration.getPrivateKey().getBytes());
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256).contentType("JWT").build(),
                new Payload(signedJWT)
        );
        log.info("Inside encrype token ");
        jweObject.encrypt(directEncrypter);
        return jweObject.serialize();
    }
}
