package academy.devdojo.youtube.security.token.converter;

import academy.devdojo.youtube.core.property.JwtConfiguration;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

/**
 * @auctor Adriano Rabello 25/05/2022 11:19:43
 **/

@Slf4j
@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class TokenConverter {

    private final JwtConfiguration jwtConfiguration;

    @SneakyThrows
    public String decryptToken(String encryptedToken){
        log.info("Decrypting token ");
        JWEObject jweObject =  JWEObject.parse(encryptedToken);
        DirectDecrypter directDecrypter = new DirectDecrypter(jwtConfiguration.getPrivateKey().getBytes());
        jweObject.decrypt(directDecrypter);
        log.info("Token decrypted, return signed token...");
        return jweObject.getPayload().toSignedJWT().serialize();
    }

    @SneakyThrows
    public void validaTeTokenSignature(String signedToken){
        log.info("Starting method to validade token signature...");
        SignedJWT signedJWT = SignedJWT.parse(signedToken);
        log.info("Token parsed! Retriving public key from signed token");
        RSAKey publicKey = RSAKey.parse(signedJWT.getHeader().getJWK().toJSONObject());
        log.info("Public key retrived, validatind signature");
        if(!signedJWT.verify(new RSASSAVerifier(publicKey)))
            throw  new AccessDeniedException("Invalid token signature");
        log.info("Token has valid signature");
    }
}
