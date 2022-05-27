package academy.devdojo.youtube.security.filter;

import academy.devdojo.youtube.core.property.JwtConfiguration;
import academy.devdojo.youtube.security.token.converter.TokenConverter;
import academy.devdojo.youtube.security.util.SecurityContextUtil;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Adriano Rabello 25/05/2022 12:11:10
 **/

@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class JwtTokenAuthorizationFilter extends OncePerRequestFilter {
    protected final JwtConfiguration jwtConfiguration;
    protected final TokenConverter tokenConverter;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader(jwtConfiguration.getHeader().getName());
        if (header == null || !header.startsWith(jwtConfiguration.getHeader().getPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }
        String token = header.replace(jwtConfiguration.getHeader().getPrefix(), "").trim();
        SecurityContextUtil.setSecurityContext(
                StringUtils.equalsIgnoreCase("signed", jwtConfiguration.getType()) ? validate(token) : decryptValidating(token));
        filterChain.doFilter(request, response);
    }

    @SneakyThrows
    private SignedJWT decryptValidating(String encryptedToken) {
        String signedToken = tokenConverter.decryptToken(encryptedToken);
        tokenConverter.validaTeTokenSignature(signedToken);
        return SignedJWT.parse(signedToken);
    }

    @SneakyThrows
    private SignedJWT validate(String signedToken) {
        tokenConverter.validaTeTokenSignature(signedToken);
        return SignedJWT.parse(signedToken);
    }
}
