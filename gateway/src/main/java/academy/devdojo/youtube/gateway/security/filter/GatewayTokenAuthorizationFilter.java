package academy.devdojo.youtube.gateway.security.filter;

import academy.devdojo.youtube.core.property.JwtConfiguration;
import academy.devdojo.youtube.security.filter.JwtTokenAuthorizationFilter;
import academy.devdojo.youtube.security.token.converter.TokenConverter;
import com.netflix.zuul.context.RequestContext;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import org.springframework.lang.NonNull;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;

import static academy.devdojo.youtube.security.util.SecurityContextUtil.setSecurityContext;

/**
 * @author Adriano Rabello 25/05/2022 14:30:26
 **/
public class GatewayTokenAuthorizationFilter extends JwtTokenAuthorizationFilter {


    public GatewayTokenAuthorizationFilter(JwtConfiguration jwtConfiguration, TokenConverter tokenConverter) {
        super(jwtConfiguration, tokenConverter);
    }

    @Override
    @SuppressWarnings("Duplicates")
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) {
        try {
            String header = request.getHeader(jwtConfiguration.getHeader().getName());
            if (header == null || !header.startsWith(jwtConfiguration.getHeader().getPrefix())) {
                filterChain.doFilter(request, response);
                return;
            }
            String token = header.replace(jwtConfiguration.getHeader().getPrefix(), "").trim();
            String signedToken = tokenConverter.decryptToken(token);
            tokenConverter.validaTeTokenSignature(signedToken);

            setSecurityContext(SignedJWT.parse(signedToken));

            if (jwtConfiguration.getType().equalsIgnoreCase("signed"))
                RequestContext.getCurrentContext().addZuulRequestHeader("Authorization",
                        jwtConfiguration.getHeader().getPrefix() + signedToken);


            filterChain.doFilter(request, response);

        } catch (ParseException | IOException | ServletException e) {
            throw new RuntimeException(e);
        }
    }
}
