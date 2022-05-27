package academy.devdojo.youtube.auth.docs;

import academy.devdojo.youtube.core.docs.BaseSwaggerConfig;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

/**
 * @author Adriano Rabello 26/05/2022 21:10:42
 **/

@Configuration
@EnableSwagger2
public class SwaggerConfig extends BaseSwaggerConfig {

    public SwaggerConfig() {
        super("academy.devdojo.youtube.auth.endpoint.controller");
    }
}
