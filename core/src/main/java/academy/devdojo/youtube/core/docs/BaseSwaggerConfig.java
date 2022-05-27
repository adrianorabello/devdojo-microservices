package academy.devdojo.youtube.core.docs;

import org.springframework.context.annotation.Bean;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;

/**
 * @author Adriano Rabello 26/05/2022 21:02:50
 **/


public class BaseSwaggerConfig {


    private final String basePackage;

    public BaseSwaggerConfig(String basePackage) {
        this.basePackage = basePackage;
    }


    @Bean
    public Docket api() {

        return new Docket(DocumentationType.SWAGGER_2)
                .select()
                .apis(RequestHandlerSelectors.basePackage(basePackage))
                .build()
                .apiInfo(metaData());
    }

    private ApiInfo metaData() {

        return new ApiInfoBuilder()
                .title("Spring boort microservices at DevDojo")
                .description("Now is real")
                .version("1.0")
                .contact(new Contact("Adrino Rabello",
                        "https://www.linkedin.com/in/adriano-rabello-4151a0106/details/skills/?detailScreenTabIndex=0",
                        "adrianor.rabello@hotmail.com")
                )
                .license("Licence here")
                .licenseUrl("Licence URL here")
                .build();
    }
}
