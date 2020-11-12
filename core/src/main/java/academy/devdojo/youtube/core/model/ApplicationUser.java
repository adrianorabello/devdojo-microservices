package academy.devdojo.youtube.core.model;

import lombok.*;
import lombok.extern.slf4j.Slf4j;

import javax.persistence.*;
import javax.validation.constraints.NotNull;

/**
 * @autor Adriano Rabello
 */

@Entity
@Data
@Builder
@ToString
@Slf4j
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class ApplicationUser implements AbstractEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;

    @NotNull(message = "The title is mandatory")
    @Column(nullable = false)
    private String username;

    @NotNull(message = "The field is mandatory ")
    @Column(nullable = false)
    @ToString.Exclude
    private String password;

    @NotNull(message = "The field can't be null ")
    @Column(nullable = false)
    private String role = "USER";

    public ApplicationUser(@NotNull ApplicationUser applicationUser){

        this.id = applicationUser.getId();
        this.username = applicationUser.getUsername();
        this.password = applicationUser.getPassword();
        this.role = applicationUser.getRole();

    }
}
