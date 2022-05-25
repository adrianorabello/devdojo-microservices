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
public class Course implements AbstractEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;

    @NotNull(message = "The title is mandatory")
    @Column(nullable = false)
    private String title;
}
