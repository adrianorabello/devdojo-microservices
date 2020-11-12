package academy.devdojo.youtube.core.repository;


import academy.devdojo.youtube.core.model.Course;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.stereotype.Repository;

/**
 * @autor Adriano Rabello
 */

@Repository
public interface CourseRepository extends PagingAndSortingRepository<Course, Long> {
}
