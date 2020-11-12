package academy.devdojo.youtube.auth;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
@Slf4j
class AuthApplicationTests {

	@Test
	void contextLoads() {
	}
	@Test
	public void test(){

		log.info(new BCryptPasswordEncoder().encode(" Password ********** ->devdojo"));
	}

}
