package andy.web.digest.authn;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	/***
	 * 
	 *  Digest authentication:
	 *  base64(expirationTime + ":" + md5Hex(expirationTime + ":" + key))
	 *	expirationTime:   The date and time when the nonce expires, expressed in milliseconds
	 *	key:  A private key to prevent modification of the nonce token
     *       
	 */
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
			.withUser("andrew").password("lausdei").roles("USER");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.anyRequest().authenticated()
			.and()
			.addFilter(digestAuthenticationFilter())
			.exceptionHandling()
				.authenticationEntryPoint(digestAuthenticationEntryPoint())
			.and()	
			.csrf().disable()
			.logout()
				.deleteCookies("remove")
				.invalidateHttpSession(true)
				.permitAll();
		
	}

	@Bean
	public DigestAuthenticationEntryPoint digestAuthenticationEntryPoint(){
		DigestAuthenticationEntryPoint dig=new DigestAuthenticationEntryPoint();
		dig.setRealmName("andyrealm");
		dig.setKey("sanctus");
		dig.setNonceValiditySeconds(15);
		return dig;
	}
	
	@Bean
	public DigestAuthenticationFilter digestAuthenticationFilter() throws Exception{
		DigestAuthenticationFilter filter=new DigestAuthenticationFilter();
		filter.setAuthenticationEntryPoint(digestAuthenticationEntryPoint());
		filter.setUserDetailsService(userDetailsServiceBean());
		return filter;
	}
	
	
}
