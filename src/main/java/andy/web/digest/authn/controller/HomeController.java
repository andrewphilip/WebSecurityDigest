package andy.web.digest.authn.controller;


import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

	@RequestMapping(value="/greet/{name}")
	public String home(@PathVariable(value="name") String name){
		return "Hello, "+ name+"!";
	}
}
