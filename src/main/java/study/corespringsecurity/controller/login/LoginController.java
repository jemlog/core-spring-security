package study.corespringsecurity.controller.login;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login(@RequestParam(value = "error",required = false) String error,
                        @RequestParam(value = "exception",required = false) String exception, Model model)
    {
        model.addAttribute("error",error);
        model.addAttribute("exception",exception);
        return "user/login/login";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response)
    {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(authentication != null)
        {
            // 그냥 생성만 해주면 된다!!
            new SecurityContextLogoutHandler().logout(request,response,authentication);
        }
        return "redirect://login";
    }

}
