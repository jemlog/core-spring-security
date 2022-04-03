package study.corespringsecurity.security.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    // 인증을 검증할때 실패하면 인증예외를 발생시킴
    //authenticationProvider이나 UserDetailsService에서 주로 발생
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        String errorMessage = "invalid Username or Password";
        if(exception instanceof BadCredentialsException)
        {
            errorMessage = "Invalid Username or Password";
        }
        else if(exception instanceof InsufficientAuthenticationException)
        {
            errorMessage = "Invalid Secret key";
        }


        setDefaultFailureUrl("/login?error=true&exception"+ errorMessage);

        super.onAuthenticationFailure(request,response,exception);
    }
}
