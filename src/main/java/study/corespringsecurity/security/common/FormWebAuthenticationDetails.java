package study.corespringsecurity.security.common;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    // 사용자의 추가적인 파라미터 저장
    private String secretKey;


    /**
     * Records the remote address and will also set the session Id if a session already
     * exists (it won't create one).
     *
     * @param request that the authentication request was received from
     */
    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        String secretKey = request.getParameter("secretKey");

    }

    public String getSecretKey()
    {
        return secretKey;
    }

}
