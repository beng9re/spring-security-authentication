package nextstep.security.util;

import jakarta.servlet.http.HttpServletRequest;
import nextstep.security.BasicToken;

public class BasicTokenParser {
    private static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BASIC_PREFIX = "Basic ";

    public static BasicToken parse(HttpServletRequest request) throws IllegalArgumentException {
        String authorization = request.getHeader(AUTHORIZATION_HEADER);

        validateAuthorizationHeader(authorization);

        final String base64Credentials = authorization.substring(BASIC_PREFIX.length()).trim();
        String decodedString = Base64Convertor.decode(base64Credentials);

        String[] credentials = decodedString.split(":");
        if (credentials.length != 2) {
            throw new IllegalArgumentException("유효한 Basic 형식이 아닙니다");
        }

        return new BasicToken(base64Credentials, credentials[0], credentials[1]);
    }

    private static void validateAuthorizationHeader(String authorization) {
        if (authorization == null) {
            throw new IllegalArgumentException("Authorization 헤더가 존재하지 않습니다");
        }

        if (!authorization.regionMatches(true, 0, BASIC_PREFIX, 0, BASIC_PREFIX.length())) {
            throw new IllegalArgumentException("Authorization 헤더가 Basic 타입이 아닙니다.");
        }
    }
}
