package nextstep.security;

public class BasicToken {
    private final String token;
    private final String username;
    private final String password;

    public BasicToken(String token, String username, String password) {
        this.token = token;
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
