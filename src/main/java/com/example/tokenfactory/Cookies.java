package com.example.tokenfactory;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;

/**
 * The tokens travel as cookies so the browser (or curl with a cookie jar) resends them
 * automatically across the 302 refresh redirect. That is what keeps the client trivial.
 */
final class Cookies {

    static final String ACCESS_TOKEN = "access_token";
    static final String REFRESH_TOKEN = "refresh_token";

    private Cookies() {
    }

    static Optional<String> read(HttpServletRequest request, String name) {
        return Optional.ofNullable(request.getCookies()).stream()
                .flatMap(Arrays::stream)
                .filter(cookie -> name.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }

    static void write(HttpServletResponse response, String name, String value, Duration maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge((int) maxAge.toSeconds());
        response.addCookie(cookie);
    }
}
