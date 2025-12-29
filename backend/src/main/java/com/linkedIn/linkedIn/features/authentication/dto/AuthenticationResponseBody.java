package com.linkedIn.linkedIn.features.authentication.dto;

public class AuthenticationResponseBody {
        private String token;
        private String message;

        public AuthenticationResponseBody(String token, String message) {
            this.token = token;
            this.message = message;
        }

        public String getToken() {
            return token;
        }

        public String getMessage() {
            return message;
        }
}
